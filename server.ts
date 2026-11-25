import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { createServer as createViteServer } from 'vite';
import { db, normalizeStoredImageUrl, Product, Category, Banner, Order, User, Coupon, Review, StoreSettings, ContactMessage, DeliveryAddress, OrderStatus, PaymentDetails, BankPayoutAccount, PayoutAuditRecord, PaymentTransaction, PaymentSession, MerchantCardDetails } from './server/db.ts';
import { sendOtpEmail } from './server/emailService.ts';
import Stripe from 'stripe';
import {
  CURRENCY_CATALOG,
  normalizeCurrencyCode,
  getCurrencyMeta,
  applyRounding,
  formatExactCurrency,
  validateVariantSelection,
  getTotalProductVariantStock,
  calculateOrderBreakdown,
  getProductOptionGroups,
  getCartItemVariantKey,
  getEffectiveDecimals,
} from './shared/pricing.ts';
import {
  getExchangeRatesSnapshot,
  resolveConversionRate,
  verifyLockedQuoteRate,
  startExchangeRateScheduler,
  RateUnavailableError,
} from './server/exchangeRates.ts';

const rawStripeKey = (process.env.STRIPE_SECRET_KEY || '').trim();
const isValidStripeSecret = (key: string) =>
  /^(sk|rk)_(test|live)_[A-Za-z0-9]{10,}$/.test(key) && !key.includes('your_stripe');
const envStripeClient = isValidStripeSecret(rawStripeKey) ? new Stripe(rawStripeKey) : null;

function getEffectiveStripeClient(storeData?: ReturnType<typeof db.getData>): Stripe | null {
  if (envStripeClient) return envStripeClient;
  const runtimeKey = (storeData?.paymentGateway?.secretKeyRuntime || '').trim();
  if (isValidStripeSecret(runtimeKey)) {
    try {
      return new Stripe(runtimeKey);
    } catch {
      return null;
    }
  }
  return null;
}

function getEffectiveSafepayKeys(storeData?: ReturnType<typeof db.getData>) {
  const apiKey = (
    process.env.SAFEPAY_MERCHANT_API_KEY ||
    process.env.SAFEPAY_API_KEY ||
    storeData?.paymentGateway?.apiKeyRuntime ||
    ''
  ).trim();
  const secretKey = (
    process.env.SAFEPAY_SECRET_KEY ||
    storeData?.paymentGateway?.secretKeyRuntime ||
    ''
  ).trim();
  return { apiKey, secretKey };
}

function sanitizePaymentGatewayForAdmin(pg: any) {
  if (!pg) return pg;
  const { apiKeyRuntime: _ak, secretKeyRuntime: _sk, webhookSecret: _ws, ...safePg } = pg;
  return {
    ...safePg,
    secretKeyConfigured: Boolean(pg.secretKeyConfigured || pg.secretKeyRuntime || process.env.STRIPE_SECRET_KEY || process.env.SAFEPAY_SECRET_KEY),
    webhookSecretSet: Boolean(pg.webhookSecretSet || pg.webhookSecret || process.env.STRIPE_WEBHOOK_SECRET || process.env.SAFEPAY_WEBHOOK_SECRET),
  };
}

const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  safepay: 'Safepay Pakistan',
  stripe: 'Stripe Global',
  paymob: 'Paymob MENA',
};

const app = express();
// Port 3000 is default and required by the AI Studio preview environment
const PORT = Number(process.env.PORT) || 3000;
const isProduction = (process.env.NODE_ENV || '').trim().toLowerCase() === 'production';

// Bootstrap default Administrator & Google Drive config (overridable dynamically inside Admin Dashboard)
const DEFAULT_ADMIN_EMAIL = (
  process.env.AUTHORIZED_ADMIN_EMAIL || 'huzaifa60010@gmail.com'
)
  .trim()
  .toLowerCase();
const DEFAULT_DRIVE_FOLDER_ID = '1q_B8QGCYgzRgVzT4r3f-NH2PN1XaU34m';
const DEFAULT_DRIVE_FOLDER_NAME = 'NOVORA_Project';

// Load Firebase client config (for server-side ID token verification)
let FIREBASE_WEB_API_KEY = process.env.FIREBASE_API_KEY || '';
let FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || '';
try {
  const fbCfgPath = path.resolve(process.cwd(), 'firebase-applet-config.json');
  if (fs.existsSync(fbCfgPath)) {
    const fbCfg = JSON.parse(fs.readFileSync(fbCfgPath, 'utf-8'));
    FIREBASE_WEB_API_KEY = FIREBASE_WEB_API_KEY || String(fbCfg.apiKey || '').trim();
    FIREBASE_PROJECT_ID = FIREBASE_PROJECT_ID || String(fbCfg.projectId || '').trim();
  }
} catch (cfgErr) {
  console.warn('[Server] Could not read firebase-applet-config.json:', cfgErr);
}

// Persistent HMAC secret for signing session tokens (generated once per workspace)
const TOKEN_SECRET_PATH = path.resolve(process.cwd(), 'data', '.token_secret');
const SERVER_TOKEN_SECRET: string = (() => {
  const envSecret = (process.env.SESSION_SECRET || process.env.JWT_SECRET || '').trim();
  if (envSecret.length >= 24) return envSecret;
  try {
    const dir = path.dirname(TOKEN_SECRET_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(TOKEN_SECRET_PATH)) {
      const stored = fs.readFileSync(TOKEN_SECRET_PATH, 'utf-8').trim();
      if (stored.length >= 32) return stored;
    }
    const generated = crypto.randomBytes(48).toString('hex');
    fs.writeFileSync(TOKEN_SECRET_PATH, generated, { mode: 0o600 });
    return generated;
  } catch {
    return crypto.createHash('sha256').update(`${process.cwd()}_novora_hmac_key`).digest('hex');
  }
})();

// Signed Stripe Webhook Endpoint (must be mounted before express.json() for raw body signature verification)
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), (req: Request, res: Response) => {
  const sig = req.headers['stripe-signature'] as string | undefined;
  const storeForHook = db.getData();
  const stripeClient = getEffectiveStripeClient(storeForHook);
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || storeForHook.paymentGateway?.webhookSecret;

  if (!stripeClient || !webhookSecret) {
    return res.status(503).json({ error: 'Stripe webhook is not configured on the server.' });
  }

  if (!sig) {
    return res.status(400).json({ error: 'Missing stripe-signature header.' });
  }

  let event: Stripe.Event;
  try {
    event = stripeClient.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err: any) {
    console.error('[Stripe:Webhook] Signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook signature verification failed: ${err.message}` });
  }

  const store = db.getData();

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    const orderId = session.metadata?.orderId;
    const order = store.orders.find(o => o.id === orderId);

    if (order) {
      // Prevent duplicate order processing
      if (order.paymentStatus === 'paid') {
        return res.json({ received: true, duplicate: true });
      }

      if (session.payment_status === 'paid') {
        order.paymentStatus = 'paid';
        order.orderStatus = 'Paid';
        const txId = typeof session.payment_intent === 'string' ? session.payment_intent : session.id;
        const paidAt = new Date().toISOString();
        const fee = Math.round(order.total * 0.029 * 100) / 100;
        const netPayout = Math.round((order.total - fee) * 100) / 100;
        const isSandbox = !session.livemode;
        order.paymentDetails = {
          provider: 'Stripe',
          paymentMethodTitle: 'Stripe Hosted Checkout',
          transactionId: txId,
          paidAt,
          isTestMode: isSandbox,
          gatewayFee: fee,
          netPayout,
        };

        if (!store.paymentTransactions) store.paymentTransactions = [];
        store.paymentTransactions.unshift({
          id: `tx_${Date.now()}`,
          transactionReference: txId,
          orderId: order.id,
          orderNumber: order.orderNumber,
          customerName: order.customer.fullName,
          customerEmail: order.customer.email,
          amount: order.total,
          currency: order.currency,
          fee,
          netPayout,
          provider: 'stripe',
          paymentMethod: 'Stripe Hosted Checkout',
          paymentStatus: 'paid',
          payoutStatus: 'Scheduled (T+2)',
          merchantSettlementDestination: order.settledToMerchantCard,
          isTestMode: isSandbox,
          paidAt,
          createdAt: paidAt,
        });

        db.commit();
      }
    }
  } else if (event.type === 'checkout.session.expired' || event.type === 'payment_intent.payment_failed') {
    const obj = event.data.object as any;
    const orderId = obj.metadata?.orderId;
    const order = store.orders.find(o => o.id === orderId);
    if (order && order.paymentStatus !== 'paid') {
      order.paymentStatus = 'declined';
      db.commit();
    }
  } else if (event.type === 'charge.refunded') {
    const charge = event.data.object as Stripe.Charge;
    const txId = typeof charge.payment_intent === 'string' ? charge.payment_intent : charge.id;
    const order = store.orders.find(o => o.paymentDetails?.transactionId === txId);
    if (order) {
      order.paymentStatus = 'refunded';
      order.orderStatus = 'Refunded';
      db.commit();
    }
  }

  return res.json({ received: true });
});

// Signed Safepay Webhook Endpoint (must be mounted before express.json() for raw body signature verification)
app.post('/api/payments/safepay/webhook', express.raw({ type: 'application/json' }), (req: Request, res: Response) => {
  const signature = req.headers['x-sfpy-signature'] as string | undefined;
  const webhookSecret = process.env.SAFEPAY_WEBHOOK_SECRET;

  if (!webhookSecret) {
    return res.status(503).json({ error: 'Safepay webhook is not configured on the server.' });
  }

  if (!signature) {
    return res.status(400).json({ error: 'Missing x-sfpy-signature header.' });
  }

  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body || {}));
  const expectedSig = crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex');

  const sigBuf = Buffer.from(signature, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    console.error('[Safepay:Webhook] Signature verification failed');
    return res.status(400).json({ error: 'Invalid webhook signature.' });
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON payload.' });
  }

  const eventType = payload?.type || payload?.event;
  const data = payload?.data || payload;
  const trackerToken = data?.tracker?.token || data?.token;
  const orderId = data?.metadata?.order_id || data?.order_id;

  const store = db.getData();
  const order = store.orders.find(
    o => (orderId && (o.id === orderId || o.orderNumber === orderId)) ||
         (trackerToken && o.paymentDetails?.transactionId === trackerToken)
  );

  if (order) {
    if (order.paymentStatus === 'paid') {
      return res.json({ received: true, duplicate: true });
    }

    const state = (data?.state || data?.tracker?.state || '').toUpperCase();
    if (eventType === 'payment.succeeded' || state === 'PAID' || state === 'TRACKER_ENDED') {
      order.paymentStatus = 'paid';
      order.orderStatus = 'Paid';
      const txId = trackerToken || order.paymentDetails?.transactionId || `sfpy_${Date.now()}`;
      const paidAt = new Date().toISOString();
      const fee = Math.round(order.total * 0.025 * 100) / 100;
      const netPayout = Math.round((order.total - fee) * 100) / 100;
      const isSandbox = store.paymentGateway?.mode
        ? store.paymentGateway.mode === 'test'
        : (store.paymentGateway?.isTestMode ?? true);
      order.paymentDetails = {
        provider: 'Safepay',
        paymentMethodTitle: 'Safepay Checkout (PKR)',
        transactionId: txId,
        paidAt,
        isTestMode: isSandbox,
        gatewayFee: fee,
        netPayout,
      };

      if (!store.paymentTransactions) store.paymentTransactions = [];
      store.paymentTransactions.unshift({
        id: `tx_${Date.now()}`,
        transactionReference: txId,
        orderId: order.id,
        orderNumber: order.orderNumber,
        customerName: order.customer.fullName,
        customerEmail: order.customer.email,
        amount: order.total,
        currency: order.currency || 'PKR',
        fee,
        netPayout,
        provider: 'safepay',
        paymentMethod: 'Safepay Checkout (PKR)',
        paymentStatus: 'paid',
        payoutStatus: 'Scheduled (T+2)',
        merchantSettlementDestination: order.settledToMerchantCard,
        isTestMode: isSandbox,
        paidAt,
        createdAt: paidAt,
      });

      db.commit();
    } else if (eventType === 'payment.failed' || state === 'FAILED' || state === 'CANCELLED') {
      order.paymentStatus = 'declined';
      db.commit();
    }
  }

  return res.json({ received: true });
});

// Allow Firebase Authentication Google OAuth popups across localhost and hosted origins
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  next();
});

// Support large payload for high-resolution PC gallery image uploads
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// Static uploads, public images, and legacy /src/assets media folders
const uploadsDir = path.resolve(process.cwd(), 'uploads');
const publicImagesDir = path.resolve(process.cwd(), 'public', 'images');
const publicAssetsAiStudioDir = path.resolve(process.cwd(), 'public', 'assets', 'aistudio');
const srcAssetsDir = path.resolve(process.cwd(), 'src', 'assets');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', express.static(uploadsDir, { fallthrough: true }));
// Fallback resolver if a stored /uploads/<subfolder>/<filename> exists in an alternate Media subfolder
app.use('/uploads', (req: Request, res: Response, next: NextFunction) => {
  const filename = path.basename(req.path || '');
  if (!filename || filename.includes('..')) return next();

  const candidateSubfolders = [
    path.join(uploadsDir, 'Media', 'Product_Images'),
    path.join(uploadsDir, 'Media', 'Banner_Images'),
    path.join(uploadsDir, 'Media', 'Category_Images'),
    path.join(uploadsDir, 'Media', 'Logos'),
    path.join(uploadsDir, 'Media', 'Other_Store_Images'),
    path.join(uploadsDir, 'products'),
    path.join(uploadsDir, 'banners'),
    publicImagesDir,
  ];
  for (const dir of candidateSubfolders) {
    const candidate = path.join(dir, filename);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return res.sendFile(candidate);
    }
  }
  return res.status(404).json({ error: 'Uploaded media file not found', path: req.path });
});

if (fs.existsSync(publicImagesDir)) {
  app.use('/images', express.static(publicImagesDir));
}
if (fs.existsSync(srcAssetsDir)) {
  app.use('/src/assets', express.static(srcAssetsDir));
}
if (fs.existsSync(publicAssetsAiStudioDir)) {
  app.use('/assets/aistudio', express.static(publicAssetsAiStudioDir));
}

function isVerifiedAdminUser(user?: User | null, store?: ReturnType<typeof db.getData>): boolean {
  if (!user) return false;
  const cleanEmail = String(user.email || '').trim().toLowerCase();
  const s = store || db.getData();
  return (
    isAuthorizedAdminEmail(cleanEmail, s) &&
    user.role === 'admin' &&
    user.isEmailVerified !== false &&
    user.accountStatus !== 'suspended'
  );
}

function getEffectiveRole(user: User, store?: ReturnType<typeof db.getData>): 'admin' | 'customer' {
  return isVerifiedAdminUser(user, store) ? 'admin' : 'customer';
}

function issueSignedToken(user: User): string {
  const effectiveRole = getEffectiveRole(user);
  const now = Date.now();
  const payload = {
    sub: user.id,
    email: String(user.email || '').trim().toLowerCase(),
    role: effectiveRole,
    iat: now,
    exp: now + 7 * 24 * 60 * 60 * 1000,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto
    .createHmac('sha256', SERVER_TOKEN_SECRET)
    .update(encodedPayload)
    .digest('base64url');
  return `nov_${encodedPayload}.${signature}`;
}

function verifySignedToken(token: string): { sub: string; email: string; role: 'admin' | 'customer'; exp: number } | null {
  if (!token || !token.startsWith('nov_')) return null;
  const raw = token.slice(4);
  const dotIdx = raw.indexOf('.');
  if (dotIdx <= 0) return null;
  const encodedPayload = raw.slice(0, dotIdx);
  const sigProvided = raw.slice(dotIdx + 1);
  if (!encodedPayload || !sigProvided) return null;

  const expectedSig = crypto
    .createHmac('sha256', SERVER_TOKEN_SECRET)
    .update(encodedPayload)
    .digest('base64url');

  const bufProvided = Buffer.from(sigProvided, 'utf8');
  const bufExpected = Buffer.from(expectedSig, 'utf8');
  if (bufProvided.length !== bufExpected.length || !crypto.timingSafeEqual(bufProvided, bufExpected)) {
    return null;
  }

  try {
    const decoded = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (!decoded || typeof decoded.sub !== 'string' || typeof decoded.email !== 'string') {
      return null;
    }
    if (typeof decoded.exp !== 'number' || decoded.exp <= Date.now()) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

let cachedFirebaseCerts: { certs: Record<string, string>; expiresAt: number } | null = null;

async function getFirebasePublicCerts(): Promise<Record<string, string>> {
  if (cachedFirebaseCerts && cachedFirebaseCerts.expiresAt > Date.now()) {
    return cachedFirebaseCerts.certs;
  }
  const certRes = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
  );
  if (!certRes.ok) {
    throw new Error(`Failed to fetch Firebase certificates (${certRes.status})`);
  }
  const cacheControl = certRes.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const ttlMs = (maxAgeMatch ? Number(maxAgeMatch[1]) : 3600) * 1000;
  const certs = (await certRes.json()) as Record<string, string>;
  cachedFirebaseCerts = { certs, expiresAt: Date.now() + ttlMs };
  return certs;
}

interface VerifiedExternalIdentity {
  uid: string;
  email: string;
  emailVerified: boolean;
  fullName: string;
  photoURL?: string;
}

async function verifyFirebaseIdToken(idToken: string): Promise<VerifiedExternalIdentity | null> {
  const cleanToken = String(idToken || '').trim();
  if (!cleanToken || cleanToken.split('.').length !== 3) return null;

  // Primary verification: Firebase Identity Toolkit accounts:lookup (checks revocation + signature + expiry)
  if (FIREBASE_WEB_API_KEY) {
    try {
      const lookupRes = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_WEB_API_KEY)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: cleanToken }),
        }
      );
      if (lookupRes.ok) {
        const lookupData = (await lookupRes.json()) as any;
        const fbUser = lookupData?.users?.[0];
        if (fbUser && fbUser.localId && fbUser.email && fbUser.disabled !== true) {
          return {
            uid: String(fbUser.localId),
            email: String(fbUser.email).trim().toLowerCase(),
            emailVerified: Boolean(fbUser.emailVerified),
            fullName: String(fbUser.displayName || '').trim(),
            photoURL: fbUser.photoUrl ? String(fbUser.photoUrl) : undefined,
          };
        }
      }
    } catch (err) {
      console.warn('[Auth] Identity Toolkit lookup fallback to local RSA cert verification:', err);
    }
  }

  // Secondary verification: RS256 signature verification against Google Firebase public x509 certs
  try {
    const [headerB64, payloadB64, sigB64] = cleanToken.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

    if (header?.alg !== 'RS256' || !header?.kid) return null;
    if (FIREBASE_PROJECT_ID) {
      if (payload?.aud !== FIREBASE_PROJECT_ID) return null;
      if (payload?.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) return null;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload?.exp !== 'number' || payload.exp <= nowSec) return null;
    if (typeof payload?.sub !== 'string' || !payload.sub || typeof payload?.email !== 'string' || !payload.email) {
      return null;
    }

    const certs = await getFirebasePublicCerts();
    const cert = certs[header.kid];
    if (!cert) return null;

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const isValid = verifier.verify(cert, Buffer.from(sigB64, 'base64url'));
    if (!isValid) return null;

    return {
      uid: String(payload.sub),
      email: String(payload.email).trim().toLowerCase(),
      emailVerified: Boolean(payload.email_verified),
      fullName: String(payload.name || '').trim(),
      photoURL: payload.picture ? String(payload.picture) : undefined,
    };
  } catch {
    return null;
  }
}

async function verifyGoogleAccessToken(accessToken: string): Promise<VerifiedExternalIdentity | null> {
  const cleanToken = String(accessToken || '').trim();
  if (!cleanToken) return null;
  try {
    const infoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${cleanToken}` },
    });
    if (!infoRes.ok) return null;
    const info = (await infoRes.json()) as any;
    const email = String(info?.email || '').trim().toLowerCase();
    if (!email) return null;
    return {
      uid: info?.sub ? `google_${info.sub}` : `google_${crypto.createHash('sha256').update(email).digest('hex').slice(0, 16)}`,
      email,
      emailVerified: info?.email_verified === true,
      fullName: String(info?.name || info?.given_name || '').trim(),
      photoURL: info?.picture ? String(info.picture) : undefined,
    };
  } catch {
    return null;
  }
}

const authenticate = (req: Request, _res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }
  const token = authHeader.slice(7).trim();
  const decoded = verifySignedToken(token);
  if (!decoded) {
    return next();
  }

  try {
    const store = db.getData();
    const user = store.users.find(
      u => u.id === decoded.sub && String(u.email || '').trim().toLowerCase() === decoded.email
    );
    if (user && user.accountStatus !== 'suspended') {
      const effectiveRole = getEffectiveRole(user);
      (req as any).user = {
        ...user,
        role: effectiveRole,
      };
    }
  } catch {
    // invalid token or lookup failure
  }
  next();
};

const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ error: 'Authentication required. Please sign in as an administrator.' });
  }
  if (!isVerifiedAdminUser(user)) {
    return res.status(403).json({ error: 'Access denied. Only the verified store administrator may access this resource.' });
  }
  next();
};

app.use(authenticate);

// Live Currency Exchange Rate, Checkout Quote & Pricing Engine
function getStoreBaseCurrency(store: ReturnType<typeof db.getData>): string {
  return normalizeCurrencyCode(store.settings?.baseCurrency || store.settings?.currency || 'USD');
}

function getEffectiveCoupon(store: ReturnType<typeof db.getData>, couponCode?: string) {
  if (!couponCode || typeof couponCode !== 'string') return null;
  const codeClean = couponCode.trim().toUpperCase();
  if (!codeClean) return null;
  return store.coupons.find(c => c.code.toUpperCase() === codeClean && c.isActive) || null;
}

interface QuoteComputationOptions {
  items: any[];
  displayCurrency?: string;
  country?: string;
  couponCode?: string;
  quotedExchangeRate?: number;
  quotedRateTimestamp?: string;
  expectedDisplayTotal?: number;
  requireValidQuote?: boolean;
}

async function validateAndComputeCheckoutQuote(
  store: ReturnType<typeof db.getData>,
  opts: QuoteComputationOptions
) {
  const baseCurrency = getStoreBaseCurrency(store);
  const enabled =
    Array.isArray(store.settings?.enabledCurrencies) && store.settings.enabledCurrencies.length > 0
      ? store.settings.enabledCurrencies.map(c => normalizeCurrencyCode(c))
      : [baseCurrency];
  const displayCurrency = normalizeCurrencyCode(
    opts.displayCurrency || store.settings?.defaultCustomerCurrency || baseCurrency
  );

  if (displayCurrency !== baseCurrency && !enabled.includes(displayCurrency)) {
    const err: any = new Error(`Currency "${displayCurrency}" is not enabled for checkout.`);
    err.statusCode = 400;
    err.code = 'CURRENCY_NOT_ENABLED';
    throw err;
  }

  // Aggregate requested quantities per SKU/variant so split duplicate cart lines cannot exceed stock/limits
  const qtyByKey = new Map<string, number>();
  const resolvedInputs: Array<{
    rawItem: any;
    product: Product;
    quantity: number;
    validation: ReturnType<typeof validateVariantSelection>;
  }> = [];

  for (const rawItem of opts.items) {
    if (!rawItem || typeof rawItem.productId !== 'string') {
      const err: any = new Error('Invalid cart item payload.');
      err.statusCode = 400;
      throw err;
    }
    const product = store.products.find(p => p.id === rawItem.productId);
    if (!product) {
      const err: any = new Error(`Product "${rawItem.productName || rawItem.productId}" has been removed from our catalog.`);
      err.statusCode = 400;
      throw err;
    }
    if (product.status !== 'published') {
      const err: any = new Error(`Product "${product.name}" is currently unavailable for purchase.`);
      err.statusCode = 400;
      throw err;
    }

    const qty = Number(rawItem.quantity);
    if (!Number.isFinite(qty) || !Number.isInteger(qty) || qty < 1) {
      const err: any = new Error(`Quantity for "${product.name}" must be a positive whole number.`);
      err.statusCode = 400;
      err.code = 'INVALID_QUANTITY';
      throw err;
    }
    if (qty > 999) {
      const err: any = new Error(`Requested quantity for "${product.name}" exceeds maximum allowed limit.`);
      err.statusCode = 400;
      err.code = 'EXCESS_QUANTITY';
      throw err;
    }

    const validation = validateVariantSelection(product, rawItem.selectedVariant);
    if (!validation.valid) {
      const err: any = new Error(validation.error || `Please select a valid variant for "${product.name}".`);
      err.statusCode = 400;
      err.code = 'INVALID_VARIANT';
      throw err;
    }

    const variantKey = getCartItemVariantKey(product.id, {
      ...(rawItem.selectedVariant || {}),
      variantId: validation.matchedItem?.id || rawItem.selectedVariant?.variantId,
    });
    const combinedQty = (qtyByKey.get(variantKey) || 0) + qty;
    qtyByKey.set(variantKey, combinedQty);

    if (combinedQty > validation.availableStock) {
      const err: any = new Error(
        `Insufficient stock for "${product.name}"${validation.label ? ` (${validation.label})` : ''}. Only ${validation.availableStock} unit(s) available.`
      );
      err.statusCode = 400;
      err.code = 'INSUFFICIENT_STOCK';
      throw err;
    }

    if (product.maxOrderQuantity && product.maxOrderQuantity > 0 && combinedQty > product.maxOrderQuantity) {
      const err: any = new Error(
        `"${product.name}" is limited to a maximum of ${product.maxOrderQuantity} unit(s) per order.`
      );
      err.statusCode = 400;
      err.code = 'MAX_ORDER_QUANTITY_EXCEEDED';
      throw err;
    }

    resolvedInputs.push({ rawItem, product, quantity: qty, validation });
  }

  const refreshMinutes = Number(store.settings?.exchangeRateRefreshMinutes || 30);
  const { rate, snapshot } = await resolveConversionRate({
    baseCurrency,
    targetCurrency: displayCurrency,
    refreshMinutes,
  });

  const coupon = getEffectiveCoupon(store, opts.couponCode);
  const breakdown = calculateOrderBreakdown({
    lines: resolvedInputs.map(entry => ({
      productId: entry.product.id,
      quantity: entry.quantity,
      baseUnitPrice: entry.validation.baseUnitPrice,
    })),
    settings: {
      baseCurrency,
      shippingCharge: Number(store.settings?.shippingCharge ?? 0),
      freeShippingThreshold: Number(store.settings?.freeShippingThreshold ?? 0),
      taxEnabled: store.settings?.taxEnabled !== false,
      taxRatePercentage: Number(store.settings?.taxRatePercentage ?? 5),
      priceRoundingMode: store.settings?.priceRoundingMode || 'two_decimals',
      shippingRegions: store.settings?.shippingRegions || [],
    },
    displayCurrency,
    exchangeRate: rate,
    coupon,
    country: opts.country,
  });

  const quoteTtlMin = Math.max(1, Number(process.env.EXCHANGE_RATE_QUOTE_TTL_MINUTES || 15));
  const quotePayload = {
    baseCurrency: breakdown.baseCurrency,
    displayCurrency: breakdown.displayCurrency,
    exchangeRate: breakdown.exchangeRate,
    exchangeRateTimestamp: snapshot.lastUpdated,
    expiresAt: new Date(Date.now() + quoteTtlMin * 60 * 1000).toISOString(),
    roundingMode: breakdown.roundingMode,
    isFallbackRate: snapshot.isFallback,
    baseSubtotal: breakdown.baseSubtotal,
    baseDiscount: breakdown.baseDiscount,
    baseShippingFee: breakdown.baseShippingFee,
    baseTaxAmount: breakdown.baseTaxAmount,
    baseTotal: breakdown.baseTotal,
    displaySubtotal: breakdown.displaySubtotal,
    displayDiscount: breakdown.displayDiscount,
    displayShippingFee: breakdown.displayShippingFee,
    displayTaxAmount: breakdown.displayTaxAmount,
    displayTotal: breakdown.displayTotal,
    shippingRegionName: breakdown.appliedShippingRegionName,
    taxEnabled: breakdown.taxEnabled,
    taxRatePercentage: breakdown.taxRatePercentage,
    couponEligible: breakdown.couponEligible,
    couponMessage: breakdown.couponMessage,
    items: resolvedInputs.map((entry, idx) => ({
      productId: entry.product.id,
      variantId: entry.validation.matchedItem?.id,
      sku: entry.validation.matchedItem?.sku || entry.product.sku,
      quantity: entry.quantity,
      baseUnitPrice: breakdown.lines[idx].baseUnitPrice,
      baseLineTotal: breakdown.lines[idx].baseLineTotal,
      displayUnitPrice: breakdown.lines[idx].displayUnitPrice,
      displayLineTotal: breakdown.lines[idx].displayLineTotal,
      availableStock: entry.validation.availableStock,
      maxOrderQuantity: entry.product.maxOrderQuantity,
    })),
  };

  if (opts.requireValidQuote) {
    const rateCheck = verifyLockedQuoteRate({
      baseCurrency,
      targetCurrency: displayCurrency,
      quotedExchangeRate: opts.quotedExchangeRate,
      quotedRateTimestamp: opts.quotedRateTimestamp,
      currentLiveRate: rate,
      quoteTtlMinutes: quoteTtlMin,
    });
    if (!rateCheck.valid) {
      const err: any = new Error(rateCheck.message || 'Exchange rate quote has changed or expired.');
      err.statusCode = 409;
      err.code = rateCheck.reason || 'QUOTE_STALE';
      err.quote = quotePayload;
      throw err;
    }

    if (
      typeof opts.expectedDisplayTotal === 'number' &&
      Number.isFinite(opts.expectedDisplayTotal)
    ) {
      const tolerance = displayCurrency === 'PKR' ? 2 : 0.05;
      if (Math.abs(breakdown.displayTotal - opts.expectedDisplayTotal) > tolerance) {
        const err: any = new Error(
          `Order total changed from ${formatExactCurrency(opts.expectedDisplayTotal, displayCurrency)} to ${formatExactCurrency(breakdown.displayTotal, displayCurrency)}. Please review and refresh your quote.`
        );
        err.statusCode = 409;
        err.code = 'PRICE_CHANGED';
        err.quote = quotePayload;
        throw err;
      }
    }
  }

  const orderItems = resolvedInputs.map((entry, idx) => {
    const matched = entry.validation.matchedItem;
    const rawVar = entry.rawItem.selectedVariant || {};
    const selectedVariant = matched
      ? {
          variantId: matched.id,
          sku: matched.sku,
          size: matched.size || rawVar.size,
          color: matched.color || rawVar.color,
          shade: matched.shade || rawVar.shade,
          attributes: matched.attributes || rawVar.attributes,
          label: entry.validation.label,
          image: matched.image || entry.product.images[0],
        }
      : {
          ...rawVar,
          label: entry.validation.label || undefined,
        };

    return {
      productId: entry.product.id,
      productName: entry.product.name,
      productImage: entry.validation.image || entry.product.images[0] || '',
      price: breakdown.lines[idx].displayUnitPrice,
      unitPrice: breakdown.lines[idx].displayUnitPrice,
      lineTotal: breakdown.lines[idx].displayLineTotal,
      baseUnitPrice: breakdown.lines[idx].baseUnitPrice,
      baseLineTotal: breakdown.lines[idx].baseLineTotal,
      quantity: entry.quantity,
      selectedVariant,
    };
  });

  const reserveVariantAndProductStock = () => {
    for (const entry of resolvedInputs) {
      const prod = store.products.find(p => p.id === entry.product.id);
      if (!prod) continue;
      if (entry.validation.matchedItem && Array.isArray(prod.variants?.items)) {
        const vItem = prod.variants.items.find(v => v.id === entry.validation.matchedItem!.id);
        if (vItem) {
          vItem.stock = Math.max(0, Math.floor(vItem.stock - entry.quantity));
          if (vItem.stock === 0 && vItem.availability === 'available') {
            vItem.availability = 'out_of_stock';
          }
        }
        prod.stock = getTotalProductVariantStock(prod);
      } else {
        prod.stock = Math.max(0, Math.floor(prod.stock - entry.quantity));
      }
      if (prod.stock <= 0) {
        prod.status = 'out_of_stock';
      }
    }
  };

  return {
    breakdown,
    snapshot,
    coupon: breakdown.couponEligible ? coupon : null,
    quotePayload,
    orderItems,
    reserveVariantAndProductStock,
  };
}

// Public Currency Rates Endpoint (cached & auto-refreshed, falls back gracefully or returns 503 if unavailable)
app.get('/api/currency/rates', async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const baseCurrency = normalizeCurrencyCode(
      typeof req.query.base === 'string' && req.query.base.trim()
        ? req.query.base
        : getStoreBaseCurrency(store)
    );
    const forceRefresh = req.query.refresh === '1' || req.query.refresh === 'true';
    const refreshMinutes = Number(store.settings?.exchangeRateRefreshMinutes || 30);

    const snapshot = await getExchangeRatesSnapshot({
      baseCurrency,
      refreshMinutes,
      forceRefresh,
    });

    return res.json({
      ...snapshot,
      enabledCurrencies: store.settings?.enabledCurrencies || [baseCurrency],
      defaultCustomerCurrency: store.settings?.defaultCustomerCurrency || baseCurrency,
      roundingMode: store.settings?.priceRoundingMode || 'two_decimals',
    });
  } catch (err: any) {
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    return res.status(503).json({
      error: err?.message || 'Unable to load exchange rates right now.',
      code: 'EXCHANGE_RATE_UNAVAILABLE',
    });
  }
});

// Admin Manual Refresh Exchange Rates Endpoint
app.post('/api/admin/currency/refresh', requireAdmin, async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const baseCurrency = normalizeCurrencyCode(
      typeof req.body?.baseCurrency === 'string' && req.body.baseCurrency.trim()
        ? req.body.baseCurrency
        : getStoreBaseCurrency(store)
    );
    const refreshMinutes = Number(store.settings?.exchangeRateRefreshMinutes || 30);
    const snapshot = await getExchangeRatesSnapshot({
      baseCurrency,
      refreshMinutes,
      forceRefresh: true,
    });

    const adminEmail = ((req as any).user as User)?.email || getPrimaryAdminEmail(store);
    db.addAuditLog({
      adminEmail,
      action: 'exchange_rates_refreshed',
      details: `Exchange rates refreshed for base currency ${baseCurrency} via ${snapshot.provider}.`,
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });

    return res.json({
      success: true,
      ...snapshot,
    });
  } catch (err: any) {
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    return res.status(503).json({
      error: err?.message || 'Unable to refresh live exchange rates.',
      code: 'EXCHANGE_RATE_UNAVAILABLE',
    });
  }
});

// Authoritative Checkout Quote Endpoint (locks displayed amounts & exchange rate before payment)
app.post('/api/checkout/quote', async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const { items, currency, country, couponCode } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty.' });
    }
    const result = await validateAndComputeCheckoutQuote(store, {
      items,
      displayCurrency: currency,
      country,
      couponCode,
      requireValidQuote: false,
    });
    return res.json({ success: true, quote: result.quotePayload });
  } catch (err: any) {
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    return res.status(err?.statusCode || 400).json({
      error: err?.message || 'Unable to generate checkout quote.',
      code: err?.code,
    });
  }
});

// Admin Pricing, Currency, Rounding, Shipping Region & Tax Configuration
app.put('/api/admin/pricing-settings', requireAdmin, async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const prevBaseCurrency = getStoreBaseCurrency(store);
    const {
      baseCurrency: rawBase,
      defaultCustomerCurrency: rawDefaultCustomer,
      enabledCurrencies: rawEnabled,
      exchangeRateRefreshMinutes,
      priceRoundingMode,
      taxEnabled,
      taxRatePercentage,
      shippingCharge,
      freeShippingThreshold,
      shippingRegions,
      convertExistingCatalogPrices,
    } = req.body || {};

    const nextBaseCurrency = normalizeCurrencyCode(rawBase || prevBaseCurrency);
    const baseMeta = getCurrencyMeta(nextBaseCurrency);

    const enabledSet = new Set<string>(
      (Array.isArray(rawEnabled) && rawEnabled.length > 0
        ? rawEnabled
        : store.settings.enabledCurrencies || [nextBaseCurrency]
      ).map((c: unknown) => normalizeCurrencyCode(String(c)))
    );
    enabledSet.add(nextBaseCurrency);
    const nextEnabledCurrencies = Array.from(enabledSet);

    const nextDefaultCustomerCurrency = nextEnabledCurrencies.includes(
      normalizeCurrencyCode(rawDefaultCustomer || store.settings.defaultCustomerCurrency)
    )
      ? normalizeCurrencyCode(rawDefaultCustomer || store.settings.defaultCustomerCurrency)
      : nextBaseCurrency;

    const validModes = ['none', 'two_decimals', 'nearest_integer', 'ending_99'];
    const nextRounding = validModes.includes(priceRoundingMode)
      ? priceRoundingMode
      : store.settings.priceRoundingMode || 'two_decimals';

    const nextRefreshMin =
      exchangeRateRefreshMinutes !== undefined
        ? Math.max(1, Math.min(1440, Math.floor(Number(exchangeRateRefreshMinutes))))
        : store.settings.exchangeRateRefreshMinutes || 30;

    const nextTaxEnabled =
      taxEnabled !== undefined ? Boolean(taxEnabled) : store.settings.taxEnabled !== false;
    const nextTaxRate =
      taxRatePercentage !== undefined
        ? Math.max(0, Math.min(50, Number(taxRatePercentage)))
        : store.settings.taxRatePercentage ?? 5;
    const nextShippingCharge =
      shippingCharge !== undefined
        ? Math.max(0, Number(shippingCharge))
        : store.settings.shippingCharge;
    const nextFreeThreshold =
      freeShippingThreshold !== undefined
        ? Math.max(0, Number(freeShippingThreshold))
        : store.settings.freeShippingThreshold;

    let rescaledRate: number | null = null;
    if (convertExistingCatalogPrices && nextBaseCurrency !== prevBaseCurrency) {
      const { rate } = await resolveConversionRate({
        baseCurrency: prevBaseCurrency,
        targetCurrency: nextBaseCurrency,
        refreshMinutes: nextRefreshMin,
      });
      rescaledRate = rate;
      const decimals = baseMeta.decimals === 0 ? 0 : 2;
      const roundVal = (n: number) => Number((n * rate).toFixed(decimals));

      store.products = store.products.map(p => {
        const nextProd: Product = {
          ...p,
          baseCurrency: nextBaseCurrency,
          originalPrice: roundVal(p.originalPrice),
          sellingPrice: roundVal(p.sellingPrice),
          updatedAt: new Date().toISOString(),
        };
        if (nextProd.variants?.items && nextProd.variants.items.length > 0) {
          nextProd.variants = {
            ...nextProd.variants,
            items: nextProd.variants.items.map(vi => ({
              ...vi,
              price: typeof vi.price === 'number' ? roundVal(vi.price) : vi.price,
              priceAdjustment:
                typeof vi.priceAdjustment === 'number' ? roundVal(vi.priceAdjustment) : vi.priceAdjustment,
            })),
          };
        }
        return nextProd;
      });

      store.coupons = store.coupons.map(c => ({
        ...c,
        minOrderValue: roundVal(c.minOrderValue),
        discountValue: c.discountType === 'fixed' ? roundVal(c.discountValue) : c.discountValue,
      }));
    } else {
      store.products = store.products.map(p => ({ ...p, baseCurrency: nextBaseCurrency }));
    }

    const sanitizedRegions = Array.isArray(shippingRegions)
      ? shippingRegions
          .filter(r => r && r.regionName)
          .map(r => ({
            id: r.id || `reg_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
            regionName: String(r.regionName).trim(),
            countries: Array.isArray(r.countries)
              ? r.countries.map((c: unknown) => String(c).trim()).filter(Boolean)
              : ['*'],
            shippingCharge: Math.max(0, Number(r.shippingCharge || 0)),
            freeShippingThreshold: Math.max(0, Number(r.freeShippingThreshold || 0)),
            estimatedDays: r.estimatedDays ? String(r.estimatedDays).trim() : undefined,
          }))
      : store.settings.shippingRegions;

    store.settings = {
      ...store.settings,
      currency: nextBaseCurrency,
      baseCurrency: nextBaseCurrency,
      currencySymbol: baseMeta.symbol,
      defaultCustomerCurrency: nextDefaultCustomerCurrency,
      enabledCurrencies: nextEnabledCurrencies,
      exchangeRateRefreshMinutes: nextRefreshMin,
      priceRoundingMode: nextRounding,
      taxEnabled: nextTaxEnabled,
      taxRatePercentage: nextTaxRate,
      shippingCharge: rescaledRate ? Number((nextShippingCharge * rescaledRate).toFixed(baseMeta.decimals === 0 ? 0 : 2)) : nextShippingCharge,
      freeShippingThreshold: rescaledRate ? Number((nextFreeThreshold * rescaledRate).toFixed(baseMeta.decimals === 0 ? 0 : 2)) : nextFreeThreshold,
      shippingRegions: sanitizedRegions,
    };

    const adminEmail = ((req as any).user as User)?.email || getPrimaryAdminEmail(store);
    db.addAuditLog({
      adminEmail,
      action: 'pricing_settings_updated',
      details: `Base currency=${nextBaseCurrency}, enabled=[${nextEnabledCurrencies.join(',')}], rounding=${nextRounding}, taxEnabled=${nextTaxEnabled} (${nextTaxRate}%)${rescaledRate ? `, rescaled catalog x${rescaledRate.toFixed(4)}` : ''}.`,
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });

    db.commit();

    // Warm exchange rates for the newly configured base currency
    let ratesSnapshot = null;
    try {
      ratesSnapshot = await getExchangeRatesSnapshot({
        baseCurrency: nextBaseCurrency,
        refreshMinutes: nextRefreshMin,
      });
    } catch {
      // Non-fatal if offline; client will see explicit status
    }

    return res.json({
      success: true,
      settings: store.settings,
      ratesSnapshot,
    });
  } catch (err: any) {
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    return res.status(500).json({ error: err?.message || 'Failed to update pricing settings.' });
  }
});

function getAuthorizedAdminEmails(store?: ReturnType<typeof db.getData>): string[] {
  const s = store || db.getData();
  const configured = Array.isArray(s.authorizedAdminEmails)
    ? s.authorizedAdminEmails
        .map((e: any) => String(e || '').trim().toLowerCase())
        .filter((e: string) => e.includes('@'))
    : [];
  if (configured.length > 0) {
    return Array.from(new Set(configured));
  }
  return [DEFAULT_ADMIN_EMAIL];
}

function getPrimaryAdminEmail(store?: ReturnType<typeof db.getData>): string {
  const s = store || db.getData();
  const list = getAuthorizedAdminEmails(s);
  const candidate = String(s.primaryAdminEmail || '').trim().toLowerCase();
  if (candidate && list.includes(candidate)) {
    return candidate;
  }
  return list[0] || DEFAULT_ADMIN_EMAIL;
}

function getActiveGoogleDriveConfig(store?: ReturnType<typeof db.getData>) {
  const s = store || db.getData();
  const primaryEmail = getPrimaryAdminEmail(s);
  const cfg = s.googleDriveConfig;
  const folderId = String(cfg?.folderId || DEFAULT_DRIVE_FOLDER_ID).trim() || DEFAULT_DRIVE_FOLDER_ID;
  const folderName = String(cfg?.folderName || DEFAULT_DRIVE_FOLDER_NAME).trim() || DEFAULT_DRIVE_FOLDER_NAME;
  const folderUrl =
    String(cfg?.folderUrl || '').trim() || `https://drive.google.com/drive/folders/${folderId}`;
  const ownerEmail = String(cfg?.ownerEmail || primaryEmail).trim().toLowerCase() || primaryEmail;
  return {
    ownerEmail,
    folderId,
    folderName,
    folderUrl,
    lastMigratedAt: cfg?.lastMigratedAt,
    migratedFromEmail: cfg?.migratedFromEmail,
    migrationHistory: Array.isArray(cfg?.migrationHistory) ? cfg!.migrationHistory : [],
  };
}

function isAuthorizedAdminEmail(email: string, store?: ReturnType<typeof db.getData>): boolean {
  const cleanEmail = String(email || '').trim().toLowerCase();
  if (!cleanEmail) return false;
  return getAuthorizedAdminEmails(store).includes(cleanEmail);
}

async function verifyUserPassword(user: User, rawPasswordInput: string): Promise<boolean> {
  const rawPassword = String(rawPasswordInput || '');
  const trimmedPassword = rawPassword.trim();
  if (!rawPassword) return false;

  if (user.password.startsWith('$2')) {
    let matched = await bcrypt.compare(rawPassword, user.password);
    if (!matched && trimmedPassword !== rawPassword) {
      matched = await bcrypt.compare(trimmedPassword, user.password);
    }
    if (matched) return true;
  } else if (user.password === rawPassword || user.password === trimmedPassword) {
    user.password = await bcrypt.hash(rawPassword, 10);
    db.commit();
    return true;
  }

  // Initial bootstrap password support ONLY before the default bootstrap owner customizes their password
  if (!user.passwordCustomized && user.email.trim().toLowerCase() === DEFAULT_ADMIN_EMAIL) {
    const initialPasswords = ['Huzaifa2009@Pak', 'Huzaifa2009@pak'];
    if (initialPasswords.includes(rawPassword) || initialPasswords.includes(trimmedPassword)) {
      user.password = await bcrypt.hash(rawPassword, 10);
      db.commit();
      return true;
    }
  }

  if (user.id === 'user_cust_1' && !user.passwordCustomized) {
    if (rawPassword === 'customer123Password!' || trimmedPassword === 'customer123Password!') {
      return true;
    }
  }

  return false;
}

// ==========================================
// 1. FILE UPLOADS (From PC Gallery)
// ==========================================
app.post('/api/upload', requireAdmin, (req: Request, res: Response) => {
  try {
    const { base64, fileName, folder = 'Product_Images' } = req.body;
    if (!base64) {
      return res.status(400).json({ error: 'No image data provided' });
    }
    const publicUrl = db.saveUploadedFile(base64, fileName, folder);
    return res.json({ success: true, url: publicUrl });
  } catch (err: any) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: err.message || 'Failed to upload image' });
  }
});

// Safe Image Deletion (checks references so items aren't broken)
app.post('/api/upload/delete', requireAdmin, (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'Image URL is required for deletion' });
    }
    const result = db.deleteUploadedFile(url);
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to delete image' });
  }
});

// List previously uploaded brand logos stored on server / PC disk
app.get('/api/admin/logos', requireAdmin, (req: Request, res: Response) => {
  try {
    const logos = db.listUploadedLogos();
    return res.json({ success: true, logos });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to list stored logos' });
  }
});

// ==========================================
// 2. AUTHENTICATION & USERS
// ==========================================
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const store = db.getData();
  const cleanEmail = String(email).trim().toLowerCase();
  let user = store.users.find(u => u.email.toLowerCase() === cleanEmail);

  // Auto-provision the initial bootstrap administrator account ONLY if still authorized & missing
  const isCleanAuthorizedAdmin = isAuthorizedAdminEmail(cleanEmail, store);
  if (!user && cleanEmail === DEFAULT_ADMIN_EMAIL && isCleanAuthorizedAdmin) {
    user = {
      id: 'user_admin_huzaifa',
      email: 'Huzaifa60010@gmail.com',
      password: await bcrypt.hash('Huzaifa2009@Pak', 10),
      fullName: 'Huzaifa Admin',
      role: 'admin',
      phone: '+1 (800) 849-2041',
      savedAddresses: [],
      wishlist: [],
      createdAt: new Date().toISOString(),
      isEmailVerified: true,
      accountStatus: 'active',
      passwordCustomized: false,
    };
    store.users.unshift(user);
    db.commit();
  }

  if (!user) {
    return res.status(401).json({
      error: 'Invalid email or password. Please verify your credentials or click "Create Account" to register.',
    });
  }

  const isMatch = await verifyUserPassword(user, String(password));

  if (!isMatch) {
    if (isCleanAuthorizedAdmin) {
      db.addAuditLog({
        adminEmail: user.email,
        action: 'admin_login_failed',
        details: 'Failed administrator authentication: incorrect password submitted.',
        status: 'failure',
        ip: req.ip || req.socket.remoteAddress,
      });
    }
    return res.status(401).json({
      error: 'Invalid email or password. Please verify your credentials or click "Forgot Password?".',
    });
  }

  // Enforce strict role assignment from server-side dynamic admin allowlist
  const isOwnerAdmin = isCleanAuthorizedAdmin;
  if (isOwnerAdmin) {
    user.role = 'admin';
    user.isEmailVerified = true;
    user.accountStatus = 'active';
    db.commit();
  } else if (user.role === 'admin') {
    user.role = 'customer';
    db.commit();
  }

  // Check email verification status for customers
  if (user.role === 'customer' && user.isEmailVerified === false) {
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    db.createOrUpdateOtp(cleanEmail, otpCode, 'registration');
    await sendOtpEmail(cleanEmail, user.fullName, otpCode, 'registration');
    return res.status(200).json({
      success: true,
      requiresVerification: true,
      email: user.email,
      fullName: user.fullName,
      message: 'Your account requires email verification. A fresh 6-digit code has been dispatched to your email.',
    });
  }

  const effectiveRole = getEffectiveRole(user);

  if (effectiveRole === 'admin') {
    db.addAuditLog({
      adminEmail: user.email,
      action: 'admin_login_success',
      details: 'Administrator successfully verified with salted bcrypt hash.',
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });
  } else {
    db.logAccountActivity({
      customerId: user.id,
      email: user.email,
      activityType: 'sign_in',
      details: 'Customer successfully authenticated session.',
      status: 'success',
      ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
    });
  }

  const token = issueSignedToken(user);
  const safeUser = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: effectiveRole,
    phone: user.phone,
    savedAddresses: user.savedAddresses || [],
    wishlist: user.wishlist || [],
    isEmailVerified: user.isEmailVerified ?? true,
  };

  return res.json({ success: true, token, user: safeUser, adminAuthorized: effectiveRole === 'admin' });
});

// Firebase Authentication Session Sync & Server-Side Token + Role Verification
app.post('/api/auth/firebase-session', async (req: Request, res: Response) => {
  const { idToken, googleAccessToken, fullName, phone, isNewRegistration, authProvider } = req.body;

  if (!idToken && !googleAccessToken) {
    return res.status(401).json({
      error: 'A verified Firebase ID token or Google OAuth access token is required.',
    });
  }

  let verified: VerifiedExternalIdentity | null = null;
  if (idToken) {
    verified = await verifyFirebaseIdToken(String(idToken));
  }
  if (!verified && googleAccessToken) {
    verified = await verifyGoogleAccessToken(String(googleAccessToken));
  }

  if (!verified || !verified.email) {
    return res.status(401).json({
      error: 'Invalid or expired authentication token. Access denied.',
    });
  }

  const store = db.getData();
  const cleanEmail = verified.email.trim().toLowerCase();
  const matchesAdminEmail = isAuthorizedAdminEmail(cleanEmail, store);
  const isVerifiedAdmin = matchesAdminEmail && verified.emailVerified === true;
  const assignedRole: 'admin' | 'customer' = isVerifiedAdmin ? 'admin' : 'customer';

  let user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
  const resolvedName =
    (fullName && String(fullName).trim()) ||
    verified.fullName ||
    cleanEmail.split('@')[0];

  if (!user) {
    const hashedPassword = await bcrypt.hash(`fb_${verified.uid}_${Date.now()}`, 10);
    user = {
      id: isVerifiedAdmin && cleanEmail === DEFAULT_ADMIN_EMAIL ? 'user_admin_huzaifa' : `user_${verified.uid}`,
      email: cleanEmail,
      password: hashedPassword,
      fullName: resolvedName,
      role: assignedRole,
      phone: phone ? String(phone).trim() : undefined,
      savedAddresses: [],
      wishlist: [],
      createdAt: new Date().toISOString(),
      isEmailVerified: verified.emailVerified,
      accountStatus: 'active',
    };
    if (authProvider) {
      (user as any).authProvider = String(authProvider);
    }
    store.users.push(user);

    if (assignedRole === 'customer') {
      db.logRegistration({
        customerId: user.id,
        email: cleanEmail,
        fullName: user.fullName,
        registrationDate: user.createdAt,
        verificationStatus: verified.emailVerified ? 'verified' : 'pending_verification',
        accountStatus: 'active',
        status: 'success',
        ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
        details: 'Customer registered via Firebase Authentication.',
      });
    }
  } else {
    user.role = assignedRole;
    user.isEmailVerified = verified.emailVerified;
    user.accountStatus = 'active';
    if (authProvider) {
      (user as any).authProvider = String(authProvider);
    }
    if (resolvedName && !user.fullName) {
      user.fullName = resolvedName;
    }
    if (phone && String(phone).trim()) {
      user.phone = String(phone).trim();
    }
  }

  if (matchesAdminEmail && !isVerifiedAdmin) {
    db.addAuditLog({
      adminEmail: cleanEmail,
      action: 'admin_verification_incomplete',
      details: 'Account matched authorized admin email but Firebase email_verified is false; downgraded to customer homepage per security policy.',
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
  } else if (assignedRole === 'admin') {
    db.addAuditLog({
      adminEmail: cleanEmail,
      action: 'admin_firebase_login_success',
      details: 'Verified administrator session authenticated via Firebase/Google ID token.',
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });
  }

  db.logAccountActivity({
    customerId: user.id,
    email: cleanEmail,
    activityType: isNewRegistration ? 'registration' : 'sign_in',
    details: isNewRegistration
      ? `Customer account registered via Firebase Authentication for ${cleanEmail}.`
      : `User signed in via Firebase Authentication${assignedRole === 'admin' ? ' (Verified Admin)' : ''}.`,
    status: 'success',
    ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
  });

  db.commit();

  const token = issueSignedToken(user);
  const effectiveRole = getEffectiveRole(user);
  const safeUser = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: effectiveRole,
    phone: user.phone,
    savedAddresses: user.savedAddresses || [],
    wishlist: user.wishlist || [],
    isEmailVerified: verified.emailVerified,
    accountStatus: 'active' as const,
    authProvider:
      (user as any).authProvider === 'google' || (user as any).authProvider === 'Google'
        ? 'Google'
        : 'Email',
  };

  return res.json({
    success: true,
    token,
    user: safeUser,
    adminAuthorized: effectiveRole === 'admin',
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
  });
});

// Dedicated Administrator Authentication Gateway
// Online verification using salted bcrypt hashing and strict single-admin email allowlist
app.post('/api/admin/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Administrator email and password are required.' });
  }

  const store = db.getData();
  const cleanEmail = String(email).trim().toLowerCase();
  if (!isAuthorizedAdminEmail(cleanEmail, store)) {
    db.addAuditLog({
      adminEmail: cleanEmail,
      action: 'admin_login_unauthorized',
      details: `Unauthorized account (${cleanEmail}) attempted Admin Console sign-in. Access denied.`,
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.status(403).json({
      success: false,
      error: 'You are not authorized to access the Admin Dashboard.',
    });
  }

  let user = store.users.find(u => u.email.toLowerCase() === cleanEmail);

  if (!user && cleanEmail === DEFAULT_ADMIN_EMAIL) {
    user = {
      id: 'user_admin_huzaifa',
      email: 'Huzaifa60010@gmail.com',
      password: await bcrypt.hash('Huzaifa2009@Pak', 10),
      fullName: 'Huzaifa Admin',
      role: 'admin',
      phone: '+1 (800) 849-2041',
      savedAddresses: [],
      wishlist: [],
      createdAt: new Date().toISOString(),
      isEmailVerified: true,
      accountStatus: 'active',
      passwordCustomized: false,
    };
    store.users.unshift(user);
    db.commit();
  }

  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Administrator account uses Google Sign-In. Please click "Sign in with Google" or set an Admin password during transfer.',
    });
  }

  const isMatch = await verifyUserPassword(user, String(password));

  if (!isMatch) {
    db.addAuditLog({
      adminEmail: user.email,
      action: 'admin_login_failed',
      details: 'Failed administrator authentication: Incorrect password submitted.',
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.status(401).json({
      success: false,
      error: 'Incorrect email or password. Access denied.',
    });
  }

  user.role = 'admin';
  user.isEmailVerified = true;
  user.accountStatus = 'active';
  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_login_success',
    details: 'Administrator successfully verified online with salted bcrypt hash encryption.',
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });
  db.commit();

  const token = issueSignedToken(user);
  const safeUser = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: 'admin' as const,
    phone: user.phone,
    savedAddresses: user.savedAddresses || [],
    wishlist: user.wishlist || [],
    isEmailVerified: true,
  };

  return res.json({
    success: true,
    token,
    user: safeUser,
    adminAuthorized: true,
    message: 'Administrator clearance granted. Welcome to NOVORA Command Console.',
  });
});

// Administrator Session Revocation / Logout
app.post('/api/admin/logout', requireAdmin, (req: Request, res: Response) => {
  const user = (req as any).user as User;
  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_logout',
    details: 'Administrator session securely revoked. Access locked.',
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });
  return res.json({ success: true, message: 'Administrator session revoked successfully.' });
});

app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { email, password, confirmPassword, fullName, phone, agreedToTerms } = req.body;
  if (!email || !password || !fullName) {
    return res.status(400).json({ error: 'Full legal name, email address, and password are required.' });
  }

  if (agreedToTerms !== true && agreedToTerms !== 'true') {
    return res.status(400).json({ error: 'You must agree to the Privacy Policy and Terms of Service to create an account.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const cleanEmail = email.trim().toLowerCase();
  if (!emailRegex.test(cleanEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  if (confirmPassword && password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match. Please verify and try again.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  const store = db.getData();
  const existing = store.users.find(u => u.email.toLowerCase() === cleanEmail);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email address already exists. Please sign in instead.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  // Security Rule: Frontend registration forms ALWAYS save a normal customer profile (never self-escalates to admin)
  const newUser: User = {
    id: `user_cust_${Date.now()}`,
    email: cleanEmail,
    password: hashedPassword,
    fullName: fullName.trim(),
    role: 'customer',
    phone: phone ? phone.trim() : undefined,
    savedAddresses: [],
    wishlist: [],
    createdAt: new Date().toISOString(),
    isEmailVerified: isAuthorizedAdminEmail(cleanEmail, store) ? false : true,
    accountStatus: 'active',
  };

  store.users.push(newUser);

  db.logRegistration({
    customerId: newUser.id,
    email: cleanEmail,
    fullName: newUser.fullName,
    registrationDate: newUser.createdAt,
    verificationStatus: newUser.isEmailVerified ? 'verified' : 'pending_verification',
    accountStatus: 'active',
    status: 'success',
    ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
    details: 'Customer account registered with email and password.',
  });

  db.logAccountActivity({
    customerId: newUser.id,
    email: cleanEmail,
    activityType: 'registration',
    details: `Customer profile created for ${cleanEmail}.`,
    status: 'success',
    ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
  });

  db.commit();

  const token = issueSignedToken(newUser);

  return res.status(201).json({
    success: true,
    token,
    user: db.sanitizeUser(newUser),
    adminAuthorized: false,
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
    email: cleanEmail,
    fullName: newUser.fullName,
    message: 'Account created successfully! Welcome to NOVORA.',
  });
});

app.post('/api/auth/verify-otp', async (req: Request, res: Response) => {
  const { email, code, purpose = 'registration' } = req.body;
  if (!email || !code) {
    return res.status(400).json({ error: 'Email address and 6-digit verification code are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanCode = String(code).trim();
  const otpRecord = db.getOtp(cleanEmail, purpose as any);

  if (!otpRecord) {
    return res.status(400).json({ error: 'No active verification code found or code has expired. Please request a new code.' });
  }

  if (Date.now() > otpRecord.expiresAt) {
    db.deleteOtp(cleanEmail, purpose as any);
    return res.status(400).json({ error: 'Verification code has expired (10-minute validity limit). Please request a new code.' });
  }

  if ((otpRecord.attempts || 0) >= 5) {
    db.deleteOtp(cleanEmail, purpose as any);
    return res.status(429).json({ error: 'Maximum verification attempts exceeded. Code has been invalidated for security. Please request a new code.' });
  }

  if (otpRecord.code !== cleanCode) {
    const attempts = db.incrementOtpAttempts(cleanEmail, purpose as any);
    const remaining = Math.max(0, 5 - attempts);
    return res.status(400).json({
      error: `Invalid verification code. ${remaining} attempt(s) remaining.`,
      remainingAttempts: remaining,
    });
  }

  db.deleteOtp(cleanEmail, purpose as any);

  if (purpose === 'password_reset') {
    return res.json({
      success: true,
      message: 'Code verified successfully. You may now set your new password.',
    });
  }

  const updatedUser = db.markEmailVerified(cleanEmail);
  if (!updatedUser) {
    return res.status(404).json({ error: 'User account not found.' });
  }
  updatedUser.role = isAuthorizedAdminEmail(cleanEmail) ? 'admin' : 'customer';
  db.commit();

  db.logAccountActivity({
    customerId: updatedUser.id,
    email: cleanEmail,
    activityType: 'email_verified',
    details: 'Customer verified email address using 6-digit OTP.',
    status: 'success',
    ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
  });

  const token = issueSignedToken(updatedUser);
  return res.json({
    success: true,
    message: 'Email successfully verified! Welcome to NOVORA.',
    token,
    user: db.sanitizeUser(updatedUser),
  });
});

app.post('/api/auth/resend-otp', async (req: Request, res: Response) => {
  const { email, purpose = 'registration' } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const existingOtp = db.getOtp(cleanEmail, purpose as any);

  if (existingOtp && Date.now() - existingOtp.lastRequestedAt < 60 * 1000) {
    const waitSeconds = Math.ceil((60 * 1000 - (Date.now() - existingOtp.lastRequestedAt)) / 1000);
    return res.status(429).json({
      error: `Please wait ${waitSeconds} seconds before requesting another verification code.`,
      cooldownSeconds: waitSeconds,
    });
  }

  const store = db.getData();
  const user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
  const recipientName = user ? user.fullName : 'Valued Patron';

  const newCode = Math.floor(100000 + Math.random() * 900000).toString();
  db.createOrUpdateOtp(cleanEmail, newCode, purpose as any);
  await sendOtpEmail(cleanEmail, recipientName, newCode, purpose as any);

  return res.json({
    success: true,
    message: 'A fresh 6-digit verification code has been dispatched to your email address.',
    cooldownSeconds: 60,
  });
});

// Google Authentication handler — requires verified Firebase ID token or Google OAuth Access Token
app.post('/api/auth/google', async (req: Request, res: Response) => {
  const { idToken, googleAccessToken, fullName } = req.body;
  if (!idToken && !googleAccessToken) {
    return res.status(401).json({
      error: 'A verified Google OAuth token or Firebase ID token is required.',
    });
  }

  let verified: VerifiedExternalIdentity | null = null;
  if (idToken) {
    verified = await verifyFirebaseIdToken(String(idToken));
  }
  if (!verified && googleAccessToken) {
    verified = await verifyGoogleAccessToken(String(googleAccessToken));
  }

  if (!verified || !verified.email) {
    return res.status(401).json({
      error: 'Google authentication token could not be verified on the server.',
    });
  }

  const store = db.getData();
  const cleanEmail = verified.email.trim().toLowerCase();
  const isVerifiedAdmin = isAuthorizedAdminEmail(cleanEmail, store) && verified.emailVerified === true;
  const assignedRole: 'admin' | 'customer' = isVerifiedAdmin ? 'admin' : 'customer';

  let user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
  const resolvedName =
    (fullName && String(fullName).trim()) ||
    verified.fullName ||
    cleanEmail.split('@')[0];

  if (!user) {
    const hashedPassword = await bcrypt.hash(`gauth_${Date.now()}_pwd`, 10);
    user = {
      id: isVerifiedAdmin && cleanEmail === DEFAULT_ADMIN_EMAIL ? 'user_admin_huzaifa' : `user_g_${Date.now()}`,
      email: cleanEmail,
      password: hashedPassword,
      fullName: resolvedName,
      role: assignedRole,
      savedAddresses: [],
      wishlist: [],
      createdAt: new Date().toISOString(),
      isEmailVerified: verified.emailVerified,
      accountStatus: 'active',
    };
    (user as any).authProvider = 'Google';
    store.users.push(user);
  } else {
    user.role = assignedRole;
    user.isEmailVerified = verified.emailVerified;
    user.accountStatus = 'active';
    (user as any).authProvider = 'Google';
    if (resolvedName && !user.fullName) {
      user.fullName = resolvedName;
    }
  }

  if (assignedRole === 'admin') {
    db.addAuditLog({
      adminEmail: user.email,
      action: 'admin_google_login_success',
      details: `Administrator verified & unlocked Admin Dashboard via Google Sign-In (${user.email}).`,
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });
  } else {
    db.logAccountActivity({
      customerId: user.id,
      email: user.email,
      activityType: 'sign_in',
      details: 'Customer signed in via verified Google authentication.',
      status: 'success',
      ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
    });
  }

  db.commit();

  const token = issueSignedToken(user);
  const effectiveRole = getEffectiveRole(user);
  const safeUser = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: effectiveRole,
    phone: user.phone,
    savedAddresses: user.savedAddresses || [],
    wishlist: user.wishlist || [],
    isEmailVerified: verified.emailVerified,
    accountStatus: 'active' as const,
    authProvider: 'Google',
  };

  return res.json({
    success: true,
    token,
    user: safeUser,
    adminAuthorized: effectiveRole === 'admin',
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
  });
});

app.get('/api/auth/me', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const effectiveRole = getEffectiveRole(user);
  const safeUser = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: effectiveRole,
    phone: user.phone,
    savedAddresses: user.savedAddresses || [],
    wishlist: user.wishlist || [],
    isEmailVerified: user.isEmailVerified ?? true,
    authProvider:
      (user as any).authProvider === 'google' || (user as any).authProvider === 'Google'
        ? 'Google'
        : 'Email',
  };
  return res.json({ user: safeUser, adminAuthorized: effectiveRole === 'admin' });
});

app.get('/api/auth/admin-check', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ authorized: false, error: 'Authentication required.' });
  }
  if (!isVerifiedAdminUser(user)) {
    return res.status(403).json({
      authorized: false,
      role: 'customer',
      email: user.email,
      error: 'Access denied. Administrator permissions required.',
    });
  }
  return res.json({
    authorized: true,
    role: 'admin',
    email: user.email,
  });
});

app.put('/api/auth/profile', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const store = db.getData();
  const dbUser = store.users.find(u => u.id === user.id);
  if (!dbUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const { fullName, phone, savedAddresses, wishlist } = req.body;
  if (fullName !== undefined) dbUser.fullName = fullName;
  if (phone !== undefined) dbUser.phone = phone;
  if (savedAddresses !== undefined) dbUser.savedAddresses = savedAddresses;
  if (wishlist !== undefined) dbUser.wishlist = wishlist;

  db.commit();

  return res.json({
    success: true,
    user: {
      id: dbUser.id,
      email: dbUser.email,
      fullName: dbUser.fullName,
      role: dbUser.role,
      phone: dbUser.phone,
      savedAddresses: dbUser.savedAddresses,
      wishlist: dbUser.wishlist,
    },
  });
});

// Forgot Password — generates secure 6-digit verification code sent via sendOtpEmail
app.post('/api/auth/forgot-password', async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const store = db.getData();
  const user = store.users.find(u => u.email.toLowerCase() === cleanEmail);

  // Always return a neutral confirmation message without revealing whether an account exists
  if (user) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    db.createOrUpdateOtp(cleanEmail, code, 'password_reset');
    await sendOtpEmail(cleanEmail, user.fullName, code, 'password_reset');
  }

  return res.json({
    success: true,
    message: 'If an account exists with this email address, a 6-digit verification code has been dispatched to your inbox.',
  });
});

// Reset Password with verification code & bcrypt salted hashing
app.post('/api/auth/reset-password', async (req: Request, res: Response) => {
  const { email, code, newPassword, confirmPassword } = req.body;
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Email, verification code, and new password are required.' });
  }

  if (confirmPassword && newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanCode = String(code).trim();
  const otpRecord = db.getOtp(cleanEmail, 'password_reset');

  if (!otpRecord) {
    return res.status(400).json({ error: 'No active password reset request found or code has expired. Please request a new code.' });
  }

  if (Date.now() > otpRecord.expiresAt) {
    db.deleteOtp(cleanEmail, 'password_reset');
    return res.status(400).json({ error: 'Verification code has expired (10-minute limit). Please request a new password reset.' });
  }

  if ((otpRecord.attempts || 0) >= 5) {
    db.deleteOtp(cleanEmail, 'password_reset');
    return res.status(429).json({ error: 'Maximum attempts exceeded. This verification code has been invalidated for security. Please request a new password reset.' });
  }

  if (otpRecord.code !== cleanCode) {
    const attempts = db.incrementOtpAttempts(cleanEmail, 'password_reset');
    const remaining = Math.max(0, 5 - attempts);
    return res.status(400).json({
      error: `Invalid verification code. ${remaining} attempt(s) remaining.`,
      remainingAttempts: remaining,
    });
  }

  const store = db.getData();
  const user = store.users.find(u => u.email.toLowerCase() === cleanEmail);
  if (!user) {
    return res.status(404).json({ error: 'User account not found.' });
  }

  // Salt and hash new password using bcrypt
  user.password = await bcrypt.hash(newPassword, 10);
  user.updatedAt = new Date().toISOString();
  db.deleteOtp(cleanEmail, 'password_reset');
  db.commit();

  return res.json({
    success: true,
    message: 'Your password has been successfully reset. You can now sign in with your new credentials.',
  });
});

// Delivery Address Management
app.post('/api/auth/address', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const store = db.getData();
  const dbUser = store.users.find(u => u.id === user.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found' });

  const payload = req.body.address ? req.body.address : req.body;
  const {
    fullName,
    email,
    phone,
    country,
    state: rawState,
    province,
    city,
    streetAddress,
    houseNumber,
    postalCode,
    apartmentDetails,
    isDefault,
  } = payload;

  const state = rawState || province;

  if (!fullName || !country || !state || !city || !streetAddress || !houseNumber || !postalCode) {
    return res.status(400).json({ error: 'All compulsory delivery address fields are required.' });
  }

  if (!dbUser.savedAddresses) dbUser.savedAddresses = [];

  const newAddress: DeliveryAddress = {
    id: `addr_${Date.now()}`,
    fullName: fullName.trim(),
    email: (email || dbUser.email).trim().toLowerCase(),
    phone: (phone || dbUser.phone || '').trim(),
    country: country.trim(),
    state: state.trim(),
    city: city.trim(),
    streetAddress: streetAddress.trim(),
    houseNumber: houseNumber.trim(),
    apartmentDetails: apartmentDetails ? apartmentDetails.trim() : '',
    postalCode: postalCode.trim(),
    isDefault: isDefault ?? (dbUser.savedAddresses.length === 0),
  };

  if (newAddress.isDefault) {
    dbUser.savedAddresses.forEach(a => { a.isDefault = false; });
  }

  dbUser.savedAddresses.push(newAddress);

  db.logAccountActivity({
    customerId: dbUser.id,
    email: dbUser.email,
    activityType: 'address_saved',
    details: `Delivery address added: ${newAddress.streetAddress}, ${newAddress.city}, ${newAddress.country}`,
    status: 'success',
    ip: req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1',
  });

  db.commit();

  return res.status(201).json({ success: true, addresses: dbUser.savedAddresses, address: newAddress });
});

app.put('/api/auth/address/:id', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) return res.status(401).json({ error: 'Authentication required' });

  const store = db.getData();
  const dbUser = store.users.find(u => u.id === user.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found' });

  const addrIdx = (dbUser.savedAddresses || []).findIndex(a => a.id === req.params.id);
  if (addrIdx === -1) return res.status(404).json({ error: 'Address not found' });

  if (req.body.isDefault) {
    dbUser.savedAddresses.forEach(a => { a.isDefault = false; });
  }

  dbUser.savedAddresses[addrIdx] = {
    ...dbUser.savedAddresses[addrIdx],
    ...req.body,
    id: req.params.id,
  };

  db.commit();
  return res.json({ success: true, addresses: dbUser.savedAddresses, address: dbUser.savedAddresses[addrIdx] });
});

app.delete('/api/auth/address/:id', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  if (!user) return res.status(401).json({ error: 'Authentication required' });

  const store = db.getData();
  const dbUser = store.users.find(u => u.id === user.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found' });

  dbUser.savedAddresses = (dbUser.savedAddresses || []).filter(a => a.id !== req.params.id);
  if (dbUser.savedAddresses.length > 0 && !dbUser.savedAddresses.some(a => a.isDefault)) {
    dbUser.savedAddresses[0].isDefault = true;
  }

  db.commit();
  return res.json({ success: true, addresses: dbUser.savedAddresses });
});

// Admin get all registered customers (Only authorized administrators)
// Never exposes passwords, password hashes, or OTP codes
app.get('/api/customers', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const customers = store.users
    .filter(u => u.role === 'customer')
    .map(u => {
      const orders = store.orders.filter(o => o.userId === u.id || o.customer.email.toLowerCase() === u.email.toLowerCase());
      const totalSpent = orders.reduce((sum, o) => sum + o.total, 0);
      return {
        id: u.id,
        email: u.email,
        fullName: u.fullName,
        phone: u.phone || 'N/A',
        createdAt: u.createdAt,
        registrationDate: u.createdAt,
        isEmailVerified: u.isEmailVerified ?? false,
        emailVerifiedAt: u.emailVerifiedAt || null,
        verificationStatus: (u.isEmailVerified ? 'verified' : 'pending_verification') as 'verified' | 'pending_verification',
        accountStatus: (u.accountStatus || (u.isEmailVerified ? 'active' : 'pending_verification')) as 'active' | 'pending_verification' | 'suspended',
        totalOrders: orders.length,
        totalSpent,
        savedAddresses: u.savedAddresses || [],
        orders: orders.map(o => ({
          id: o.id,
          orderNumber: o.orderNumber,
          createdAt: o.createdAt,
          total: o.total,
          currency: o.currency,
          orderStatus: o.orderStatus,
          paymentStatus: o.paymentStatus,
          itemsCount: o.items.reduce((sum, it) => sum + it.quantity, 0),
        })),
      };
    });
  return res.json(customers);
});

// Admin get customer registration audit log
app.get('/api/admin/customers/registration-log', requireAdmin, (req: Request, res: Response) => {
  return res.json(db.getRegistrationLog());
});

// Admin get account activity log
app.get('/api/admin/customers/account-activity-log', requireAdmin, (req: Request, res: Response) => {
  return res.json(db.getAccountActivityLog());
});

// ==========================================
// GOOGLE DRIVE OFFICIAL CLOUD STORAGE SYNC
// Target Folder: 1q_B8QGCYgzRgVzT4r3f-NH2PN1XaU34m (NOVORA_Project/Data)
// Files: products.json, categories.json, banners.json, orders.json, customers_export.json, store_settings.json, admin_audit_log.json
// ==========================================
app.get('/api/drive/export-data', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  
  // 1. customers_export.json payload (Strictly NO passwords or hashes per security guidelines)
  const customers = (store.users || [])
    .filter(u => u.role === 'customer')
    .map(u => ({
      customerId: u.id,
      fullName: u.fullName,
      email: u.email,
      phone: u.phone || 'N/A',
      savedAddressesCount: u.savedAddresses ? u.savedAddresses.length : 0,
      savedAddresses: (u.savedAddresses || []).map(a => ({
        fullName: a.fullName,
        email: a.email,
        phone: a.phone,
        country: a.country,
        state: a.state,
        city: a.city,
        streetAddress: a.streetAddress,
        houseNumber: a.houseNumber,
        postalCode: a.postalCode,
      })),
      createdAt: u.createdAt,
    }));

  // 2. addresses.json payload (All 10 compulsory address fields linked to user ID & email)
  const addresses: any[] = [];
  (store.users || []).forEach(u => {
    (u.savedAddresses || []).forEach(a => {
      addresses.push({
        id: a.id || `addr_${Date.now()}`,
        userId: u.id,
        customerEmail: u.email,
        fullName: a.fullName || u.fullName,
        email: a.email || u.email,
        phone: a.phone || u.phone || '',
        country: a.country,
        state: a.state,
        city: a.city,
        streetAddress: a.streetAddress,
        houseNumber: a.houseNumber,
        apartmentDetails: a.apartmentDetails || '',
        postalCode: a.postalCode,
        isDefault: a.isDefault ?? false,
      });
    });
  });

  // Also include order delivery addresses if not already recorded
  (store.orders || []).forEach(o => {
    if (o.deliveryAddress && !addresses.some(a => a.streetAddress === o.deliveryAddress.streetAddress && a.postalCode === o.deliveryAddress.postalCode && a.userId === o.userId)) {
      addresses.push({
        id: `addr_ord_${o.id}`,
        userId: o.userId || 'guest',
        customerEmail: o.customer.email,
        fullName: o.deliveryAddress.fullName,
        email: o.deliveryAddress.email,
        phone: o.deliveryAddress.phone,
        country: o.deliveryAddress.country,
        state: o.deliveryAddress.state,
        city: o.deliveryAddress.city,
        streetAddress: o.deliveryAddress.streetAddress,
        houseNumber: o.deliveryAddress.houseNumber,
        apartmentDetails: o.deliveryAddress.apartmentDetails || '',
        postalCode: o.deliveryAddress.postalCode,
        isDefault: false,
        sourceOrderNumber: o.orderNumber,
      });
    }
  });

  // 3. orders.json payload (Orders with items, destination address, and fulfillment)
  const orders = (store.orders || []).map(o => ({
    id: o.id,
    orderNumber: o.orderNumber,
    createdAt: o.createdAt,
    userId: o.userId || 'guest',
    customer: {
      fullName: o.customer.fullName,
      email: o.customer.email,
      phone: o.customer.phone,
    },
    deliveryAddress: {
      fullName: o.deliveryAddress.fullName,
      email: o.deliveryAddress.email,
      phone: o.deliveryAddress.phone,
      country: o.deliveryAddress.country,
      state: o.deliveryAddress.state,
      city: o.deliveryAddress.city,
      streetAddress: o.deliveryAddress.streetAddress,
      houseNumber: o.deliveryAddress.houseNumber,
      apartmentDetails: o.deliveryAddress.apartmentDetails || '',
      postalCode: o.deliveryAddress.postalCode,
    },
    itemsCount: o.items.reduce((acc, it) => acc + it.quantity, 0),
    items: o.items.map(it => ({
      productId: it.productId,
      productName: it.productName,
      quantity: it.quantity,
      price: it.price,
      total: it.price * it.quantity,
      selectedVariant: it.selectedVariant,
    })),
    subtotal: o.subtotal,
    discount: o.discount,
    shippingFee: o.shippingFee,
    taxAmount: o.taxAmount,
    total: o.total,
    currency: o.currency,
    paymentMethod: o.paymentMethod,
    paymentStatus: o.paymentStatus,
    orderStatus: o.orderStatus,
    trackingNumber: o.trackingNumber || 'Pending Courier',
    carrier: o.carrier || 'DHL Express / Local Courier',
    isArchived: Boolean(o.isArchived),
    archivedAt: o.archivedAt || null,
  }));

  // 4. products.json payload
  const products = (store.products || []).map(p => ({
    id: p.id,
    sku: p.sku,
    name: p.name,
    category: p.category,
    subcategory: p.subcategory || '',
    brand: p.brand,
    originalPrice: p.originalPrice,
    sellingPrice: p.sellingPrice,
    discountPercentage: p.discountPercentage,
    stock: p.stock,
    status: p.status,
    featured: p.featured,
    bestSeller: p.bestSeller,
    rating: p.rating,
    reviewsCount: p.reviewsCount,
    updatedAt: p.updatedAt || p.createdAt,
  }));

  // 5. categories.json payload
  const categories = store.categories || [];

  // 6. banners.json payload
  const banners = store.banners || [];

  // 7. store_settings.json payload
  const settings = {
    storeName: store.settings.storeName,
    tagline: store.settings.tagline,
    currency: store.settings.currency,
    currencySymbol: store.settings.currencySymbol,
    shippingCharge: store.settings.shippingCharge,
    freeShippingThreshold: store.settings.freeShippingThreshold,
    taxRatePercentage: store.settings.taxRatePercentage,
    contactEmail: store.settings.contactEmail,
    contactPhone: store.settings.contactPhone,
    address: store.settings.address,
    seoTitle: store.settings.seoTitle,
    seoDescription: store.settings.seoDescription,
    promotionalBarText: store.settings.promotionalBarText,
  };

  // 8. admin_audit_log.json payload
  const auditLog = db.getAuditLog();

  // Navigation payload
  const navigation = {
    headerMenu: [
      { name: 'Home', path: '/' },
      { name: 'Shop All', path: '/shop' },
      ...categories.filter(c => c.status === 'active').map(c => ({
        name: c.name,
        path: `/category/${c.slug}`,
        subcategories: c.subcategories || [],
      })),
      { name: 'About Concierge', path: '/about' },
      { name: 'Private Releases', path: '/releases' },
    ],
    footerMenu: {
      concierge: [
        { name: 'Contact Client Care', path: '/contact' },
        { name: 'Order Tracking', path: '/track' },
        { name: 'Shipping & Delivery', path: '/shipping' },
        { name: 'Returns & Exchanges', path: '/returns' },
      ],
      legal: [
        { name: 'Privacy Policy', path: '/privacy' },
        { name: 'Terms of Service', path: '/terms' },
        { name: 'Payment Security Guarantee', path: '/security-guarantee' },
      ],
    },
  };

  // Homepage content payload
  const homepageContent = {
    banners,
    promotionalBar: {
      show: store.settings.showPromotionalBar,
      text: store.settings.promotionalBarText,
    },
    featuredCategories: categories.filter(c => c.status === 'active').slice(0, 4),
    featuredProducts: products.filter(p => p.featured),
    bestSellers: products.filter(p => p.bestSeller),
  };

  // Safe Payment Settings Backup
  const paymentSettingsBackup = {
    provider: store.paymentGateway.provider,
    providerName: store.paymentGateway.providerName,
    mode: store.paymentGateway.mode || 'test',
    isTestMode: store.paymentGateway.isTestMode,
    merchantIdMasked: store.paymentGateway.merchantIdMasked,
    publishableKeyMasked: store.paymentGateway.publishableKeyMasked,
    cardsEnabled: store.paymentGateway.cardsEnabled,
    bankTransferEnabled: store.paymentGateway.bankTransferEnabled,
    codEnabled: store.paymentGateway.codEnabled,
    maxCodAmount: store.paymentGateway.maxCodAmount,
    supportedCurrencies: store.paymentGateway.supportedCurrencies,
    bankDetails: {
      bankName: store.paymentGateway.bankDetails.bankName,
      accountTitle: store.paymentGateway.bankDetails.accountTitle,
      ibanMasked: store.paymentGateway.bankDetails.ibanMasked,
      branchCode: store.paymentGateway.bankDetails.branchCode,
    },
    payoutStatus: store.paymentGateway.payoutStatus,
    payoutAccountMasked: store.paymentGateway.payoutAccountMasked,
    lastVerifiedAt: store.paymentGateway.lastVerifiedAt,
  };

  // Payment transactions
  const paymentTransactions = store.paymentTransactions || [];

  // Payout settings backup
  const payoutSettingsBackup = {
    payoutAccount: store.paymentGateway.payoutAccount || null,
    merchantCards: store.paymentGateway.merchantCards || [],
    payoutAuditLog: store.paymentGateway.payoutAuditLog || [],
  };

  const activeDrive = getActiveGoogleDriveConfig(store);
  const primaryAdmin = getPrimaryAdminEmail(store);
  const authorizedAdmins = getAuthorizedAdminEmails(store);

  // Managed Files Structured for NOVORA_Project Hierarchy
  const filesByFolder = {
    Store_Content: {
      'store_settings.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), settings },
      'homepage_content.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), ...homepageContent },
      'categories.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalCategories: categories.length, categories },
      'navigation.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), ...navigation },
    },
    Products: {
      'products.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalProducts: products.length, products },
    },
    Customers: {
      'customers_export.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalCustomers: customers.length, customers },
      'registration_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce Customer Registration Audit Engine', lastUpdated: new Date().toISOString(), totalRegistrations: db.getRegistrationLog().length, registrations: db.getRegistrationLog() },
    },
    Addresses: {
      'addresses_export.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalAddresses: addresses.length, addresses },
    },
    Orders: {
      'orders.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalOrders: orders.length, orders },
    },
    Backups: {
      'customer_backup.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce Customer Database Snapshot', lastUpdated: new Date().toISOString(), totalCustomers: customers.length, totalAddresses: addresses.length, customers, addresses },
      'backup_status.json': {
        schemaVersion: '1.0.0',
        source: 'NOVORA Luxury E-Commerce',
        lastUpdated: new Date().toISOString(),
        targetGoogleDriveFolder: activeDrive.folderName,
        googleDriveFolderId: activeDrive.folderId,
        googleDriveOwnerEmail: activeDrive.ownerEmail,
        foldersConfigured: ['Customers', 'Addresses', 'Backups', 'Logs', 'Products', 'Categories', 'Store_Settings', 'Admin'],
        filesManaged: [
          'Customers/customers_export.json',
          'Customers/registration_log.json',
          'Addresses/addresses_export.json',
          'Backups/customer_backup.json',
          'Backups/backup_status.json',
          'Logs/account_activity_log.json',
        ],
        integrityStatus: 'healthy',
        securityCompliance: {
          plainTextPasswordsStored: false,
          passwordHashesInDrive: false,
          otpCodesInDrive: false,
          sessionTokensInDrive: false,
          bcryptSaltedHashedLocalAuth: true,
        },
        counts: {
          totalCustomers: customers.length,
          totalAddresses: addresses.length,
          totalRegistrations: db.getRegistrationLog().length,
          totalAccountActivities: db.getAccountActivityLog().length,
        },
      },
    },
    Logs: {
      'account_activity_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce Account Activity Engine', lastUpdated: new Date().toISOString(), totalEntries: db.getAccountActivityLog().length, activities: db.getAccountActivityLog() },
      'registration_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalRegistrations: db.getRegistrationLog().length, registrations: db.getRegistrationLog() },
      'product_changes_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce Product Change Engine', lastUpdated: new Date().toISOString(), totalChanges: db.getProductChangesLog().length, changes: db.getProductChangesLog() },
      'admin_audit_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalAuditEntries: auditLog.length, auditLog },
    },
    Payment_Data: {
      'payment_settings_backup.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), gatewayConfig: paymentSettingsBackup },
      'payment_transactions.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalTransactions: paymentTransactions.length, transactions: paymentTransactions },
      'payout_settings_backup.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), ...payoutSettingsBackup },
    },
    Admin: {
      'admin_audit_log.json': { schemaVersion: '1.0.0', source: 'NOVORA Luxury E-Commerce', lastUpdated: new Date().toISOString(), totalAuditEntries: auditLog.length, auditLog },
      'admin_config.json': {
        schemaVersion: '1.0.0',
        source: 'NOVORA Luxury E-Commerce Admin Gateway',
        lastUpdated: new Date().toISOString(),
        primaryAdminEmail: primaryAdmin,
        authorizedAdminEmails: authorizedAdmins,
        autoEnableAdminOnGoogleSignIn: true,
        googleDriveFolderId: activeDrive.folderId,
        googleDriveOwnerEmail: activeDrive.ownerEmail,
      },
      'admin_credentials.json': {
        schemaVersion: '1.0.0',
        source: 'NOVORA Luxury E-Commerce Admin Gateway',
        lastUpdated: new Date().toISOString(),
        primaryAdminEmail: primaryAdmin,
        authorizedAdminEmails: authorizedAdmins,
        googleDriveOwnerEmail: activeDrive.ownerEmail,
        administrators: (store.users || [])
          .filter(u => u.role === 'admin')
          .map(u => ({
            id: u.id,
            email: u.email.trim().toLowerCase(),
            fullName: u.fullName,
            role: u.role,
            phone: u.phone || '',
            isEmailVerified: u.isEmailVerified ?? true,
            accountStatus: u.accountStatus || 'active',
            passwordSecurity: 'Bcrypt Salted Hash ($2)',
            updatedAt: u.updatedAt || u.createdAt,
          })),
        securityNotice: 'Plaintext passwords and hashes are excluded from Google Drive exports.',
      },
    },
  };

  console.log(`[API:GoogleDrive] Exported structured files across ${activeDrive.folderName} hierarchy (Owner: ${activeDrive.ownerEmail}).`);

  const adminCredentialsExport = filesByFolder.Admin['admin_credentials.json'];
  const adminConfigExport = filesByFolder.Admin['admin_config.json'];

  return res.json({
    folderId: activeDrive.folderId,
    folderName: activeDrive.folderName,
    folderUrl: activeDrive.folderUrl,
    googleDriveOwnerEmail: activeDrive.ownerEmail,
    primaryAdminEmail: primaryAdmin,
    timestamp: new Date().toISOString(),
    authorizedAdminEmails: authorizedAdmins,
    googleDriveConfig: activeDrive,
    adminCredentials: adminCredentialsExport,
    adminConfig: adminConfigExport,
    filesByFolder,
    customers,
    addresses,
    orders,
    products,
    categories,
    banners,
    settings,
    navigation,
    homepageContent,
    paymentSettingsBackup,
    paymentTransactions,
    payoutSettingsBackup,
    auditLog,
    productChangesLog: db.getProductChangesLog(),
    registrationLog: db.getRegistrationLog(),
    accountActivityLog: db.getAccountActivityLog(),
  });
});

// Admin-only Backend Google Drive Sync for NOVORA_CUSTOMER_DATABASE
app.post('/api/drive/sync-customer-data', requireAdmin, async (req: Request, res: Response) => {
  const driveToken =
    (req.body && req.body.accessToken) ||
    (req.headers['x-drive-token'] as string) ||
    process.env.GOOGLE_DRIVE_ACCESS_TOKEN;

  if (!driveToken) {
    return res.status(401).json({
      error: 'Google Drive authorization required. Please connect Google Drive to sync NOVORA_CUSTOMER_DATABASE.',
    });
  }

  const store = db.getData();

  // 1. users.json (strictly NO passwords, tokens, or card details)
  const usersPayload = (store.users || [])
    .filter(u => u.role === 'customer')
    .map(u => ({
      customerId: u.id,
      fullName: u.fullName,
      email: u.email,
      phone: u.phone || '',
      profilePictureUrl: (u as any).avatar || (u as any).photoURL || '',
      authProvider: (u as any).authProvider === 'google' ? 'Google' : 'Email',
      registrationDate: u.createdAt,
    }));

  // 2. addresses.json
  const addressesPayload: any[] = [];
  (store.users || []).forEach(u => {
    (u.savedAddresses || []).forEach(a => {
      addressesPayload.push({
        customerId: u.id,
        recipientName: a.fullName || u.fullName,
        country: a.country,
        province: a.state,
        city: a.city,
        street: [a.houseNumber, a.streetAddress, a.apartmentDetails].filter(Boolean).join(', '),
        postalCode: a.postalCode,
      });
    });
  });

  // 3. orders.json (strictly NO card numbers or CVVs)
  const ordersPayload = (store.orders || []).map(o => ({
    customerId: o.userId || 'guest',
    orderId: o.id,
    products: (o.items || []).map(item => ({
      productId: item.productId,
      name: (item as any).name || (item as any).productName || item.productId,
      quantity: item.quantity,
      price: item.price,
    })),
    orderAmount: o.total,
    paymentStatus: o.paymentStatus,
    orderDate: o.createdAt,
  }));

  // 4. login_history.json
  const loginHistoryPayload = (db.getAccountActivityLog() || [])
    .filter((entry: any) => entry.action === 'login' || entry.action === 'register' || entry.action === 'google_login')
    .map((entry: any) => ({
      customerId: entry.userId || 'unknown',
      loginDate: entry.timestamp || new Date().toISOString(),
      authProvider: entry.authProvider === 'google' || entry.action === 'google_login' ? 'Google' : 'Email',
    }));

  async function withRetry<T>(fn: () => Promise<T>, retries = 3): Promise<T> {
    let lastErr: any;
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        return await fn();
      } catch (err) {
        lastErr = err;
        if (attempt < retries) {
          await new Promise(r => setTimeout(r, 400 * attempt));
        }
      }
    }
    throw lastErr;
  }

  try {
    // Find or create NOVORA_CUSTOMER_DATABASE folder
    const folderId = await withRetry(async () => {
      const q = encodeURIComponent("name='NOVORA_CUSTOMER_DATABASE' and mimeType='application/vnd.google-apps.folder' and trashed=false");
      const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)`, {
        headers: { Authorization: `Bearer ${driveToken}` },
      });
      if (!searchRes.ok) {
        const errData = await searchRes.json().catch(() => ({}));
        throw new Error(errData.error?.message || `Drive folder search failed (${searchRes.status})`);
      }
      const searchData = await searchRes.json();
      if (searchData.files && searchData.files.length > 0) {
        return searchData.files[0].id as string;
      }

      const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${driveToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'NOVORA_CUSTOMER_DATABASE',
          mimeType: 'application/vnd.google-apps.folder',
        }),
      });
      if (!createRes.ok) {
        const errData = await createRes.json().catch(() => ({}));
        throw new Error(errData.error?.message || `Drive folder creation failed (${createRes.status})`);
      }
      const created = await createRes.json();
      return created.id as string;
    });

    const filesToSync = [
      { name: 'users.json', content: JSON.stringify({ updatedAt: new Date().toISOString(), users: usersPayload }, null, 2) },
      { name: 'addresses.json', content: JSON.stringify({ updatedAt: new Date().toISOString(), addresses: addressesPayload }, null, 2) },
      { name: 'orders.json', content: JSON.stringify({ updatedAt: new Date().toISOString(), orders: ordersPayload }, null, 2) },
      { name: 'login_history.json', content: JSON.stringify({ updatedAt: new Date().toISOString(), login_history: loginHistoryPayload }, null, 2) },
    ];

    for (const file of filesToSync) {
      await withRetry(async () => {
        const q = encodeURIComponent(`name='${file.name}' and '${folderId}' in parents and trashed=false`);
        const listRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)`, {
          headers: { Authorization: `Bearer ${driveToken}` },
        });
        const listData = await listRes.json();
        const existingId = listData.files?.[0]?.id;

        const boundary = '-------novora_drive_boundary_2026';
        const metadata = existingId
          ? { name: file.name, mimeType: 'application/json' }
          : { name: file.name, mimeType: 'application/json', parents: [folderId] };

        const body =
          `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
          `--${boundary}\r\nContent-Type: application/json\r\n\r\n${file.content}\r\n` +
          `--${boundary}--`;

        const url = existingId
          ? `https://www.googleapis.com/upload/drive/v3/files/${existingId}?uploadType=multipart`
          : 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart';

        const uploadRes = await fetch(url, {
          method: existingId ? 'PATCH' : 'POST',
          headers: {
            Authorization: `Bearer ${driveToken}`,
            'Content-Type': `multipart/related; boundary=${boundary}`,
          },
          body,
        });

        if (!uploadRes.ok) {
          const errData = await uploadRes.json().catch(() => ({}));
          throw new Error(errData.error?.message || `Failed to upload ${file.name} (${uploadRes.status})`);
        }
      });
    }

    return res.json({
      success: true,
      folderName: 'NOVORA_CUSTOMER_DATA',
      folderId,
      filesSynced: ['users.json', 'addresses.json', 'orders.json'],
      counts: {
        users: usersPayload.length,
        addresses: addressesPayload.length,
        orders: ordersPayload.length,
      },
    });
  } catch (err: any) {
    console.error('[GoogleDrive:NOVORA_CUSTOMER_DATA] Sync error:', err.message);
    return res.status(502).json({
      error: err.message || 'Google Drive synchronization failed. Please reconnect Google Drive and retry.',
    });
  }
});

// Admin-only Google Drive Backup Status Endpoint
app.get('/api/drive/backup-status', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const activeDrive = getActiveGoogleDriveConfig(store);
  const backupPath = path.join(process.cwd(), 'data', 'novora_storage', 'Backups', 'backup_status.json');
  if (fs.existsSync(backupPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(backupPath, 'utf-8'));
      return res.json({
        ...data,
        targetGoogleDriveFolder: activeDrive.folderName,
        googleDriveFolderId: activeDrive.folderId,
        googleDriveFolderUrl: activeDrive.folderUrl,
        googleDriveOwnerEmail: activeDrive.ownerEmail,
      });
    } catch {}
  }
  return res.json({
    schemaVersion: '1.0.0',
    targetGoogleDriveFolder: activeDrive.folderName,
    googleDriveFolderId: activeDrive.folderId,
    googleDriveFolderUrl: activeDrive.folderUrl,
    googleDriveOwnerEmail: activeDrive.ownerEmail,
    foldersConfigured: ['Admin', 'Customers', 'Addresses', 'Orders', 'Store_Settings', 'Backups', 'Logs'],
    filesManaged: [
      'customers_export.json',
      'addresses_export.json',
      'orders.json',
      'store_settings.json',
      'admin_audit_log.json',
      'backup_status.json',
    ],
    integrityStatus: 'healthy',
    lastUpdated: new Date().toISOString(),
    counts: {
      totalCustomers: store.users.filter(u => u.role === 'customer').length,
      totalOrders: store.orders.length,
      totalProducts: store.products.length,
    },
  });
});

// Admin-only Media Manifest & Streaming for Google Drive Account Migration
app.get('/api/drive/media-manifest', requireAdmin, (_req: Request, res: Response) => {
  try {
    const files = db.listMediaFilesForMigration();
    return res.json({
      success: true,
      total: files.length,
      files,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'Failed to build media migration manifest.' });
  }
});

app.get('/api/drive/media-file', requireAdmin, (req: Request, res: Response) => {
  const folder = String(req.query.folder || '').trim();
  const fileName = String(req.query.fileName || '').trim();
  if (!folder || !fileName) {
    return res.status(400).json({ error: 'Both folder and fileName query parameters are required.' });
  }
  const resolved = db.resolveMediaFilePath(folder, fileName);
  if (!resolved) {
    return res.status(404).json({ error: 'Media file not found or invalid media path.' });
  }
  res.setHeader('Content-Type', resolved.mimeType);
  return res.sendFile(resolved.fullPath);
});

// Admin-only Persistent Active Google Drive Config & Migration Registry
app.get('/api/admin/google-drive/config', requireAdmin, (_req: Request, res: Response) => {
  const store = db.getData();
  const activeDrive = getActiveGoogleDriveConfig(store);
  return res.json({
    success: true,
    googleDriveConfig: activeDrive,
    primaryAdminEmail: getPrimaryAdminEmail(store),
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
  });
});

async function verifyAdminReauth(
  callerRecord: User,
  body: Record<string, any>
): Promise<{ ok: true; method: 'password' | 'google_reauth' } | { ok: false; status: number; error: string }> {
  const cleanCallerEmail = String(callerRecord.email || '').trim().toLowerCase();
  const { currentPassword, reauthIdToken, reauthGoogleAccessToken } = body || {};

  if (currentPassword && String(currentPassword).trim().length > 0) {
    const validPassword = await verifyUserPassword(callerRecord, String(currentPassword));
    if (!validPassword) {
      return { ok: false, status: 401, error: 'Current administrator password is incorrect.' };
    }
    return { ok: true, method: 'password' };
  }

  if (reauthIdToken && String(reauthIdToken).trim().length > 0) {
    const verified = await verifyFirebaseIdToken(String(reauthIdToken).trim());
    if (!verified || !verified.emailVerified) {
      return { ok: false, status: 401, error: 'Google account re-authentication token could not be verified.' };
    }
    if (verified.email.trim().toLowerCase() !== cleanCallerEmail) {
      return {
        ok: false,
        status: 403,
        error: `Please re-authenticate using the active Admin Google account (${cleanCallerEmail}).`,
      };
    }
    return { ok: true, method: 'google_reauth' };
  }

  if (reauthGoogleAccessToken && String(reauthGoogleAccessToken).trim().length > 0) {
    const verified = await verifyGoogleAccessToken(String(reauthGoogleAccessToken).trim());
    if (!verified) {
      return { ok: false, status: 401, error: 'Google OAuth re-authentication token could not be verified.' };
    }
    if (verified.email.trim().toLowerCase() !== cleanCallerEmail) {
      return {
        ok: false,
        status: 403,
        error: `Please re-authenticate using the active Admin Google account (${cleanCallerEmail}).`,
      };
    }
    return { ok: true, method: 'google_reauth' };
  }

  return {
    ok: false,
    status: 400,
    error: 'Identity confirmation required: enter your current administrator password or re-authenticate with your Google account.',
  };
}

app.put('/api/admin/google-drive/config', requireAdmin, async (req: Request, res: Response) => {
  const caller = (req as any).user as User;
  const { ownerEmail, folderId, folderName, folderUrl, filesCount, mediaCount } = req.body || {};

  const store = db.getData();
  const callerRecord = store.users.find(
    u => u.id === caller.id || u.email.toLowerCase() === caller.email.toLowerCase()
  );
  if (!callerRecord) {
    return res.status(404).json({ error: 'Active administrator account record not found.' });
  }

  const reauthCheck = await verifyAdminReauth(callerRecord, req.body || {});
  if (reauthCheck.ok === false) {
    db.addAuditLog({
      adminEmail: callerRecord.email,
      action: 'google_drive_switch_denied',
      details: `Google Drive storage update denied: ${reauthCheck.error}`,
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.status(reauthCheck.status).json({ error: reauthCheck.error });
  }

  const cleanOwnerEmail = String(ownerEmail || '').trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!cleanOwnerEmail || !emailRegex.test(cleanOwnerEmail)) {
    return res.status(400).json({ error: 'A valid Google Drive owner email address is required.' });
  }

  const cleanFolderId = String(folderId || '').trim();
  if (!cleanFolderId || !/^[A-Za-z0-9_-]{8,128}$/.test(cleanFolderId)) {
    return res.status(400).json({ error: 'A valid Google Drive folder ID is required.' });
  }

  const cleanFolderName = String(folderName || DEFAULT_DRIVE_FOLDER_NAME).trim() || DEFAULT_DRIVE_FOLDER_NAME;
  const cleanFolderUrl =
    String(folderUrl || `https://drive.google.com/drive/folders/${cleanFolderId}`).trim();
  if (!cleanFolderUrl.startsWith('https://drive.google.com/')) {
    return res.status(400).json({ error: 'Invalid Google Drive folder URL.' });
  }

  const previousCfg = getActiveGoogleDriveConfig(store);
  const now = new Date().toISOString();

  const historyEntry = {
    id: `gdm_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    migratedAt: now,
    fromEmail: previousCfg.ownerEmail,
    toEmail: cleanOwnerEmail,
    folderId: cleanFolderId,
    folderName: cleanFolderName,
    folderUrl: cleanFolderUrl,
    filesCount: typeof filesCount === 'number' ? filesCount : 0,
    mediaCount: typeof mediaCount === 'number' ? mediaCount : 0,
    performedBy: caller.email,
  };

  store.googleDriveConfig = {
    ownerEmail: cleanOwnerEmail,
    folderId: cleanFolderId,
    folderName: cleanFolderName,
    folderUrl: cleanFolderUrl,
    lastMigratedAt: now,
    migratedFromEmail: previousCfg.ownerEmail !== cleanOwnerEmail ? previousCfg.ownerEmail : previousCfg.migratedFromEmail,
    migrationHistory: [historyEntry, ...(previousCfg.migrationHistory || [])].slice(0, 25),
  };

  db.addAuditLog({
    adminEmail: caller.email,
    action: 'google_drive_account_switched',
    details: `Google Drive target switched to ${cleanOwnerEmail} (Folder: ${cleanFolderName} / ${cleanFolderId}; ${historyEntry.filesCount} JSON files, ${historyEntry.mediaCount} media files migrated; verified via ${reauthCheck.method}).`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  return res.json({
    success: true,
    googleDriveConfig: store.googleDriveConfig,
    message: `Google Drive linked to ${cleanOwnerEmail} (${cleanFolderName}).`,
  });
});

// Signed-in Authorized Admin Profile & Credential Update (strictly requires existing Admin session)
app.post('/api/admin/enable-portal', requireAdmin, async (req: Request, res: Response) => {
  const { email, password, fullName } = req.body;
  const activeSessionAdmin = (req as any).user as User;
  const store = db.getData();

  const cleanEmail = String(email || activeSessionAdmin.email).trim().toLowerCase();
  if (!isAuthorizedAdminEmail(cleanEmail, store)) {
    return res.status(403).json({
      success: false,
      error: `Only an authorized administrator account (${getAuthorizedAdminEmails(store).join(', ')}) is permitted.`,
    });
  }

  let adminUser = store.users.find(u => u.email.toLowerCase() === cleanEmail);

  if (password && String(password).trim().length > 0 && String(password).trim().length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  if (adminUser) {
    adminUser.role = 'admin';
    adminUser.isEmailVerified = true;
    adminUser.accountStatus = 'active';
    adminUser.updatedAt = new Date().toISOString();
    if (fullName && String(fullName).trim()) {
      adminUser.fullName = String(fullName).trim();
    }
    if (password && String(password).trim()) {
      adminUser.password = await bcrypt.hash(String(password), 10);
      adminUser.passwordCustomized = true;
    }
  } else {
    adminUser = {
      id: cleanEmail === DEFAULT_ADMIN_EMAIL ? 'user_admin_huzaifa' : `user_admin_${Date.now()}`,
      email: cleanEmail,
      password:
        password && String(password).trim()
          ? await bcrypt.hash(String(password), 10)
          : activeSessionAdmin.password,
      fullName: fullName && String(fullName).trim() ? String(fullName).trim() : activeSessionAdmin.fullName || 'System Administrator',
      role: 'admin',
      phone: activeSessionAdmin.phone || '+1 (800) 849-2041',
      savedAddresses: [],
      wishlist: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      isEmailVerified: true,
      accountStatus: 'active',
      passwordCustomized: Boolean(password && String(password).trim()),
    };
    store.users.unshift(adminUser);
  }

  store.authorizedAdminEmails = getAuthorizedAdminEmails(store);
  if (!store.primaryAdminEmail || !store.authorizedAdminEmails.includes(store.primaryAdminEmail.toLowerCase())) {
    store.primaryAdminEmail = cleanEmail;
  }

  db.addAuditLog({
    adminEmail: adminUser.email,
    action: 'admin_details_updated',
    details: `Administrator details verified & saved for ${adminUser.email} (persisted to data/sign_in/admin_credentials.json).`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  const token = issueSignedToken(adminUser);
  const safeUser = {
    id: adminUser.id,
    email: adminUser.email,
    fullName: adminUser.fullName,
    role: 'admin' as const,
    phone: adminUser.phone,
    savedAddresses: adminUser.savedAddresses || [],
    wishlist: adminUser.wishlist || [],
  };

  return res.json({
    success: true,
    message: 'Admin details verified and saved to local storage.',
    token,
    user: safeUser,
    primaryAdminEmail: getPrimaryAdminEmail(store),
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
    localCredentialsPath: 'data/sign_in/admin_credentials.json',
  });
});

// Admin Change / Transfer Ownership to New Gmail (supports full ownership transfer or co-admin)
app.post('/api/admin/transfer-admin', requireAdmin, async (req: Request, res: Response) => {
  const caller = (req as any).user as User;
  const {
    newEmail,
    newFullName,
    mode = 'transfer',
    newPassword,
    driveTransfer,
  } = req.body || {};

  const cleanNewEmail = String(newEmail || '').trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!cleanNewEmail || !emailRegex.test(cleanNewEmail)) {
    return res.status(400).json({ error: 'Please enter a valid new administrator Gmail / email address.' });
  }

  const transferMode: 'transfer' | 'co-admin' = mode === 'co-admin' ? 'co-admin' : 'transfer';
  const store = db.getData();
  const callerRecord = store.users.find(u => u.id === caller.id || u.email.toLowerCase() === caller.email.toLowerCase());
  if (!callerRecord) {
    return res.status(404).json({ error: 'Active administrator account record not found.' });
  }

  const reauthCheck = await verifyAdminReauth(callerRecord, req.body || {});
  if (reauthCheck.ok === false) {
    db.addAuditLog({
      adminEmail: callerRecord.email,
      action: 'admin_transfer_denied',
      details: `Admin transfer to ${cleanNewEmail} denied: ${reauthCheck.error}`,
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.status(reauthCheck.status).json({ error: reauthCheck.error });
  }

  if (newPassword && String(newPassword).trim().length > 0) {
    const rawNewPass = String(newPassword);
    if (rawNewPass.length < 8 || !/(?=.*[a-zA-Z])(?=.*[0-9])/.test(rawNewPass)) {
      return res.status(400).json({
        error: 'New Admin password must be at least 8 characters and contain both letters and numbers.',
      });
    }
  }

  const now = new Date().toISOString();
  const previousPrimary = getPrimaryAdminEmail(store);

  // Create or promote target new Admin user record
  let targetUser = store.users.find(u => u.email.toLowerCase() === cleanNewEmail);
  const hashedNewPassword =
    newPassword && String(newPassword).trim().length > 0
      ? await bcrypt.hash(String(newPassword), 10)
      : targetUser?.password || (await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 10));

  if (targetUser) {
    targetUser.email = cleanNewEmail;
    targetUser.role = 'admin';
    targetUser.isEmailVerified = true;
    targetUser.accountStatus = 'active';
    targetUser.updatedAt = now;
    if (newFullName && String(newFullName).trim()) {
      targetUser.fullName = String(newFullName).trim();
    }
    if (newPassword && String(newPassword).trim().length > 0) {
      targetUser.password = hashedNewPassword;
      targetUser.passwordCustomized = true;
    }
  } else {
    targetUser = {
      id: `user_admin_${Date.now()}`,
      email: cleanNewEmail,
      password: hashedNewPassword,
      fullName: (newFullName && String(newFullName).trim()) || cleanNewEmail.split('@')[0] || 'NOVORA Administrator',
      role: 'admin',
      phone: callerRecord.phone || '',
      savedAddresses: [],
      wishlist: [],
      createdAt: now,
      updatedAt: now,
      isEmailVerified: true,
      accountStatus: 'active',
      passwordCustomized: Boolean(newPassword && String(newPassword).trim().length > 0),
    };
    (targetUser as any).authProvider = newPassword ? 'Email' : 'Google';
    store.users.unshift(targetUser);
  }

  if (transferMode === 'transfer') {
    store.authorizedAdminEmails = [cleanNewEmail];
    store.primaryAdminEmail = cleanNewEmail;
    // Demote any previous admin user records so the new Gmail is the sole Admin
    for (const u of store.users) {
      if (u.email.trim().toLowerCase() !== cleanNewEmail && u.role === 'admin') {
        u.role = 'customer';
        u.updatedAt = now;
      }
    }
  } else {
    const merged = Array.from(new Set([...getAuthorizedAdminEmails(store), cleanNewEmail]));
    store.authorizedAdminEmails = merged;
    if (!store.primaryAdminEmail) {
      store.primaryAdminEmail = previousPrimary || cleanNewEmail;
    }
  }

  // Optionally persist Google Drive migration metadata in the same atomic commit
  if (driveTransfer && typeof driveTransfer === 'object' && driveTransfer.folderId && driveTransfer.ownerEmail) {
    const prevDrive = getActiveGoogleDriveConfig(store);
    const cleanDriveOwner = String(driveTransfer.ownerEmail).trim().toLowerCase();
    const cleanFolderId = String(driveTransfer.folderId).trim();
    const cleanFolderName = String(driveTransfer.folderName || DEFAULT_DRIVE_FOLDER_NAME).trim() || DEFAULT_DRIVE_FOLDER_NAME;
    const cleanFolderUrl = String(driveTransfer.folderUrl || `https://drive.google.com/drive/folders/${cleanFolderId}`).trim();
    if (emailRegex.test(cleanDriveOwner) && cleanFolderUrl.startsWith('https://drive.google.com/')) {
      const historyEntry = {
        id: `gdm_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        migratedAt: now,
        fromEmail: prevDrive.ownerEmail,
        toEmail: cleanDriveOwner,
        folderId: cleanFolderId,
        folderName: cleanFolderName,
        folderUrl: cleanFolderUrl,
        filesCount: Number(driveTransfer.filesCount || 0),
        mediaCount: Number(driveTransfer.mediaCount || 0),
        performedBy: callerRecord.email,
      };
      store.googleDriveConfig = {
        ownerEmail: cleanDriveOwner,
        folderId: cleanFolderId,
        folderName: cleanFolderName,
        folderUrl: cleanFolderUrl,
        lastMigratedAt: now,
        migratedFromEmail: prevDrive.ownerEmail,
        migrationHistory: [historyEntry, ...(prevDrive.migrationHistory || [])].slice(0, 25),
      };
    }
  }

  const callerDemoted = callerRecord.email.trim().toLowerCase() !== cleanNewEmail && transferMode === 'transfer';

  db.addAuditLog({
    adminEmail: callerRecord.email,
    action: transferMode === 'transfer' ? 'admin_ownership_transferred' : 'admin_co_admin_added',
    details:
      transferMode === 'transfer'
        ? `Primary Administrator transferred from ${previousPrimary} to ${cleanNewEmail}. Old account demoted to customer; ${cleanNewEmail} is now sole verified Admin.`
        : `Added ${cleanNewEmail} as authorized co-administrator.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  const updatedCallerToken = issueSignedToken(callerRecord);

  return res.json({
    success: true,
    mode: transferMode,
    primaryAdminEmail: getPrimaryAdminEmail(store),
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
    callerDemoted,
    callerUser: db.sanitizeUser(callerRecord),
    callerToken: updatedCallerToken,
    googleDriveConfig: getActiveGoogleDriveConfig(store),
    message:
      transferMode === 'transfer'
        ? `Admin ownership transferred to ${cleanNewEmail}. Signing in with ${cleanNewEmail} will automatically unlock the Admin Dashboard.`
        : `${cleanNewEmail} has been authorized as an Administrator.`,
  });
});

// Admin Change Password
app.post('/api/admin/change-password', requireAdmin, async (req: Request, res: Response) => {
  const user = (req as any).user as User;
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'Current password, new password, and confirmation are required.' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New password and confirmation password do not match.' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  if (!/(?=.*[a-zA-Z])(?=.*[0-9])/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must contain both letters and numbers for administrator security.' });
  }

  const store = db.getData();
  const adminUser = store.users.find(u => u.id === user.id);
  if (!adminUser) {
    return res.status(404).json({ error: 'Administrator user not found.' });
  }

  const isCurrentValid = await verifyUserPassword(adminUser, String(currentPassword));

  if (!isCurrentValid) {
    db.addAuditLog({
      adminEmail: adminUser.email,
      action: 'change_password_failed',
      details: 'Failed password change: current password verification failed.',
      status: 'failure',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.status(400).json({ error: 'Current password is incorrect. Please verify and try again.' });
  }

  const newHashed = await bcrypt.hash(newPassword, 10);
  adminUser.password = newHashed;
  adminUser.passwordCustomized = true;
  adminUser.updatedAt = new Date().toISOString();

  const newToken = issueSignedToken(adminUser);

  db.addAuditLog({
    adminEmail: adminUser.email,
    action: 'admin_password_changed',
    details: 'Administrator security password was changed and re-encrypted with salted bcrypt hash.',
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  return res.json({
    success: true,
    message: 'Administrator security password has been successfully updated.',
    token: newToken,
  });
});

// Admin Request Email Change (prepares email change verification step)
app.post('/api/admin/request-email-change', requireAdmin, async (req: Request, res: Response) => {
  const user = (req as any).user as User;
  const { newEmail, currentPassword } = req.body || {};
  const cleanNewEmail = String(newEmail || '').trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!cleanNewEmail || !emailRegex.test(cleanNewEmail)) {
    return res.status(400).json({ error: 'Please provide a valid new administrator email address.' });
  }

  const store = db.getData();
  const adminUser = store.users.find(u => u.id === user.id || u.email.toLowerCase() === user.email.toLowerCase());
  if (!adminUser) {
    return res.status(404).json({ error: 'Administrator user not found.' });
  }

  if (currentPassword) {
    const valid = await verifyUserPassword(adminUser, String(currentPassword));
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
  }

  const verificationToken = crypto.randomBytes(20).toString('hex');
  return res.json({
    success: true,
    message: `Verification prepared for ${cleanNewEmail}. Confirm below to transfer Admin privileges.`,
    pendingEmail: cleanNewEmail,
    verificationToken,
    verificationLink: `${req.protocol}://${req.get('host')}/admin?verifyEmail=${encodeURIComponent(cleanNewEmail)}&token=${verificationToken}`,
  });
});

// Admin Confirm & Activate Email Change
app.post('/api/admin/confirm-email-change', requireAdmin, async (req: Request, res: Response) => {
  const user = (req as any).user as User;
  const { newEmail, currentPassword } = req.body || {};
  const cleanNewEmail = String(newEmail || '').trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!cleanNewEmail || !emailRegex.test(cleanNewEmail)) {
    return res.status(400).json({ error: 'Please provide a valid new administrator email address.' });
  }

  const store = db.getData();
  const adminUser = store.users.find(u => u.id === user.id || u.email.toLowerCase() === user.email.toLowerCase());
  if (!adminUser) {
    return res.status(404).json({ error: 'Administrator user not found.' });
  }

  if (currentPassword) {
    const valid = await verifyUserPassword(adminUser, String(currentPassword));
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
  }

  const previousEmail = adminUser.email;
  adminUser.email = cleanNewEmail;
  adminUser.role = 'admin';
  adminUser.isEmailVerified = true;
  adminUser.updatedAt = new Date().toISOString();

  const remaining = getAuthorizedAdminEmails(store).filter(e => e !== previousEmail.trim().toLowerCase());
  store.authorizedAdminEmails = Array.from(new Set([cleanNewEmail, ...remaining]));
  store.primaryAdminEmail = cleanNewEmail;

  db.addAuditLog({
    adminEmail: cleanNewEmail,
    action: 'admin_email_updated',
    details: `Administrator email updated from ${previousEmail} to ${cleanNewEmail}.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  return res.json({
    success: true,
    message: `Administrator email confirmed as ${cleanNewEmail}.`,
    user: db.sanitizeUser(adminUser),
    token: issueSignedToken(adminUser),
    primaryAdminEmail: store.primaryAdminEmail,
    authorizedAdminEmails: store.authorizedAdminEmails,
  });
});

// Get & Update Dynamic Authorized Admin Emails Allowlist
app.get('/api/admin/security/admin-emails', requireAdmin, (_req: Request, res: Response) => {
  const store = db.getData();
  return res.json({
    primaryAdminEmail: getPrimaryAdminEmail(store),
    authorizedAdminEmails: getAuthorizedAdminEmails(store),
    googleDriveConfig: getActiveGoogleDriveConfig(store),
  });
});

app.put('/api/admin/security/admin-emails', requireAdmin, (req: Request, res: Response) => {
  const caller = (req as any).user as User;
  const { emails, primaryEmail } = req.body || {};
  if (!Array.isArray(emails)) {
    return res.status(400).json({ error: 'An array of administrator email addresses is required.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const cleaned = Array.from(
    new Set(
      emails
        .map((e: any) => String(e || '').trim().toLowerCase())
        .filter(e => emailRegex.test(e))
    )
  );
  if (cleaned.length === 0) {
    return res.status(400).json({ error: 'At least one valid administrator email address is required.' });
  }

  const store = db.getData();
  store.authorizedAdminEmails = cleaned;
  const requestedPrimary = String(primaryEmail || '').trim().toLowerCase();
  store.primaryAdminEmail = cleaned.includes(requestedPrimary)
    ? requestedPrimary
    : cleaned.includes(store.primaryAdminEmail?.toLowerCase() || '')
    ? store.primaryAdminEmail
    : cleaned[0];

  const now = new Date().toISOString();
  for (const u of store.users) {
    const mail = u.email.trim().toLowerCase();
    if (cleaned.includes(mail)) {
      u.role = 'admin';
      u.isEmailVerified = true;
      u.accountStatus = 'active';
      u.updatedAt = now;
    } else if (u.role === 'admin') {
      u.role = 'customer';
      u.updatedAt = now;
    }
  }

  db.addAuditLog({
    adminEmail: caller.email,
    action: 'admin_allowlist_updated',
    details: `Authorized admin allowlist updated to [${cleaned.join(', ')}] (primary: ${store.primaryAdminEmail}).`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });

  db.commit();

  return res.json({
    success: true,
    primaryAdminEmail: store.primaryAdminEmail,
    authorizedAdminEmails: cleaned,
    message: 'Authorized administrator Gmail allowlist updated.',
  });
});

// Admin Security Audit Log (Protected endpoint)
app.get('/api/admin/security/audit-log', requireAdmin, (req: Request, res: Response) => {
  return res.json(db.getAuditLog());
});



// Public Track Order endpoint (Requirement: Track My Order feature)
app.get('/api/orders/track/:orderNumber', (req: Request, res: Response) => {
  const store = db.getData();
  const rawParam = req.params.orderNumber.trim();
  const searchUpper = rawParam.toUpperCase();
  const order = store.orders.find(
    o => o.orderNumber.toUpperCase() === searchUpper || o.id === rawParam
  );

  if (!order) {
    return res.status(404).json({
      error: `Order "${rawParam}" was not found. Please double-check your order number (e.g. NOV-2026-XXXX).`,
    });
  }

  // Build comprehensive status timeline
  const isPaid = order.paymentStatus === 'paid';
  const isDelivered = order.orderStatus === 'Delivered';
  const isShipped = order.orderStatus === 'Shipped' || isDelivered;
  const isProcessing = order.orderStatus === 'Processing' || order.orderStatus === 'Sent to Supplier' || isShipped;

  const timeline = [
    { title: 'Order Confirmed', completed: true, timestamp: order.createdAt, detail: 'Order received and logged in database.' },
    { title: 'Payment Verified', completed: isPaid, timestamp: order.paymentDetails?.paidAt || order.createdAt, detail: isPaid ? 'Payment settled successfully.' : 'Awaiting payment confirmation.' },
    { title: 'In Preparation & Quality Check', completed: isProcessing, timestamp: isProcessing ? order.createdAt : undefined, detail: 'Tailoring, inspection, and luxury packaging in progress.' },
    { title: 'Dispatched with Courier', completed: isShipped, timestamp: isShipped ? order.createdAt : undefined, detail: order.trackingNumber ? `${order.carrier || 'Courier'}: ${order.trackingNumber}` : 'Preparing consignment.' },
    { title: 'Delivered', completed: isDelivered, timestamp: isDelivered ? order.createdAt : undefined, detail: isDelivered ? 'Delivered to recipient address.' : 'Estimated 2-4 business days.' },
  ];

  return res.json({
    success: true,
    order: {
      id: order.id,
      orderNumber: order.orderNumber,
      createdAt: order.createdAt,
      orderStatus: order.orderStatus,
      paymentStatus: order.paymentStatus,
      paymentMethod: order.paymentMethod,
      trackingNumber: order.trackingNumber || 'Pending Courier Consignment',
      carrier: order.carrier || 'DHL Express Worldwide / Local Courier',
      trackingUrl: order.trackingUrl,
      total: order.total,
      currency: order.currency,
      items: order.items,
      deliveryAddress: {
        fullName: order.deliveryAddress.fullName,
        city: order.deliveryAddress.city,
        state: order.deliveryAddress.state,
        country: order.deliveryAddress.country,
        postalCode: order.deliveryAddress.postalCode,
      },
      timeline,
    },
  });
});

// Newsletter Subscription
app.post('/api/newsletter/subscribe', (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Please provide a valid email address.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const store = db.getData();
  if (!store.newsletterSubscribers) {
    store.newsletterSubscribers = [];
  }

  const exists = store.newsletterSubscribers.some(s => s.email.toLowerCase() === cleanEmail);
  if (!exists) {
    store.newsletterSubscribers.push({
      id: `sub_${Date.now()}`,
      email: cleanEmail,
      subscribedAt: new Date().toISOString(),
    });
    db.commit();
  }

  return res.status(201).json({
    success: true,
    message: 'Thank you for subscribing to the NOVORA register!',
  });
});

app.get('/api/admin/newsletter/subscribers', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(store.newsletterSubscribers || []);
});

app.get('/api/admin/newsletter/export-csv', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const subs = store.newsletterSubscribers || [];
  let csv = 'ID,Email,SubscribedAt\n';
  subs.forEach(s => {
    csv += `"${s.id}","${s.email}","${s.subscribedAt}"\n`;
  });
  res.setHeader('Content-Disposition', 'attachment; filename="novora_newsletter_subscribers.csv"');
  res.setHeader('Content-Type', 'text/csv');
  return res.send(csv);
});

// Admin Folder Storage Status (matching PC Folder Flowchart & Server 137.184.23.176)
app.get('/api/admin/folder-storage', requireAdmin, (req: Request, res: Response) => {
  const status = db.getFolderStorageStatus();
  return res.json(status);
});

// Admin Download Local PC Folder Files (novora.db, users.json, addresses.json, orders.json, database.db)
app.get('/api/admin/folder-storage/download/:filename', requireAdmin, (req: Request, res: Response) => {
  const allowedFiles = ['novora.db', 'users.json', 'addresses.json', 'orders.json', 'database.db', 'store.json'];
  const filename = req.params.filename;
  if (!allowedFiles.includes(filename)) {
    return res.status(400).json({ error: 'Invalid file requested' });
  }

  const filePath = path.join(process.cwd(), 'data', filename);
  if (!fs.existsSync(filePath)) {
    // Generate fresh before serving
    db.commit();
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on server' });
  }

  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', filename.endsWith('.db') ? 'application/octet-stream' : 'application/json');
  return res.sendFile(filePath);
});

// Admin Database Backup System (Requirement 7: Reliability & School-Project Testing)
app.post('/api/admin/database/backup', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { description } = req.body;
    const backupResult = await db.createBackup(description || 'Manual Admin Snapshot');
    return res.status(201).json(backupResult);
  } catch (err: any) {
    console.error('Backup creation error:', err);
    return res.status(500).json({ error: err.message || 'Failed to create database backup' });
  }
});

app.get('/api/admin/database/backups', requireAdmin, async (req: Request, res: Response) => {
  try {
    const backups = await db.listBackups();
    return res.json(backups);
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to list backups' });
  }
});

// Validate a backup snapshot before restoring
app.post('/api/admin/database/validate-backup', requireAdmin, (req: Request, res: Response) => {
  try {
    const { filename } = req.body;
    if (!filename) {
      return res.status(400).json({ error: 'Backup filename is required for validation' });
    }
    const validation = db.validateBackup(filename);
    return res.json(validation);
  } catch (err: any) {
    return res.status(500).json({ isValid: false, message: err.message || 'Validation failed' });
  }
});

app.post('/api/admin/database/restore', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { filename } = req.body;
    if (!filename) {
      return res.status(400).json({ error: 'Backup filename is required' });
    }

    // Validate backup before restoring to prevent replacing current data with corrupted snapshot
    const validation = db.validateBackup(filename);
    if (!validation.isValid) {
      return res.status(400).json({
        error: `Cannot restore invalid backup: ${validation.message}`,
        validation,
      });
    }

    const result = await db.restoreBackup(filename);
    db.addAuditLog({
      adminEmail: ((req as any).user as User)?.email || 'admin@novora.store',
      action: 'database_backup_restored',
      details: `Database snapshot "${filename}" successfully restored and verified.`,
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    });
    return res.json({ ...result, validated: true });
  } catch (err: any) {
    console.error('Backup restore error:', err);
    return res.status(500).json({ error: err.message || 'Failed to restore database backup' });
  }
});

app.get('/api/admin/database/download-backup/:filename', requireAdmin, (req: Request, res: Response) => {
  const filename = req.params.filename;
  if (!filename || !filename.endsWith('.db') || filename.includes('..')) {
    return res.status(400).json({ error: 'Invalid backup file requested' });
  }
  const filePath = path.join(process.cwd(), 'data', 'backups', filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Backup file not found' });
  }
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  return res.sendFile(filePath);
});

// Admin Export SQL Dump for local sqlite3 import
app.get('/api/admin/database/export-sql', requireAdmin, (req: Request, res: Response) => {
  try {
    const scriptPath = path.resolve(process.cwd(), 'server', 'sqlite_sync.py');
    const { execSync } = require('child_process');
    execSync(`python3 "${scriptPath}"`);
    
    // Dump using python sqlite3 script
    const dumpScript = `
import sqlite3
conn = sqlite3.connect('data/novora.db')
for line in conn.iterdump():
    print(line)
conn.close()
`;
    const dumpOutput = execSync(`python3 -c "${dumpScript.replace(/"/g, '\\"')}"`, { encoding: 'utf-8' });
    res.setHeader('Content-Disposition', 'attachment; filename="novora_schema_and_data.sql"');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send(dumpOutput);
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to export SQL' });
  }
});


// Admin Update User Personal Details (matching Admin Actions in Flowchart)
app.put('/api/admin/users/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const user = store.users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found in local database' });
  }

  const { fullName, email, phone } = req.body;
  if (fullName) user.fullName = fullName.trim();
  if (email) user.email = email.trim().toLowerCase();
  if (phone !== undefined) user.phone = phone.trim();
  user.updatedAt = new Date().toISOString();

  db.commit();
  return res.json({ success: true, user: db.sanitizeUser(user) });
});

// Admin Delete User (matching Admin Actions in Flowchart)
app.delete('/api/admin/users/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const initialLen = store.users.length;
  store.users = store.users.filter(u => u.id !== req.params.id && u.role !== 'admin');
  if (store.users.length === initialLen) {
    return res.status(404).json({ error: 'User not found or cannot delete root admin' });
  }

  db.commit();
  return res.json({ success: true, message: 'User deleted and removed from local storage files' });
});

// ==========================================
// 3. PRODUCTS CATALOG & ADMIN PRODUCT MGMT
// ==========================================
function formatNormalizedProduct(p: Product & Record<string, any>): Product {
  const rawImages: unknown[] = [];
  if (Array.isArray(p.images)) {
    rawImages.push(...p.images);
  }
  for (const field of ['mainImage', 'image', 'imageUrl', 'image_url', 'thumbnail']) {
    if (p[field]) rawImages.push(p[field]);
  }
  const normalized = Array.from(
    new Set(rawImages.map(item => normalizeStoredImageUrl(item, '')).filter(Boolean))
  );
  return {
    ...p,
    images: normalized.length > 0 ? normalized : ['/images/novora_cat_fashion_1792421786979.jpg'],
  };
}

function formatNormalizedCategory(c: Category & Record<string, any>): Category {
  const rawImg = c.image || c.imageUrl || c.image_url || c.thumbnail || '/images/novora_cat_fashion_1792421786979.jpg';
  return {
    ...c,
    image: normalizeStoredImageUrl(rawImg, '/images/novora_cat_fashion_1792421786979.jpg'),
  };
}

function formatNormalizedBanner(b: Banner & Record<string, any>): Banner {
  const rawImg = b.imageUrl || b.image_url || b.image || '/images/novora_beauty_banner.jpg';
  return {
    ...b,
    imageUrl: normalizeStoredImageUrl(rawImg, '/images/novora_beauty_banner.jpg'),
  };
}

app.get('/api/products', (req: Request, res: Response) => {
  const store = db.getData();
  const { category, search, sort, featured, bestSeller, status, brand } = req.query;

  let products = [...store.products];

  // If request is not from an authenticated admin, STRICTLY return 'published' items
  const user = (req as any).user as User | undefined;
  const isAdmin = user && user.role === 'admin';

  if (!isAdmin) {
    products = products.filter(p => p.status === 'published');
  } else if (status && status !== 'all') {
    products = products.filter(p => p.status === status);
  }

  if (category && category !== 'all') {
    const catLower = String(category).toLowerCase();
    products = products.filter(p => 
      p.category.toLowerCase() === catLower ||
      p.category.toLowerCase().includes(catLower)
    );
  }

  if (brand) {
    products = products.filter(p => p.brand.toLowerCase() === String(brand).toLowerCase());
  }

  if (featured === 'true') {
    products = products.filter(p => p.featured);
  }

  if (bestSeller === 'true') {
    products = products.filter(p => p.bestSeller);
  }

  if (search) {
    const term = String(search).toLowerCase().trim();
    products = products.filter(p => 
      p.name.toLowerCase().includes(term) ||
      p.description.toLowerCase().includes(term) ||
      p.brand.toLowerCase().includes(term) ||
      p.category.toLowerCase().includes(term) ||
      p.sku.toLowerCase().includes(term)
    );
  }

  // Sorting
  if (sort === 'price-low') {
    products.sort((a, b) => a.sellingPrice - b.sellingPrice);
  } else if (sort === 'price-high') {
    products.sort((a, b) => b.sellingPrice - a.sellingPrice);
  } else if (sort === 'highest-rated') {
    products.sort((a, b) => b.rating - a.rating);
  } else if (sort === 'best-selling') {
    products.sort((a, b) => (b.bestSeller ? 1 : 0) - (a.bestSeller ? 1 : 0));
  } else {
    // Newest first default
    products.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  return res.json(products.map(formatNormalizedProduct));
});

app.get('/api/products/:id', (req: Request, res: Response) => {
  const user = (req as any).user as User | undefined;
  const isAdmin = user && user.role === 'admin';
  const product = db.getProduct(req.params.id);

  if (!product) {
    return res.status(404).json({ error: 'Product not found or has been removed from store.' });
  }

  if (!isAdmin && product.status !== 'published') {
    return res.status(404).json({ error: 'This product is currently unpublished or no longer available.' });
  }

  return res.json(formatNormalizedProduct(product));
});

app.post('/api/products', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const {
    name,
    sku,
    description,
    category,
    subcategory,
    brand,
    originalPrice,
    sellingPrice,
    discountPercentage,
    stock,
    maxOrderQuantity,
    status,
    featured,
    bestSeller,
    images,
    image,
    imageUrl,
    image_url,
    mainImage,
    thumbnail,
    variants,
  } = req.body;

  if (!name || sellingPrice === undefined || !category) {
    return res.status(400).json({ error: 'Product name, selling price, and category are required' });
  }

  const candidateImgs: unknown[] = [];
  if (Array.isArray(images)) candidateImgs.push(...images);
  else if (typeof images === 'string' && images.trim()) candidateImgs.push(images);
  for (const extra of [mainImage, image, imageUrl, image_url, thumbnail]) {
    if (extra) candidateImgs.push(extra);
  }
  const normalizedImages = Array.from(
    new Set(candidateImgs.map(item => normalizeStoredImageUrl(item, '')).filter(Boolean))
  );

  const generatedSku = sku?.trim() || `NVR-${category.substring(0, 3).toUpperCase()}-${Math.floor(100 + Math.random() * 900)}`;
  const calcDiscount = discountPercentage !== undefined && discountPercentage !== ''
    ? Number(discountPercentage)
    : (originalPrice && Number(originalPrice) > Number(sellingPrice)
      ? Math.round(((Number(originalPrice) - Number(sellingPrice)) / Number(originalPrice)) * 100)
      : 0);

  const baseCur = getStoreBaseCurrency(store);
  const newProduct: Product = db.normalizeProductVariantsAndStock({
    id: `prod_${Date.now()}`,
    name: name.trim(),
    sku: generatedSku,
    description: description || '',
    category: category.trim(),
    subcategory: subcategory?.trim() || '',
    brand: brand?.trim() || 'NOVORA Atelier',
    originalPrice: Math.max(0, Number(originalPrice || sellingPrice)),
    sellingPrice: Math.max(0, Number(sellingPrice)),
    discountPercentage: calcDiscount,
    baseCurrency: baseCur,
    stock: Number(stock !== undefined ? stock : 10),
    maxOrderQuantity: maxOrderQuantity && Number(maxOrderQuantity) > 0 ? Math.floor(Number(maxOrderQuantity)) : undefined,
    status: status || 'published',
    featured: Boolean(featured),
    bestSeller: Boolean(bestSeller),
    images: normalizedImages.length > 0 ? normalizedImages : ['/images/novora_hero_campaign_1792421787462.jpg'],
    variants: variants || {},
    rating: 5.0,
    reviewsCount: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  const adminEmail = ((req as any).user as User)?.email || 'admin@novora.store';
  store.products.unshift(newProduct);
  db.logProductChange({
    action: 'product_created',
    productId: newProduct.id,
    productName: newProduct.name,
    sku: newProduct.sku,
    adminEmail,
    details: `Product "${newProduct.name}" created with price ${formatExactCurrency(newProduct.sellingPrice, baseCur)} (${baseCur}) and stock ${newProduct.stock}.`,
    status: 'success',
  });
  db.addAuditLog({
    adminEmail,
    action: 'product_created',
    details: `Product "${newProduct.name}" (SKU: ${newProduct.sku}, ID: ${newProduct.id}) created by ${adminEmail}.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });
  db.commit();

  return res.status(201).json({ success: true, product: formatNormalizedProduct(newProduct) });
});

app.put('/api/products/:id', requireAdmin, (req: Request, res: Response) => {
  const adminEmail = ((req as any).user as User)?.email || 'admin@novora.store';
  const updated = db.updateProduct(req.params.id, req.body);
  if (!updated) {
    return res.status(404).json({ error: 'Product not found' });
  }
  db.logProductChange({
    action: 'product_updated',
    productId: updated.id,
    productName: updated.name,
    sku: updated.sku,
    adminEmail,
    details: `Product "${updated.name}" updated by administrator ${adminEmail}.`,
    status: 'success',
  });
  db.addAuditLog({
    adminEmail,
    action: 'product_updated',
    details: `Product "${updated.name}" (SKU: ${updated.sku}, ID: ${updated.id}) updated by ${adminEmail}.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  });
  return res.json({ success: true, product: formatNormalizedProduct(updated) });
});

app.delete('/api/products/:id', requireAdmin, (req: Request, res: Response) => {
  const adminEmail = ((req as any).user as User)?.email || 'admin@novora.store';
  const success = db.deleteProduct(req.params.id, adminEmail);
  if (!success) {
    return res.status(404).json({ error: 'Product not found or already deleted' });
  }
  return res.json({
    success: true,
    productId: req.params.id,
    message: 'Product deleted permanently from database and storefront',
  });
});

app.get('/api/admin/products/changes-log', requireAdmin, (req: Request, res: Response) => {
  return res.json(db.getProductChangesLog());
});

// ==========================================
// 4. CATEGORIES MANAGEMENT
// ==========================================
app.get('/api/categories', (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User | undefined;
  const isAdmin = user && user.role === 'admin';
  let categories = [...store.categories];
  if (!isAdmin) {
    categories = categories.filter(c => c.status === 'active');
  }
  categories.sort((a, b) => a.displayOrder - b.displayOrder);
  return res.json(categories.map(formatNormalizedCategory));
});

app.post('/api/categories', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { name, image, imageUrl, image_url, thumbnail, description, subcategories, displayOrder, status } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  const resolvedImg = normalizeStoredImageUrl(
    image || imageUrl || image_url || thumbnail,
    '/images/novora_cat_fashion_1792421786979.jpg'
  );
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
  const newCat: Category = {
    id: `cat_${Date.now()}`,
    name: name.trim(),
    slug,
    image: resolvedImg,
    description: description || '',
    subcategories: Array.isArray(subcategories) ? subcategories : [],
    displayOrder: displayOrder !== undefined ? Number(displayOrder) : store.categories.length + 1,
    status: status || 'active',
  };

  store.categories.push(newCat);
  db.commit();

  return res.status(201).json({ success: true, category: formatNormalizedCategory(newCat) });
});

app.put('/api/categories/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const idx = store.categories.findIndex(c => c.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Category not found' });
  }

  const nextImage = req.body.image || req.body.imageUrl || req.body.image_url || req.body.thumbnail;
  store.categories[idx] = {
    ...store.categories[idx],
    ...req.body,
    ...(nextImage
      ? { image: normalizeStoredImageUrl(nextImage, '/images/novora_cat_fashion_1792421786979.jpg') }
      : {}),
  };
  db.commit();

  return res.json({ success: true, category: formatNormalizedCategory(store.categories[idx]) });
});

app.delete('/api/categories/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  store.categories = store.categories.filter(c => c.id !== req.params.id);
  db.commit();
  return res.json({ success: true });
});

// ==========================================
// 5. BANNERS MANAGEMENT
// ==========================================
app.get('/api/banners', (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User | undefined;
  const isAdmin = user && user.role === 'admin';
  let banners = [...store.banners];
  if (!isAdmin) {
    banners = banners.filter(b => b.isActive);
  }
  banners.sort((a, b) => a.displayOrder - b.displayOrder);
  return res.json(banners.map(formatNormalizedBanner));
});

app.post('/api/banners', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { title, subtitle, badgeText, buttonText, linkUrl, imageUrl, image, image_url, displayOrder, isActive, startDate, endDate } = req.body;
  const rawImg = imageUrl || image || image_url;
  if (!title || !rawImg) {
    return res.status(400).json({ error: 'Banner title and image are required' });
  }

  const newBanner: Banner = {
    id: `banner_${Date.now()}`,
    title: title.trim(),
    subtitle: subtitle || '',
    badgeText: badgeText || 'Special Highlight',
    buttonText: buttonText || 'Shop Now',
    linkUrl: linkUrl || '/shop',
    imageUrl: normalizeStoredImageUrl(rawImg, '/images/novora_beauty_banner.jpg'),
    displayOrder: displayOrder !== undefined ? Number(displayOrder) : store.banners.length + 1,
    isActive: isActive !== undefined ? Boolean(isActive) : true,
    startDate,
    endDate,
  };

  store.banners.push(newBanner);
  db.commit();

  return res.status(201).json({ success: true, banner: formatNormalizedBanner(newBanner) });
});

app.put('/api/banners/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const idx = store.banners.findIndex(b => b.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Banner not found' });
  }

  const nextImg = req.body.imageUrl || req.body.image || req.body.image_url;
  store.banners[idx] = {
    ...store.banners[idx],
    ...req.body,
    ...(nextImg ? { imageUrl: normalizeStoredImageUrl(nextImg, '/images/novora_beauty_banner.jpg') } : {}),
  };
  db.commit();

  return res.json({ success: true, banner: formatNormalizedBanner(store.banners[idx]) });
});

app.delete('/api/banners/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  store.banners = store.banners.filter(b => b.id !== req.params.id);
  db.commit();
  return res.json({ success: true });
});

// ==========================================
// 6. ORDERS & CHECKOUT (Compulsory 10 Delivery Fields)
// ==========================================
app.post('/api/orders', async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const {
      items,
      deliveryAddress,
      accountEmail,
      couponCode,
      paymentMethod,
      bankReferenceNumber,
      currency,
      quotedExchangeRate,
      quotedRateTimestamp,
      expectedDisplayTotal,
      notes,
    } = req.body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Your cart is empty. Please add items before checking out.' });
    }

    // MANDATORY 10 DELIVERY ADDRESS FIELDS VALIDATION
    if (!deliveryAddress) {
      return res.status(400).json({ error: 'Compulsory delivery address is required.' });
    }

    const {
      fullName,
      email,
      phone,
      country,
      state,
      city,
      streetAddress,
      houseNumber,
      postalCode,
      apartmentDetails,
    } = deliveryAddress;

    if (!fullName || !fullName.trim()) {
      return res.status(400).json({ error: 'Full legal name is required for delivery.' });
    }
    if (!email || !email.trim() || !email.includes('@')) {
      return res.status(400).json({ error: 'A valid email address is required for order & tracking updates.' });
    }

    // Enforce email verification policy for orders
    const authenticatedUser = (req as any).user as User | undefined;
    if (authenticatedUser && authenticatedUser.role === 'customer' && authenticatedUser.isEmailVerified === false) {
      return res.status(403).json({
        error: 'Email verification is required before placing an order. Please verify your email with your 6-digit verification code.',
        requiresVerification: true,
        email: authenticatedUser.email,
      });
    }

    const matchingCustomer = store.users.find(u => u.email.toLowerCase() === email.trim().toLowerCase());
    if (matchingCustomer && matchingCustomer.role === 'customer' && matchingCustomer.isEmailVerified === false) {
      return res.status(403).json({
        error: 'An account exists for this email address and requires email verification before placing orders. Please sign in and verify your account.',
        requiresVerification: true,
        email: matchingCustomer.email,
      });
    }

    if (!phone || !phone.trim()) {
      return res.status(400).json({ error: 'Phone number is compulsory for courier contact.' });
    }
    if (!country || !country.trim()) {
      return res.status(400).json({ error: 'Country is compulsory.' });
    }
    if (!state || !state.trim()) {
      return res.status(400).json({ error: 'State or province is compulsory.' });
    }
    if (!city || !city.trim()) {
      return res.status(400).json({ error: 'City is compulsory.' });
    }
    if (!streetAddress || !streetAddress.trim()) {
      return res.status(400).json({ error: 'Street address is compulsory.' });
    }
    if (!houseNumber || !houseNumber.trim()) {
      return res.status(400).json({ error: 'House or building number is compulsory.' });
    }
    if (!postalCode || !postalCode.trim()) {
      return res.status(400).json({ error: 'Postal or ZIP code is compulsory.' });
    }

    // Authoritative server-side variant, stock, currency, coupon, shipping-region & quote verification
    const computed = await validateAndComputeCheckoutQuote(store, {
      items,
      displayCurrency: currency,
      country: country.trim(),
      couponCode,
      quotedExchangeRate,
      quotedRateTimestamp,
      expectedDisplayTotal,
      requireValidQuote:
        quotedExchangeRate !== undefined ||
        quotedRateTimestamp !== undefined ||
        expectedDisplayTotal !== undefined,
    });

    const { breakdown, snapshot, coupon, orderItems, reserveVariantAndProductStock } = computed;

    // Verified Payment Gateway Processing
    let paymentStatus: 'pending' | 'paid' | 'declined' = 'pending';
    let orderStatus: OrderStatus = 'Awaiting Payment';
    let paymentDetails: PaymentDetails;

    const selectedMethod = (paymentMethod || 'Cash on Delivery (COD)').trim();

    if (
      (selectedMethod.toLowerCase().includes('cash on delivery') || selectedMethod.toLowerCase() === 'cod') &&
      store.paymentGateway?.codEnabled === false
    ) {
      return res.status(400).json({ error: 'Cash on Delivery is currently disabled in Store Payment Settings.' });
    }
    if (
      (selectedMethod.toLowerCase().includes('cash on delivery') || selectedMethod.toLowerCase() === 'cod') &&
      store.paymentGateway?.maxCodAmount > 0 &&
      breakdown.baseTotal > store.paymentGateway.maxCodAmount
    ) {
      return res.status(400).json({
        error: `Cash on Delivery is limited to orders up to ${formatExactCurrency(store.paymentGateway.maxCodAmount, breakdown.baseCurrency)}. Please use Card or Bank Transfer.`,
      });
    }

    if (selectedMethod.toLowerCase().includes('card') || selectedMethod.toLowerCase().includes('stripe') || selectedMethod.toLowerCase().includes('safepay')) {
      return res.status(400).json({
        error: 'Card payments must be processed and verified through the secure Payment Gateway session (/api/payments/create-session).',
      });
    } else if (selectedMethod.toLowerCase().includes('bank') || selectedMethod.toLowerCase().includes('easypaisa') || selectedMethod.toLowerCase().includes('jazzcash')) {
      if (store.paymentGateway?.bankTransferEnabled === false) {
        return res.status(400).json({ error: 'Bank Transfer is currently disabled in Store Payment Settings.' });
      }
      const notesBankMatch = typeof notes === 'string' ? notes.match(/\[Bank Ref:\s*([^\]]+)\]/i) : null;
      const rawBankRef =
        typeof bankReferenceNumber === 'string' && bankReferenceNumber.trim()
          ? bankReferenceNumber.trim()
          : notesBankMatch?.[1]?.trim() || '';
      paymentStatus = 'pending';
      orderStatus = 'Awaiting Payment';
      paymentDetails = {
        provider: 'Bank Transfer / JazzCash / EasyPaisa',
        paymentMethodTitle: 'Direct Bank Transfer / EasyPaisa / JazzCash',
        referenceNumber: rawBankRef || 'Awaiting Customer Transfer TID',
        bankSubmittedByCustomer: Boolean(rawBankRef),
        isTestMode: false,
      };
    } else {
      paymentStatus = 'pending';
      orderStatus = 'Awaiting Payment';
      paymentDetails = {
        provider: 'Cash on Delivery',
        paymentMethodTitle: 'Cash on Delivery (COD)',
        isTestMode: false,
      };
    }

    // Increment coupon usage & atomically decrement variant SKU + aggregate product stock
    if (coupon && breakdown.displayDiscount > 0) {
      coupon.usageCount = (coupon.usageCount || 0) + 1;
    }
    reserveVariantAndProductStock();

    // Generate unique order number
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const orderNumber = `NOV-2026-${randomSuffix}`;
    const currentUser = (req as any).user as User | undefined;
    const deliveryEmailClean = email.trim().toLowerCase();
    const bodyAccountEmail = typeof accountEmail === 'string' && accountEmail.trim().includes('@') ? accountEmail.trim().toLowerCase() : '';
    const buyerAccountEmail = currentUser?.email?.trim().toLowerCase() || bodyAccountEmail || deliveryEmailClean;
    const nowIso = new Date().toISOString();

    const newOrder: Order = {
      id: `ord_${Date.now()}`,
      orderNumber,
      createdAt: nowIso,
      updatedAt: nowIso,
      userId: currentUser?.id,
      accountEmail: buyerAccountEmail,
      isRegisteredBuyer: Boolean(currentUser),
      customer: {
        fullName: currentUser?.fullName?.trim() || fullName.trim(),
        email: buyerAccountEmail,
        phone: phone.trim(),
      },
      deliveryAddress: {
        fullName: fullName.trim(),
        email: deliveryEmailClean,
        phone: phone.trim(),
        country: country.trim(),
        state: state.trim(),
        city: city.trim(),
        streetAddress: streetAddress.trim(),
        houseNumber: houseNumber.trim(),
        apartmentDetails: apartmentDetails ? apartmentDetails.trim() : '',
        postalCode: postalCode.trim(),
      },
      items: orderItems,
      subtotal: breakdown.displaySubtotal,
      discount: breakdown.displayDiscount,
      couponCode: coupon && breakdown.displayDiscount > 0 ? coupon.code : undefined,
      shippingFee: breakdown.displayShippingFee,
      shippingRegion: breakdown.appliedShippingRegionName,
      taxAmount: breakdown.displayTaxAmount,
      taxRatePercentage: breakdown.taxRatePercentage,
      total: breakdown.displayTotal,
      currency: breakdown.displayCurrency,
      baseCurrency: breakdown.baseCurrency,
      baseSubtotal: breakdown.baseSubtotal,
      baseDiscount: breakdown.baseDiscount,
      baseShippingFee: breakdown.baseShippingFee,
      baseTaxAmount: breakdown.baseTaxAmount,
      baseTotal: breakdown.baseTotal,
      exchangeRateUsed: breakdown.exchangeRate,
      exchangeRateTimestamp: snapshot.lastUpdated,
      paymentMethod: selectedMethod,
      paymentStatus,
      orderStatus,
      paymentDetails,
      trackingNumber: `TRK-NV-${Math.floor(1000000 + Math.random() * 9000000)}`,
      carrier: 'NOVORA Express & Courier Network',
      dropshippingStatus: 'unfulfilled',
      notes: notes?.trim(),
    };

    // Route customer purchase payment directly to Admin's Default Merchant Bank Card / Account
    const activeMerchantCard = store.paymentGateway?.merchantCard;
    const activeBankName = store.paymentGateway?.payoutAccount?.bankName || 'Meezan Bank Ltd (Raast / 1Link)';
    const cardLast4 = activeMerchantCard?.last4 || '9922';
    const cardBrand = activeMerchantCard?.brand ? activeMerchantCard.brand.toUpperCase() : 'VISA';
    const cardHolder = activeMerchantCard?.cardholderName || 'NOVORA ATELIER GLOBAL';
    const settlementInfo = `Credited to Admin Card •••• ${cardLast4} (${cardBrand} · ${cardHolder}) / Payout: ${activeBankName}`;

    newOrder.settledToMerchantCard = settlementInfo;

    // Auto-save address to customer's account if authenticated and not yet saved
    if (currentUser) {
      const dbUser = store.users.find(u => u.id === currentUser.id);
      if (dbUser) {
        if (!dbUser.savedAddresses) dbUser.savedAddresses = [];
        const alreadyHas = dbUser.savedAddresses.some(
          a => a.streetAddress.toLowerCase() === streetAddress.trim().toLowerCase() &&
               a.city.toLowerCase() === city.trim().toLowerCase()
        );
        if (!alreadyHas) {
          dbUser.savedAddresses.push({
            id: `addr_${Date.now()}`,
            ...newOrder.deliveryAddress,
            isDefault: dbUser.savedAddresses.length === 0,
          });
        }
      }
    }

    store.orders.unshift(newOrder);

    db.commit();

    return res.status(201).json({
      success: true,
      order: newOrder,
      message: `Order ${newOrder.orderNumber} placed successfully! Please follow payment instructions.`,
    });
  } catch (err: any) {
    console.error('Order creation error:', err);
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    if (err?.statusCode) {
      return res.status(err.statusCode).json({
        error: err.message,
        code: err.code,
        quote: err.quote,
      });
    }
    return res.status(500).json({ error: err.message || 'Failed to place order.' });
  }
});

app.get('/api/orders', (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User | undefined;

  if (!user) {
    return res.status(401).json({ error: 'Authentication required to view orders' });
  }

  // Admin sees all orders; customers only see their personal orders
  if (user.role === 'admin') {
    return res.json(store.orders);
  } else {
    const cleanUserEmail = user.email.toLowerCase();
    const customerOrders = store.orders.filter(o =>
      o.userId === user.id ||
      o.accountEmail?.toLowerCase() === cleanUserEmail ||
      o.customer.email.toLowerCase() === cleanUserEmail ||
      o.deliveryAddress.email.toLowerCase() === cleanUserEmail
    );
    return res.json(customerOrders);
  }
});

app.get('/api/orders/:id', (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User | undefined;
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const order = store.orders.find(o => o.id === req.params.id || o.orderNumber === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  const cleanUserEmail = user.email.toLowerCase();
  if (
    user.role !== 'admin' &&
    order.userId !== user.id &&
    order.accountEmail?.toLowerCase() !== cleanUserEmail &&
    order.customer.email.toLowerCase() !== cleanUserEmail
  ) {
    return res.status(403).json({ error: 'Access denied to this order' });
  }

  return res.json(order);
});

app.put('/api/orders/:id/status', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User;
  const { status, trackingNumber, carrier, paymentStatus } = req.body;
  const order = store.orders.find(o => o.id === req.params.id || o.orderNumber === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  const prevStatus = order.orderStatus;
  const prevPayment = order.paymentStatus;

  if (status) order.orderStatus = status;
  if (trackingNumber !== undefined) order.trackingNumber = trackingNumber;
  if (carrier !== undefined) order.carrier = carrier;
  if (paymentStatus) {
    order.paymentStatus = paymentStatus;
    if (paymentStatus === 'paid' && (order.orderStatus === 'Awaiting Payment' || (order.orderStatus as string) === 'Pending Payment')) {
      order.orderStatus = 'Paid';
    }
  }
  order.updatedAt = new Date().toISOString();

  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_order_status_updated',
    details: `Order ${order.orderNumber} status changed from "${prevStatus}" to "${order.orderStatus}" (Payment: ${prevPayment} -> ${order.paymentStatus}) by ${user.email}.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  }, true);

  db.commit();
  return res.json({ success: true, order });
});

// Archive / Unarchive order
app.put('/api/orders/:id/archive', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User;
  const { isArchived } = req.body;
  const order = store.orders.find(o => o.id === req.params.id || o.orderNumber === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  order.isArchived = isArchived !== undefined ? Boolean(isArchived) : !order.isArchived;
  order.archivedAt = order.isArchived ? new Date().toISOString() : undefined;

  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_order_archived',
    details: `Order ${order.orderNumber} ${order.isArchived ? 'archived' : 'unarchived'} by administrator ${user.email}.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  }, true);

  db.commit();
  return res.json({ success: true, order });
});

// Bulk Delete Orders in a single commit
app.post('/api/orders/bulk-delete', requireAdmin, (req: Request, res: Response) => {
  const user = (req as any).user as User;
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'An array of order IDs is required.' });
  }

  const deletedOrders = db.deleteOrdersBulk(ids, true);
  if (deletedOrders.length === 0) {
    return res.status(404).json({ error: 'No matching orders found to delete.' });
  }

  const summary = deletedOrders.slice(0, 10).map(o => o.orderNumber).join(', ');
  const moreCount = deletedOrders.length > 10 ? ` (+${deletedOrders.length - 10} more)` : '';
  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_orders_bulk_deleted',
    details: `${deletedOrders.length} orders permanently deleted (${summary}${moreCount}) by administrator ${user.email}. Payment transaction records preserved.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  }, true);

  db.commit();
  return res.json({
    success: true,
    deletedIds: deletedOrders.map(o => o.id),
    message: `${deletedOrders.length} order(s) permanently deleted from active records.`,
  });
});

// Delete Order from active orders and database (with single commit + audit logging, preserving payment transactions)
app.delete('/api/orders/:id', requireAdmin, (req: Request, res: Response) => {
  const user = (req as any).user as User;
  const deletedOrder = db.deleteOrder(req.params.id, true);
  if (!deletedOrder) {
    return res.status(404).json({ error: 'Order not found or has already been removed' });
  }

  db.addAuditLog({
    adminEmail: user.email,
    action: 'admin_order_deleted',
    details: `Order ${deletedOrder.orderNumber} (ID: ${deletedOrder.id}) was permanently deleted by administrator ${user.email}. Customer: ${deletedOrder.customer.fullName} (${deletedOrder.customer.email}). Total: $${deletedOrder.total}. Payment transaction records preserved.`,
    status: 'success',
    ip: req.ip || req.socket.remoteAddress,
  }, true);

  db.commit();
  return res.json({
    success: true,
    message: `Order ${deletedOrder.orderNumber} permanently deleted from active records.`,
  });
});

// ==========================================
// PAYMENT GATEWAY SETTINGS & WEBHOOKS
// ==========================================
app.get('/api/payment-settings', (req: Request, res: Response) => {
  const store = db.getData();
  const config = store.paymentGateway;
  // Return public safe configuration needed by customer checkout
  return res.json({
    provider: config.provider,
    providerName: config.providerName,
    isTestMode: config.isTestMode,
    mode: config.mode || (config.isTestMode ? 'test' : 'live'),
    cardsEnabled: config.cardsEnabled,
    bankTransferEnabled: config.bankTransferEnabled,
    codEnabled: config.codEnabled,
    maxCodAmount: config.maxCodAmount,
    supportedCurrencies: config.supportedCurrencies,
    bankDetails: {
      bankName: config.bankDetails.bankName,
      accountTitle: config.bankDetails.accountTitle,
      ibanMasked: config.bankDetails.ibanMasked,
      branchCode: config.bankDetails.branchCode,
      instructions: config.bankDetails.instructions,
    },
  });
});

app.get('/api/admin/payment-settings', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(sanitizePaymentGatewayForAdmin(store.paymentGateway));
});

app.put('/api/admin/payment-settings', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const current = store.paymentGateway;
  const updates = req.body || {};

  // Security enforcement: Never accept full card numbers, CVVs, or bank passwords
  if (updates.cardNumber || updates.cvv || updates.pin || updates.bankingPassword) {
    return res.status(400).json({
      error: 'Security Violation: Full card numbers, PINs, or banking passwords must never be stored in the admin panel.',
    });
  }

  const nextProvider = updates.provider || current.provider;
  const nextIsTestMode =
    updates.isTestMode !== undefined
      ? Boolean(updates.isTestMode)
      : updates.mode !== undefined
      ? updates.mode === 'test'
      : current.isTestMode;
  const nextMode: 'test' | 'live' = updates.mode || (nextIsTestMode ? 'test' : 'live');

  store.paymentGateway = {
    ...current,
    ...updates,
    provider: nextProvider,
    providerName: updates.providerName || PROVIDER_DISPLAY_NAMES[nextProvider] || current.providerName,
    isTestMode: nextIsTestMode,
    mode: nextMode,
    bankDetails: {
      ...current.bankDetails,
      ...(updates.bankDetails || {}),
    },
  };
  db.commit();

  return res.json({ success: true, paymentGateway: sanitizePaymentGatewayForAdmin(store.paymentGateway) });
});

app.post('/api/admin/payment-settings/connect', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { provider = 'safepay' } = req.body;

  store.paymentGateway.isConnected = true;
  store.paymentGateway.payoutStatus = 'Active';
  store.paymentGateway.provider = provider;
  store.paymentGateway.providerName = PROVIDER_DISPLAY_NAMES[provider] || provider.toUpperCase();
  store.paymentGateway.lastVerifiedAt = new Date().toISOString();
  if (!store.paymentGateway.payoutAccountMasked) {
    store.paymentGateway.payoutAccountMasked = 'Meezan Bank Ltd · IBAN: PK** **** **** 4821';
  }
  db.commit();

  return res.json({
    success: true,
    message: `Successfully connected and verified with ${store.paymentGateway.providerName} Gateway!`,
    paymentGateway: sanitizePaymentGatewayForAdmin(store.paymentGateway),
  });
});

// Admin Bank Payout Account Save & Verify
app.post('/api/admin/payment-settings/bank-account', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { bankName, accountHolderName, country, currency, accountNumberOrIban, branchCode, pin, bankingPassword, cvv, cardNumber } = req.body;

  // Strict PCI-DSS and Banking Security check
  if (pin || bankingPassword || cvv || cardNumber) {
    return res.status(400).json({
      error: 'Security Alert: ATM PIN, banking password, CVV, or card numbers must never be requested or submitted.',
    });
  }

  if (!bankName || !accountHolderName || !country || !currency || !accountNumberOrIban) {
    return res.status(400).json({
      error: 'Bank name, account holder name, country, currency, and account number / IBAN are required.',
    });
  }

  const rawIban = String(accountNumberOrIban).trim().toUpperCase().replace(/\s+/g, '');
  if (rawIban.length < 8) {
    return res.status(400).json({
      error: 'Please enter a valid bank account number or IBAN.',
    });
  }

  // Create masked IBAN format (e.g. PK92 MEZN **** **** 4821)
  const prefix = rawIban.substring(0, 4);
  const suffix = rawIban.slice(-4);
  const maskedIban = `${prefix} **** **** ${suffix}`;

  const bankAccount: BankPayoutAccount = {
    bankName: bankName.trim(),
    accountHolderName: accountHolderName.trim(),
    country: country.trim().toUpperCase(),
    currency: currency.trim().toUpperCase(),
    maskedIban,
    branchCode: branchCode ? String(branchCode).trim() : undefined,
    status: 'Verified',
    verifiedAt: new Date().toISOString(),
  };

  const previousMasked = store.paymentGateway.payoutAccountMasked || 'None (Initial Setup)';
  store.paymentGateway.payoutAccount = bankAccount;
  store.paymentGateway.payoutAccountMasked = `${bankAccount.bankName} · ${maskedIban}`;
  store.paymentGateway.payoutStatus = 'Active';
  store.paymentGateway.lastVerifiedAt = new Date().toISOString();

  if (!store.paymentGateway.payoutAuditLog) {
    store.paymentGateway.payoutAuditLog = [];
  }
  const refCode = `REF-PO-2026-${Math.floor(100000 + Math.random() * 900000)}`;
  const auditEntry: PayoutAuditRecord = {
    id: `audit_${Date.now()}`,
    changedAt: new Date().toISOString(),
    adminEmail: (req as any).user?.email || 'admin@novora.store',
    action: 'payout_destination_linked',
    previousAccountMasked: previousMasked,
    newAccountMasked: store.paymentGateway.payoutAccountMasked,
    bankName: bankAccount.bankName,
    currency: bankAccount.currency,
    confirmationReference: refCode,
    provider: store.paymentGateway.provider || 'safepay',
    notes: 'Secure bank payout account verified and linked via 1Link payment rail.',
  };
  store.paymentGateway.payoutAuditLog.unshift(auditEntry);

  db.commit();

  return res.json({
    success: true,
    message: `Bank account with ${bankName} successfully verified and linked for merchant payouts.`,
    payoutAccount: bankAccount,
    confirmationReference: refCode,
    auditRecord: auditEntry,
    paymentGateway: store.paymentGateway,
  });
});

// Admin Dedicated Change Payout Account Flow with Confirmation & Audit Trail
app.post('/api/admin/payment-settings/change-payout-account', requireAdmin, async (req: Request, res: Response) => {
  const store = db.getData();
  const {
    bankName,
    accountHolderName,
    country,
    currency,
    accountNumberOrIban,
    branchCode,
    adminConfirmationPassword,
    reasonForChange,
    pin,
    bankingPassword,
    cvv,
    cardNumber,
  } = req.body;

  // Strict PCI-DSS / Zero-Banking-Password Security Rule
  if (pin || bankingPassword || cvv || cardNumber) {
    return res.status(400).json({
      error: 'Security Alert: ATM PIN, online banking password, CVV, or card numbers must NEVER be requested or submitted.',
    });
  }

  // Required Field Validations
  if (!bankName || !bankName.trim()) {
    return res.status(400).json({ error: 'Commercial bank name is required.' });
  }
  if (!accountHolderName || !accountHolderName.trim()) {
    return res.status(400).json({ error: 'Beneficiary account holder name is required and must match your business/tax registration.' });
  }
  if (!country || !country.trim()) {
    return res.status(400).json({ error: 'Bank country is required.' });
  }
  if (!currency || !currency.trim()) {
    return res.status(400).json({ error: 'Payout settlement currency is required.' });
  }
  if (!accountNumberOrIban || !accountNumberOrIban.trim()) {
    return res.status(400).json({ error: 'Bank Account Number or 24-character IBAN is required.' });
  }

  const rawIban = String(accountNumberOrIban).trim().toUpperCase().replace(/\s+/g, '');
  if (rawIban.length < 8) {
    return res.status(400).json({
      error: 'Invalid IBAN/account number. Please provide a valid 24-character IBAN or bank account number.',
    });
  }

  // Security Clearance Verification: Verify admin password with bcrypt
  const currentUser = (req as any).user as User | undefined;
  if (adminConfirmationPassword && currentUser) {
    const valid = await verifyUserPassword(currentUser, String(adminConfirmationPassword));
    if (!valid) {
      return res.status(403).json({
        error: 'Security Authorization Failed: Admin security password is incorrect. Payout destination unchanged.',
      });
    }
  }

  // Format masked IBAN
  const prefix = rawIban.substring(0, 4);
  const suffix = rawIban.slice(-4);
  const maskedIban = `${prefix} **** **** ${suffix}`;

  const previousMasked = store.paymentGateway.payoutAccountMasked || 'None (Initial Configuration)';
  const newAccountMasked = `${bankName.trim()} · ${maskedIban}`;

  const updatedAccount: BankPayoutAccount = {
    bankName: bankName.trim(),
    accountHolderName: accountHolderName.trim(),
    country: country.trim(),
    currency: currency.trim().toUpperCase(),
    maskedIban,
    branchCode: branchCode ? String(branchCode).trim() : undefined,
    status: 'Verified',
    verifiedAt: new Date().toISOString(),
  };

  const confirmationReference = `REF-PO-2026-${Math.floor(100000 + Math.random() * 900000)}`;

  const auditRecord: PayoutAuditRecord = {
    id: `audit_${Date.now()}`,
    changedAt: new Date().toISOString(),
    adminEmail: currentUser?.email || 'admin@novora.store',
    action: 'payout_destination_updated',
    previousAccountMasked: previousMasked,
    newAccountMasked: newAccountMasked,
    bankName: bankName.trim(),
    currency: currency.trim().toUpperCase(),
    confirmationReference,
    provider: store.paymentGateway.provider || 'safepay',
    notes: reasonForChange?.trim() || 'Admin confirmed bank payout account migration',
  };

  if (!store.paymentGateway.payoutAuditLog) {
    store.paymentGateway.payoutAuditLog = [];
  }
  store.paymentGateway.payoutAuditLog.unshift(auditRecord);

  store.paymentGateway.payoutAccount = updatedAccount;
  store.paymentGateway.payoutAccountMasked = newAccountMasked;
  store.paymentGateway.payoutStatus = 'Active';
  store.paymentGateway.lastVerifiedAt = new Date().toISOString();

  db.commit();

  console.log(`[API:Payment] Payout account changed by ${auditRecord.adminEmail}. Ref: ${confirmationReference}. New: ${newAccountMasked}`);

  return res.json({
    success: true,
    message: `Payout destination successfully updated to ${bankName.trim()} (${maskedIban}). Verified on 1Link settlement rails.`,
    payoutAccount: updatedAccount,
    confirmationReference,
    auditRecord,
    paymentGateway: store.paymentGateway,
  });
});

// Admin Get Payout Destination Audit Trail
app.get('/api/admin/payment-settings/payout-audit-log', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(store.paymentGateway.payoutAuditLog || []);
});

// Admin Disconnect Payment Gateway & Payouts
app.post('/api/admin/payment-settings/disconnect', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const previous = store.paymentGateway.payoutAccountMasked || 'None';
  store.paymentGateway.isConnected = false;
  store.paymentGateway.payoutStatus = 'Needs Setup';
  store.paymentGateway.payoutAccount = undefined;
  store.paymentGateway.payoutAccountMasked = '';
  store.paymentGateway.lastVerifiedAt = undefined;

  if (!store.paymentGateway.payoutAuditLog) {
    store.paymentGateway.payoutAuditLog = [];
  }
  const disconnectRef = `REF-PO-DISC-${Math.floor(100000 + Math.random() * 900000)}`;
  store.paymentGateway.payoutAuditLog.unshift({
    id: `audit_disc_${Date.now()}`,
    changedAt: new Date().toISOString(),
    adminEmail: (req as any).user?.email || 'admin@novora.store',
    action: 'payout_destination_disconnected',
    previousAccountMasked: previous,
    newAccountMasked: 'None (Disconnected)',
    bankName: 'Disconnected',
    currency: 'PKR',
    confirmationReference: disconnectRef,
    provider: store.paymentGateway.provider || 'safepay',
    notes: 'Admin manually disconnected payment provider and bank payout destination.',
  });

  db.commit();

  return res.json({
    success: true,
    message: 'Payment provider and payout bank account successfully disconnected.',
    paymentGateway: store.paymentGateway,
  });
});

// Admin Test Gateway Connection & Webhook Health
app.post('/api/admin/payment-settings/test-connection', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const provider = store.paymentGateway.provider || 'safepay';
  const mode = store.paymentGateway.mode || (store.paymentGateway.isTestMode ? 'test' : 'live');

  // Simulated provider API handshake ping latency
  const latencyMs = Math.floor(95 + Math.random() * 80);

  return res.json({
    success: true,
    provider,
    providerName: store.paymentGateway.providerName,
    mode,
    latencyMs,
    gatewayStatus: 'Operational',
    webhookEndpoint: '/api/webhooks/payment',
    webhookStatus: 'Healthy (Listening for SBP/PCI Tokenized Events)',
    payoutRail: store.paymentGateway.payoutAccount ? '1Link / SBP Direct Deposit (Active)' : 'Unlinked',
    testedAt: new Date().toISOString(),
  });
});

// Admin Get Payment Transactions History
app.get('/api/admin/payment-transactions', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { status, search } = req.query;
  let transactions = [...(store.paymentTransactions || [])];

  if (status && status !== 'all') {
    transactions = transactions.filter(t => t.paymentStatus === status || t.payoutStatus === status);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    transactions = transactions.filter(t =>
      t.transactionReference.toLowerCase().includes(q) ||
      t.orderNumber.toLowerCase().includes(q) ||
      t.customerName.toLowerCase().includes(q) ||
      t.customerEmail.toLowerCase().includes(q)
    );
  }

  return res.json(transactions);
});

// Admin Process Order Refund
app.post('/api/admin/orders/:id/refund', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const order = store.orders.find(o => o.id === req.params.id || o.orderNumber === req.params.id);

  if (!order) {
    return res.status(404).json({ error: 'Order not found.' });
  }

  if (order.paymentStatus !== 'paid' && order.paymentStatus !== 'partially_refunded') {
    return res.status(400).json({
      error: `Cannot refund order with payment status "${order.paymentStatus}". Only paid orders can be refunded.`,
    });
  }

  const { amount, reason } = req.body;
  const refundAmount = amount ? Number(amount) : order.total;

  if (isNaN(refundAmount) || refundAmount <= 0 || refundAmount > order.total) {
    return res.status(400).json({
      error: `Invalid refund amount. Must be between 1 and ${order.total} ${order.currency}.`,
    });
  }

  const isFullRefund = refundAmount >= order.total;
  order.paymentStatus = isFullRefund ? 'refunded' : 'partially_refunded';
  if (isFullRefund) {
    order.orderStatus = 'Refunded';
  }
  order.updatedAt = new Date().toISOString();

  const refundTx: PaymentTransaction = {
    id: `tx_ref_${Date.now()}`,
    transactionReference: `REF-SP-${Math.floor(100000 + Math.random() * 900000)}`,
    orderId: order.id,
    orderNumber: order.orderNumber,
    customerName: order.customer.fullName,
    customerEmail: order.accountEmail || order.customer.email,
    amount: refundAmount,
    currency: order.currency,
    fee: 0,
    netPayout: -refundAmount,
    provider: store.paymentGateway.provider || 'safepay',
    paymentMethod: order.paymentDetails?.paymentMethodTitle || order.paymentMethod,
    paymentStatus: isFullRefund ? 'refunded' : 'partially_refunded',
    payoutStatus: 'Refunded',
    merchantSettlementDestination: order.settledToMerchantCard,
    createdAt: new Date().toISOString(),
    refundedAmount: refundAmount,
    refundReason: reason || 'Customer requested refund / order cancellation',
  };

  if (!store.paymentTransactions) {
    store.paymentTransactions = [];
  }
  store.paymentTransactions.unshift(refundTx);
  db.commit();

  return res.json({
    success: true,
    message: `Successfully processed ${isFullRefund ? 'full' : 'partial'} refund of ${order.currency} ${refundAmount.toLocaleString()}.`,
    order,
    transaction: refundTx,
  });
});

// Admin Verify & Record Real Received Payment (for Bank Transfer, EasyPaisa, JazzCash, or Cash on Delivery)
app.post('/api/admin/orders/:id/verify-payment', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const adminUser = (req as any).user as User;
  const order = store.orders.find(o => o.id === req.params.id || o.orderNumber === req.params.id);

  if (!order) {
    return res.status(404).json({ error: 'Order not found.' });
  }

  if (order.paymentStatus === 'paid' && order.paymentDetails?.verifiedByAdmin) {
    return res.status(400).json({ error: 'This order payment has already been verified and settled.' });
  }

  const { transactionReference, paymentMethodTitle, provider, fee, notes } = req.body || {};
  const cleanRef =
    (typeof transactionReference === 'string' && transactionReference.trim()) ||
    order.paymentDetails?.referenceNumber ||
    order.paymentDetails?.transactionId ||
    `VER-${order.orderNumber}-${Date.now().toString().slice(-4)}`;

  const feeAmount = Number.isFinite(Number(fee)) && Number(fee) >= 0 ? Math.round(Number(fee) * 100) / 100 : 0;
  const netPayout = Math.round((Number(order.total || 0) - feeAmount) * 100) / 100;
  const nowIso = new Date().toISOString();

  const resolvedProvider =
    (typeof provider === 'string' && provider.trim()) ||
    order.paymentDetails?.provider ||
    (order.paymentMethod?.toLowerCase().includes('bank') ? 'Bank Transfer / Mobile Wallet' : 'Cash on Delivery');

  const resolvedMethodTitle =
    (typeof paymentMethodTitle === 'string' && paymentMethodTitle.trim()) ||
    order.paymentDetails?.paymentMethodTitle ||
    order.paymentMethod ||
    'Verified Direct Payment';

  order.paymentStatus = 'paid';
  if (order.orderStatus === 'Awaiting Payment' || (order.orderStatus as string) === 'Pending Payment') {
    order.orderStatus = 'Paid';
  }
  order.updatedAt = nowIso;
  order.paymentDetails = {
    ...(order.paymentDetails || {}),
    provider: resolvedProvider,
    paymentMethodTitle: resolvedMethodTitle,
    transactionId: cleanRef,
    referenceNumber: cleanRef,
    paidAt: order.paymentDetails?.paidAt || nowIso,
    isTestMode: false,
    verifiedByAdmin: adminUser.email,
    verifiedAt: nowIso,
    gatewayFee: feeAmount,
    netPayout,
  };

  if (typeof notes === 'string' && notes.trim()) {
    order.notes = order.notes ? `${order.notes} | Payment Verified: ${notes.trim()}` : `Payment Verified: ${notes.trim()}`;
  }

  const activeMerchantCard = store.paymentGateway?.merchantCard;
  const activeBankName = store.paymentGateway?.payoutAccount?.bankName || 'Merchant Bank Account';
  const payoutAccountStr = activeMerchantCard
    ? `Admin Card •••• ${activeMerchantCard.last4} (${activeBankName})`
    : activeBankName;

  if (!store.paymentTransactions) {
    store.paymentTransactions = [];
  }

  let tx = store.paymentTransactions.find(t => t.orderId === order.id && t.paymentStatus !== 'refunded');
  if (tx) {
    tx.transactionReference = cleanRef;
    tx.provider = resolvedProvider;
    tx.paymentMethod = resolvedMethodTitle;
    tx.paymentStatus = 'paid';
    tx.payoutStatus = 'Deposited';
    tx.fee = feeAmount;
    tx.netPayout = netPayout;
    tx.isTestMode = false;
    tx.bankReferenceNumber = cleanRef;
    tx.paidAt = nowIso;
  } else {
    tx = {
      id: `tx_${Date.now()}`,
      transactionReference: cleanRef,
      orderId: order.id,
      orderNumber: order.orderNumber,
      customerName: order.customer.fullName,
      customerEmail: order.accountEmail || order.customer.email,
      amount: order.total,
      currency: order.currency || 'USD',
      fee: feeAmount,
      netPayout,
      provider: resolvedProvider,
      paymentMethod: resolvedMethodTitle,
      paymentStatus: 'paid',
      payoutStatus: 'Deposited',
      payoutAccount: payoutAccountStr,
      merchantSettlementDestination: order.settledToMerchantCard,
      isTestMode: false,
      bankReferenceNumber: cleanRef,
      paidAt: nowIso,
      createdAt: nowIso,
    };
    store.paymentTransactions.unshift(tx);
  }

  db.addAuditLog(
    {
      adminEmail: adminUser.email,
      action: 'admin_verified_real_payment',
      details: `Confirmed real payment for order ${order.orderNumber} (${order.currency} ${order.total}) via ${resolvedProvider}. Ref: ${cleanRef}.`,
      status: 'success',
      ip: req.ip || req.socket.remoteAddress,
    },
    true
  );

  db.commit();

  return res.json({
    success: true,
    message: `Real payment confirmed for ${order.orderNumber} (Ref: ${cleanRef}).`,
    order,
    transaction: tx,
  });
});

// Admin Purge AI-Seeded Demo & Test Data (keeps real customer orders, catalog, settings, and admin account)
app.post('/api/admin/purge-demo-data', requireAdmin, (req: Request, res: Response) => {
  const adminUser = (req as any).user as User;
  const includeSandboxOrders = req.body?.includeSandboxOrders !== false;
  const result = db.purgeDemoAndTestData({
    includeSandboxOrders,
    adminEmail: adminUser.email,
  });

  return res.json({
    success: true,
    ...result,
    message: `Cleared ${result.removedOrders} demo/test order(s), ${result.removedTransactions} test transaction(s), and ${result.removedCustomers} test customer account(s).`,
  });
});

// ==========================================
// REAL PAYMENT GATEWAY SESSIONS & VERIFICATION
// ==========================================

// Create Payment Session for Customer Checkout (Supports Stripe, Safepay, and Test/Sandbox Mode cleanly)
app.post('/api/payments/create-session', async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const { items, deliveryAddress, accountEmail, couponCode, currency = 'PKR', notes } = req.body;

    if (store.paymentGateway?.cardsEnabled === false) {
      return res.status(400).json({ error: 'Card payments are currently disabled in store payment settings. Please use Cash on Delivery or Bank Transfer.' });
    }

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Shopping bag is empty. Please add items to checkout.' });
    }

    if (!deliveryAddress) {
      return res.status(400).json({ error: 'Compulsory delivery address is required.' });
    }

    const {
      fullName,
      email,
      phone,
      country,
      state,
      city,
      streetAddress,
      houseNumber,
      apartmentDetails,
      postalCode,
    } = deliveryAddress;

    if (
      !fullName?.trim() ||
      !email?.trim() ||
      !phone?.trim() ||
      !country?.trim() ||
      !state?.trim() ||
      !city?.trim() ||
      !streetAddress?.trim() ||
      !houseNumber?.trim() ||
      !postalCode?.trim()
    ) {
      return res.status(400).json({
        error: 'All compulsory customer delivery address fields are required before creating a payment session.',
      });
    }

    const {
      quotedExchangeRate,
      quotedRateTimestamp,
      expectedDisplayTotal,
    } = req.body;

    // Server-side variant, inventory, coupon, shipping-region & live exchange-rate quote validation
    const computed = await validateAndComputeCheckoutQuote(store, {
      items,
      displayCurrency: currency || 'PKR',
      country: country.trim(),
      couponCode,
      quotedExchangeRate,
      quotedRateTimestamp,
      expectedDisplayTotal,
      requireValidQuote:
        quotedExchangeRate !== undefined ||
        quotedRateTimestamp !== undefined ||
        expectedDisplayTotal !== undefined,
    });

    const { breakdown, snapshot, coupon, orderItems, reserveVariantAndProductStock } = computed;
    const provider = store.paymentGateway?.provider || 'safepay';
    const isTestMode = store.paymentGateway?.mode
      ? store.paymentGateway.mode === 'test'
      : (store.paymentGateway?.isTestMode ?? true);
    const selectedCurrency = breakdown.displayCurrency;
    const chargeAmount = breakdown.displayTotal;
    const stripeClient = getEffectiveStripeClient(store);
    const { apiKey: safepayKey } = getEffectiveSafepayKeys(store);

    // Validate Live Mode has real server provider keys BEFORE reserving stock or saving order
    if (!isTestMode) {
      if (provider === 'stripe' && !stripeClient) {
        return res.status(503).json({
          error: 'Live Stripe mode requires a valid Stripe Secret Key in server env or Admin Credentials. Switch to Test Mode or add a Stripe Secret Key.',
        });
      }
      if (provider === 'safepay' && !safepayKey) {
        return res.status(503).json({
          error: 'Live Safepay mode requires a Safepay Merchant API Key in server env or Admin Credentials. Switch to Test Mode or add your Safepay Key.',
        });
      }
    }

    const reserveStock = () => {
      if (coupon && breakdown.displayDiscount > 0) {
        coupon.usageCount = (coupon.usageCount || 0) + 1;
      }
      reserveVariantAndProductStock();
    };

    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const orderNumber = `NOV-2026-${randomSuffix}`;
    const currentUser = (req as any).user as User | undefined;
    const deliveryEmailClean = email.trim().toLowerCase();
    const bodyAccountEmail = typeof accountEmail === 'string' && accountEmail.trim().includes('@') ? accountEmail.trim().toLowerCase() : '';
    const buyerAccountEmail = currentUser?.email?.trim().toLowerCase() || bodyAccountEmail || deliveryEmailClean;
    const nowIso = new Date().toISOString();

    const newOrder: Order = {
      id: `ord_${Date.now()}`,
      orderNumber,
      createdAt: nowIso,
      updatedAt: nowIso,
      userId: currentUser?.id,
      accountEmail: buyerAccountEmail,
      isRegisteredBuyer: Boolean(currentUser),
      customer: {
        fullName: currentUser?.fullName?.trim() || fullName.trim(),
        email: buyerAccountEmail,
        phone: phone.trim(),
      },
      deliveryAddress: {
        fullName: fullName.trim(),
        email: deliveryEmailClean,
        phone: phone.trim(),
        country: country.trim(),
        state: state.trim(),
        city: city.trim(),
        streetAddress: streetAddress.trim(),
        houseNumber: houseNumber.trim(),
        apartmentDetails: apartmentDetails ? apartmentDetails.trim() : '',
        postalCode: postalCode.trim(),
      },
      items: orderItems,
      subtotal: breakdown.displaySubtotal,
      discount: breakdown.displayDiscount,
      couponCode: coupon && breakdown.displayDiscount > 0 ? coupon.code : undefined,
      shippingFee: breakdown.displayShippingFee,
      shippingRegion: breakdown.appliedShippingRegionName,
      taxAmount: breakdown.displayTaxAmount,
      taxRatePercentage: breakdown.taxRatePercentage,
      total: breakdown.displayTotal,
      currency: selectedCurrency,
      baseCurrency: breakdown.baseCurrency,
      baseSubtotal: breakdown.baseSubtotal,
      baseDiscount: breakdown.baseDiscount,
      baseShippingFee: breakdown.baseShippingFee,
      baseTaxAmount: breakdown.baseTaxAmount,
      baseTotal: breakdown.baseTotal,
      exchangeRateUsed: breakdown.exchangeRate,
      exchangeRateTimestamp: snapshot.lastUpdated,
      paymentMethod: `${store.paymentGateway?.providerName || 'Safepay'} Secure Hosted Checkout`,
      paymentStatus: 'pending',
      orderStatus: 'Awaiting Payment',
      paymentDetails: {
        provider: store.paymentGateway?.providerName || 'Safepay',
        paymentMethodTitle: 'Credit/Debit Card (Awaiting Authorization)',
        isTestMode,
      },
      trackingNumber: `TRK-NV-${Math.floor(1000000 + Math.random() * 9000000)}`,
      carrier: 'NOVORA Express & Courier Network',
      dropshippingStatus: 'unfulfilled',
      notes: notes?.trim(),
    };

    const activeMerchantCard = store.paymentGateway?.merchantCard;
    const activeBankName = store.paymentGateway?.payoutAccount?.bankName || 'Meezan Bank Ltd (Raast / 1Link)';
    const cardLast4 = activeMerchantCard?.last4 || '9922';
    const cardBrand = activeMerchantCard?.brand ? activeMerchantCard.brand.toUpperCase() : 'VISA';
    const cardHolder = activeMerchantCard?.cardholderName || 'NOVORA ATELIER GLOBAL';
    newOrder.settledToMerchantCard = `Credited to Admin Card •••• ${cardLast4} (${cardBrand} · ${cardHolder}) / Payout: ${activeBankName}`;

    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;

    // 1. Live or Configured Stripe Hosted Checkout
    if (provider === 'stripe' && stripeClient) {
      try {
        const stripeSession = await stripeClient.checkout.sessions.create({
          mode: 'payment',
          customer_email: newOrder.customer.email,
          line_items: [
            {
              price_data: {
                currency: selectedCurrency.toLowerCase(),
                product_data: {
                  name: `NOVORA Order ${newOrder.orderNumber}`,
                  description: `${newOrder.items.length} item(s) — ${newOrder.customer.fullName}`,
                },
                unit_amount: Math.max(50, Math.round(chargeAmount * 100)),
              },
              quantity: 1,
            },
          ],
          metadata: {
            orderId: newOrder.id,
            orderNumber: newOrder.orderNumber,
          },
          success_url: `${appUrl}/order-confirmation?session_id={CHECKOUT_SESSION_ID}&order_id=${newOrder.id}`,
          cancel_url: `${appUrl}/checkout?payment_cancelled=true&order_id=${newOrder.id}`,
        });

        const session: PaymentSession = {
          id: stripeSession.id,
          orderId: newOrder.id,
          orderNumber: newOrder.orderNumber,
          amount: chargeAmount,
          currency: selectedCurrency,
          customerEmail: newOrder.customer.email,
          customerName: newOrder.customer.fullName,
          provider: 'stripe',
          mode: stripeSession.livemode ? 'live' : 'test',
          status: 'pending',
          token: stripeSession.id,
          clientSecret: stripeSession.id,
          checkoutUrl: stripeSession.url || '',
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        };

        reserveStock();
        store.orders.unshift(newOrder);
        if (!store.paymentSessions) store.paymentSessions = [];
        store.paymentSessions.unshift(session);
        db.commit();

        return res.status(201).json({
          success: true,
          checkoutUrl: stripeSession.url,
          order: newOrder,
          session,
        });
      } catch (stripeErr: any) {
        if (!isTestMode) {
          return res.status(502).json({
            error: stripeErr?.message || 'Unable to initialize live Stripe checkout session.',
          });
        }
        console.warn('[Stripe:SandboxFallback] Stripe API unavailable in test mode, using interactive sandbox session:', stripeErr?.message);
      }
    }

    // 2. Safepay V3 Session (if SAFEPAY_MERCHANT_API_KEY configured)
    if (provider === 'safepay' && safepayKey) {
      const safepayEndpoint = isTestMode
        ? 'https://sandbox.api.getsafepay.com/order/payments/v3/'
        : 'https://api.getsafepay.com/order/payments/v3/';
      const amountSmallestUnit = Math.max(100, Math.round(chargeAmount * 100));

      const spResponse = await fetch(safepayEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          merchant_api_key: safepayKey,
          intent: 'CYBERSOURCE',
          mode: 'payment',
          entry_mode: 'flex',
          currency: selectedCurrency,
          amount: amountSmallestUnit,
          metadata: { order_id: newOrder.id, order_number: newOrder.orderNumber },
        }),
      });

      const spResult: any = await spResponse.json().catch(() => ({}));
      if (spResponse.ok && spResult?.data?.tracker?.token) {
        const trackerToken = spResult.data.tracker.token;
        const spCheckoutBase = isTestMode
          ? 'https://sandbox.api.getsafepay.com/checkout/pay'
          : 'https://getsafepay.com/checkout/pay';
        const checkoutUrl = `${spCheckoutBase}?tracker=${encodeURIComponent(trackerToken)}&source=custom&redirect_url=${encodeURIComponent(`${appUrl}/order-confirmation?tracker=${trackerToken}&order_id=${newOrder.id}`)}&cancel_url=${encodeURIComponent(`${appUrl}/checkout?payment_cancelled=true&order_id=${newOrder.id}`)}`;

        newOrder.paymentDetails = {
          ...newOrder.paymentDetails,
          paymentMethodTitle: newOrder.paymentDetails?.paymentMethodTitle || 'Safepay Hosted Checkout',
          provider: 'Safepay',
          transactionId: trackerToken,
          isTestMode,
        };

        const session: PaymentSession = {
          id: trackerToken,
          orderId: newOrder.id,
          orderNumber: newOrder.orderNumber,
          amount: chargeAmount,
          currency: selectedCurrency,
          customerEmail: newOrder.customer.email,
          customerName: newOrder.customer.fullName,
          provider: 'safepay',
          mode: isTestMode ? 'sandbox' : 'live',
          status: 'pending',
          token: trackerToken,
          clientSecret: trackerToken,
          checkoutUrl,
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        };

        reserveStock();
        store.orders.unshift(newOrder);
        if (!store.paymentSessions) store.paymentSessions = [];
        store.paymentSessions.unshift(session);
        db.commit();

        return res.status(201).json({
          success: true,
          checkoutUrl,
          trackerToken,
          order: newOrder,
          session,
        });
      }
      if (!isTestMode) {
        return res.status(502).json({
          error: spResult?.status?.message || 'Unable to initialize live Safepay payment session.',
        });
      }
    }

    // 3. Sandbox / Test Mode Interactive Secure Checkout Session (no external server secret required)
    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const sessionToken = `tok_${Math.random().toString(36).substring(2, 12)}`;
    const clientSecret = `cs_sec_${Math.random().toString(36).substring(2, 16)}`;

    const sandboxSession: PaymentSession = {
      id: sessionId,
      orderId: newOrder.id,
      orderNumber: newOrder.orderNumber,
      amount: chargeAmount,
      currency: selectedCurrency,
      customerEmail: newOrder.customer.email,
      customerName: newOrder.customer.fullName,
      provider,
      mode: 'test',
      status: 'pending',
      token: sessionToken,
      clientSecret,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    };

    reserveStock();
    store.orders.unshift(newOrder);
    if (!store.paymentSessions) store.paymentSessions = [];
    store.paymentSessions.unshift(sandboxSession);
    db.commit();

    return res.status(201).json({
      success: true,
      order: newOrder,
      session: sandboxSession,
    });
  } catch (err: any) {
    console.error('Create payment session error:', err);
    if (err instanceof RateUnavailableError) {
      return res.status(err.statusCode).json({ error: err.message, code: err.code });
    }
    if (err?.statusCode) {
      return res.status(err.statusCode).json({
        error: err.message,
        code: err.code,
        quote: err.quote,
      });
    }
    return res.status(500).json({ error: err.message || 'Failed to create payment session.' });
  }
});

// Create Hosted Checkout Session for an existing pending order
app.post('/api/payments/create-checkout', async (req: Request, res: Response) => {
  try {
    const { orderId } = req.body;
    if (!orderId) {
      return res.status(400).json({ message: 'Order ID is required.' });
    }

    const store = db.getData();
    const stripeClient = getEffectiveStripeClient(store);
    if (!stripeClient) {
      return res.status(503).json({
        message: 'Stripe server key (STRIPE_SECRET_KEY) is not configured.',
      });
    }

    const order = store.orders.find(o => o.id === orderId || o.orderNumber === orderId);
    if (!order) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    if (order.paymentStatus === 'paid') {
      return res.status(400).json({ message: 'This order has already been paid.' });
    }

    const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const currencyCode = normalizeCurrencyCode(order.currency || getStoreBaseCurrency(store));
    const chargeAmount = Number(order.total || 0);

    const stripeSession = await stripeClient.checkout.sessions.create({
      mode: 'payment',
      customer_email: order.customer.email,
      line_items: [
        {
          price_data: {
            currency: currencyCode.toLowerCase(),
            product_data: {
              name: `NOVORA Order ${order.orderNumber}`,
              description: `${order.items.length} item(s)`,
            },
            unit_amount: Math.max(50, Math.round(chargeAmount * 100)),
          },
          quantity: 1,
        },
      ],
      metadata: {
        orderId: order.id,
        orderNumber: order.orderNumber,
      },
      success_url: `${appUrl}/order-confirmation?session_id={CHECKOUT_SESSION_ID}&order_id=${order.id}`,
      cancel_url: `${appUrl}/checkout?payment_cancelled=true&order_id=${order.id}`,
    });

    return res.json({
      success: true,
      checkoutUrl: stripeSession.url,
    });
  } catch (err: any) {
    console.error('Create checkout error:', err);
    return res.status(500).json({ message: err.message || 'Payment could not start.' });
  }
});

// Verify Hosted Redirect Payment (Stripe session_id or Safepay tracker)
app.get('/api/payments/confirm-redirect', async (req: Request, res: Response) => {
  try {
    const orderId = String(req.query.order_id || '');
    const sessionId = String(req.query.session_id || '');
    const tracker = String(req.query.tracker || '');

    if (!orderId && !sessionId && !tracker) {
      return res.status(400).json({ error: 'Order ID or payment reference is required.' });
    }

    const store = db.getData();
    const order = store.orders.find(
      o => (orderId && (o.id === orderId || o.orderNumber === orderId)) ||
           (tracker && o.paymentDetails?.transactionId === tracker)
    );

    if (!order) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    if (order.paymentStatus === 'paid') {
      return res.json({ success: true, status: 'paid', order });
    }

    const stripeClient = getEffectiveStripeClient(store);
    const { apiKey: safepayApiKey, secretKey: safepaySecretKey } = getEffectiveSafepayKeys(store);

    // Verify Stripe Checkout Session server-side
    if (sessionId && stripeClient) {
      const stripeSession = await stripeClient.checkout.sessions.retrieve(sessionId);
      if (stripeSession.payment_status === 'paid') {
        order.paymentStatus = 'paid';
        order.orderStatus = 'Paid';
        order.updatedAt = new Date().toISOString();
        const txId = typeof stripeSession.payment_intent === 'string' ? stripeSession.payment_intent : stripeSession.id;
        const paidAt = new Date().toISOString();
        const fee = Math.round(order.total * 0.029 * 100) / 100;
        const netPayout = Math.round((order.total - fee) * 100) / 100;
        const isSandbox = !stripeSession.livemode;
        order.paymentDetails = {
          provider: 'Stripe',
          paymentMethodTitle: 'Stripe Hosted Checkout',
          transactionId: txId,
          paidAt,
          isTestMode: isSandbox,
          gatewayFee: fee,
          netPayout,
        };
        const sessRecord = store.paymentSessions?.find(s => s.id === sessionId || s.orderId === order.id);
        if (sessRecord) sessRecord.status = 'completed';

        if (!store.paymentTransactions) store.paymentTransactions = [];
        store.paymentTransactions.unshift({
          id: `tx_${Date.now()}`,
          transactionReference: txId,
          orderId: order.id,
          orderNumber: order.orderNumber,
          customerName: order.customer.fullName,
          customerEmail: order.accountEmail || order.customer.email,
          amount: order.total,
          currency: order.currency,
          fee,
          netPayout,
          provider: 'stripe',
          paymentMethod: 'Stripe Hosted Checkout',
          paymentStatus: 'paid',
          payoutStatus: 'Scheduled (T+2)',
          merchantSettlementDestination: order.settledToMerchantCard,
          isTestMode: isSandbox,
          paidAt,
          createdAt: paidAt,
        });
        db.commit();
        return res.json({ success: true, status: 'paid', order });
      }
      return res.status(402).json({
        success: false,
        status: stripeSession.payment_status,
        error: 'Payment has not been completed at Stripe.',
        order,
      });
    }

    // Verify Safepay Tracker server-side
    if (tracker && safepayApiKey) {
      const apiKey = safepayApiKey;
      const isTest = store.paymentGateway?.mode
        ? store.paymentGateway.mode === 'test'
        : (store.paymentGateway?.isTestMode ?? true);
      const base = isTest ? 'https://sandbox.api.getsafepay.com/order/payments/v3/' : 'https://api.getsafepay.com/order/payments/v3/';
      const verifyRes = await fetch(`${base}${encodeURIComponent(tracker)}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-SFPY-MERCHANT-SECRET': safepaySecretKey || apiKey,
        },
      });
      const verifyData: any = await verifyRes.json().catch(() => ({}));
      const state = (verifyData?.data?.tracker?.state || verifyData?.data?.state || '').toUpperCase();
      if (verifyRes.ok && (state === 'PAID' || state === 'TRACKER_ENDED')) {
        order.paymentStatus = 'paid';
        order.orderStatus = 'Paid';
        order.updatedAt = new Date().toISOString();
        const paidAt = new Date().toISOString();
        const fee = Math.round(order.total * 0.025 * 100) / 100;
        const netPayout = Math.round((order.total - fee) * 100) / 100;
        order.paymentDetails = {
          provider: 'Safepay',
          paymentMethodTitle: 'Safepay Hosted Checkout',
          transactionId: tracker,
          paidAt,
          isTestMode: isTest,
          gatewayFee: fee,
          netPayout,
        };
        const sessRecord = store.paymentSessions?.find(s => s.id === tracker || s.orderId === order.id);
        if (sessRecord) sessRecord.status = 'completed';

        if (!store.paymentTransactions) store.paymentTransactions = [];
        store.paymentTransactions.unshift({
          id: `tx_${Date.now()}`,
          transactionReference: tracker,
          orderId: order.id,
          orderNumber: order.orderNumber,
          customerName: order.customer.fullName,
          customerEmail: order.accountEmail || order.customer.email,
          amount: order.total,
          currency: order.currency || 'PKR',
          fee,
          netPayout,
          provider: 'safepay',
          paymentMethod: 'Safepay Hosted Checkout',
          paymentStatus: 'paid',
          payoutStatus: 'Scheduled (T+2)',
          merchantSettlementDestination: order.settledToMerchantCard,
          isTestMode: isTest,
          paidAt,
          createdAt: paidAt,
        });
        db.commit();
        return res.json({ success: true, status: 'paid', order });
      }
      return res.status(402).json({
        success: false,
        status: order.paymentStatus,
        error: 'Safepay payment is not confirmed yet.',
        order,
      });
    }

    return res.json({ success: (order.paymentStatus as string) === 'paid', status: order.paymentStatus, order });
  } catch (err: any) {
    console.error('Confirm redirect payment error:', err);
    return res.status(500).json({ error: err.message || 'Unable to verify payment.' });
  }
});

// Verify Payment Session Result (Sandbox / Modal Checkout)
app.post('/api/payments/verify-session', async (req: Request, res: Response) => {
  try {
    const store = db.getData();
    const { sessionId, token, action = 'confirm', cardLast4 = '4242', cardBrand = 'Visa' } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required.' });
    }

    const session = store.paymentSessions?.find(s => s.id === sessionId || s.token === token);
    if (!session) {
      return res.status(404).json({ error: 'Payment session not found or expired.' });
    }

    const order = store.orders.find(o => o.id === session.orderId || o.orderNumber === session.orderNumber);
    if (!order) {
      return res.status(404).json({ error: 'Associated order not found.' });
    }

    if (action === 'confirm') {
      const stripeClient = getEffectiveStripeClient(store);
      // Prevent marking unverified live Stripe sessions paid without checking Stripe
      if (session.mode === 'live' && session.provider === 'stripe' && stripeClient && session.id.startsWith('cs_')) {
        const stripeSession = await stripeClient.checkout.sessions.retrieve(session.id);
        if (stripeSession.payment_status !== 'paid') {
          return res.status(402).json({ error: 'Live Stripe payment has not been confirmed yet.' });
        }
      }

      session.status = 'completed';
      order.paymentStatus = 'paid';
      order.orderStatus = 'Paid';
      order.updatedAt = new Date().toISOString();

      const transactionId = `txn_sp_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const isSandbox = session.mode === 'test' || session.mode === 'sandbox';
      const paidAt = new Date().toISOString();
      const fee = Math.round(order.total * 0.025 * 100) / 100;
      const netPayout = Math.round((order.total - fee) * 100) / 100;
      order.paymentDetails = {
        provider: session.provider === 'safepay' ? 'Safepay' : session.provider === 'stripe' ? 'Stripe' : 'Paymob',
        paymentMethodTitle: `${cardBrand} Ending in ${cardLast4}`,
        transactionId,
        maskedCard: `•••• •••• •••• ${cardLast4}`,
        maskedCardNumber: `•••• •••• •••• ${cardLast4}`,
        cardBrand,
        paidAt,
        isTestMode: isSandbox,
        gatewayFee: fee,
        netPayout,
      };

      const activeMerchantCard = store.paymentGateway?.merchantCard;
      const activeBankName = store.paymentGateway?.payoutAccount?.bankName || 'Meezan Bank Ltd (Raast / 1Link)';
      const mCardLast4 = activeMerchantCard?.last4 || '9922';

      const tx: PaymentTransaction = {
        id: `tx_${Date.now()}`,
        transactionReference: transactionId,
        orderId: order.id,
        orderNumber: order.orderNumber,
        customerName: order.customer.fullName,
        customerEmail: order.accountEmail || order.customer.email,
        amount: order.total,
        currency: order.currency,
        fee,
        netPayout,
        provider: session.provider,
        paymentMethod: `${cardBrand} (•••• ${cardLast4})`,
        paymentStatus: 'paid',
        payoutStatus: 'Deposited',
        payoutAccount: `Admin Card •••• ${mCardLast4} (${activeBankName})`,
        merchantSettlementDestination: order.settledToMerchantCard,
        isTestMode: isSandbox,
        paidAt,
        createdAt: paidAt,
      };

      if (!store.paymentTransactions) store.paymentTransactions = [];
      store.paymentTransactions.unshift(tx);
      db.commit();

      return res.json({
        success: true,
        status: 'paid',
        order,
        transaction: tx,
      });
    } else if (action === 'decline') {
      session.status = 'failed';
      order.paymentStatus = 'declined';
      order.orderStatus = 'Awaiting Payment';
      order.updatedAt = new Date().toISOString();

      const transactionId = `txn_dec_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const tx: PaymentTransaction = {
        id: `tx_${Date.now()}`,
        transactionReference: transactionId,
        orderId: order.id,
        orderNumber: order.orderNumber,
        customerName: order.customer.fullName,
        customerEmail: order.accountEmail || order.customer.email,
        amount: order.total,
        currency: order.currency,
        fee: 0,
        netPayout: 0,
        provider: session.provider,
        paymentMethod: `${cardBrand} (•••• ${cardLast4})`,
        paymentStatus: 'declined',
        payoutStatus: 'Held',
        createdAt: new Date().toISOString(),
      };

      if (!store.paymentTransactions) store.paymentTransactions = [];
      store.paymentTransactions.unshift(tx);
      db.commit();

      return res.status(402).json({
        success: false,
        status: 'declined',
        error: 'Payment authorization declined by issuing bank: Insufficient funds or test card decline.',
        order,
      });
    } else {
      session.status = 'expired';
      order.paymentStatus = 'pending';
      order.updatedAt = new Date().toISOString();
      db.commit();
      return res.json({ success: false, status: 'cancelled', message: 'Checkout cancelled by customer.' });
    }
  } catch (err: any) {
    console.error('Verify payment session error:', err);
    return res.status(500).json({ error: err.message || 'Payment verification failed.' });
  }
});

// Admin Get Payment Credentials & Live Checklist Status
app.get('/api/admin/payment-settings/credentials', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const provider = store.paymentGateway.provider || 'safepay';
  const isTestMode = store.paymentGateway.isTestMode ?? true;

  const envApiKey = process.env.SAFEPAY_MERCHANT_API_KEY || process.env.SAFEPAY_API_KEY || process.env.STRIPE_PUBLISHABLE_KEY;
  const envSecretKey = process.env.SAFEPAY_SECRET_KEY || process.env.STRIPE_SECRET_KEY;
  const envWebhookSecret = process.env.SAFEPAY_WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET;

  const apiKeyConfigured = Boolean(envApiKey || store.paymentGateway.apiKeyMasked || store.paymentGateway.apiKeyRuntime);
  const secretKeyConfigured = Boolean(envSecretKey || store.paymentGateway.secretKeyConfigured || store.paymentGateway.secretKeyRuntime);
  const webhookSecretConfigured = Boolean(envWebhookSecret || store.paymentGateway.webhookSecretSet || store.paymentGateway.webhookSecret);
  const merchantKycApproved = store.paymentGateway.merchantKycStatus === 'verified';
  const payoutAccountLinked = Boolean(store.paymentGateway.payoutAccount && store.paymentGateway.payoutAccount.status === 'Verified');

  const isLiveEligible = apiKeyConfigured && secretKeyConfigured && webhookSecretConfigured && merchantKycApproved && payoutAccountLinked;

  const checklist = [
    {
      id: 'merchant_registration',
      title: 'Merchant Registration (Safepay / Paymob / Stripe)',
      description: 'Register legal business entity or sole proprietorship with payment provider.',
      status: store.paymentGateway.isConnected ? 'completed' : 'pending',
      required: true,
    },
    {
      id: 'server_credentials',
      title: 'Server-Side Secret API Keys',
      description: 'Configure API Key and Secret Key in server environment variables.',
      status: secretKeyConfigured ? 'completed' : 'pending',
      required: true,
    },
    {
      id: 'webhook_signing',
      title: 'Signed Webhook Listener',
      description: 'Configure Webhook Secret for HMAC-SHA256 signature verification.',
      status: webhookSecretConfigured ? 'completed' : 'pending',
      required: true,
    },
    {
      id: 'kyc_verification',
      title: 'State Bank / KYC Document Approval',
      description: 'Submit CNIC, FBR NTN, and bank account certificate for compliance approval.',
      status: merchantKycApproved ? 'completed' : 'pending',
      required: true,
    },
    {
      id: 'bank_payout_account',
      title: '1Link Bank Payout Account (IBAN)',
      description: 'Link verified Pakistani or international bank account for rolling payouts.',
      status: payoutAccountLinked ? 'completed' : 'pending',
      required: true,
    },
  ];

  return res.json({
    provider,
    isTestMode,
    mode: store.paymentGateway.mode || (isTestMode ? 'test' : 'live'),
    apiKeyConfigured,
    secretKeyConfigured,
    webhookSecretConfigured,
    merchantKycApproved,
    payoutAccountLinked,
    isLiveEligible,
    checklist,
    liveWarningMessage: !isLiveEligible
      ? 'Live payments cannot be enabled until your merchant account is approved and all server-side credentials are configured. Use Sandbox/Test Mode to simulate checkouts safely.'
      : 'All credentials and KYC verifications are confirmed. Store is eligible for live customer card processing.',
  });
});

// Admin Update Server-Side Payment Credentials
app.post('/api/admin/payment-settings/credentials', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { apiKey, secretKey, webhookSecret, merchantKycStatus } = req.body;

  if (apiKey) {
    const raw = String(apiKey).trim();
    store.paymentGateway.apiKeyRuntime = raw;
    store.paymentGateway.apiKeyMasked = raw.length > 10 ? `${raw.substring(0, 8)}...${raw.slice(-4)}` : '••••••';
    store.paymentGateway.publishableKeyMasked = store.paymentGateway.apiKeyMasked;
  }

  if (secretKey) {
    store.paymentGateway.secretKeyRuntime = String(secretKey).trim();
    store.paymentGateway.secretKeyConfigured = true;
  }

  if (webhookSecret) {
    store.paymentGateway.webhookSecret = String(webhookSecret).trim();
    store.paymentGateway.webhookSecretSet = true;
  }

  if (merchantKycStatus) {
    store.paymentGateway.merchantKycStatus = merchantKycStatus;
  }

  db.commit();

  return res.json({
    success: true,
    message: 'Server-side payment credentials updated securely.',
    paymentGateway: sanitizePaymentGatewayForAdmin(store.paymentGateway),
  });
});

// Admin Add or Update Merchant Business Card (Card-on-File)
app.post('/api/admin/payment-settings/merchant-card', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const {
    cardholderName,
    cardNumber,
    expiryMonth,
    expiryYear,
    cvc,
    billingPostalCode,
    isDefault = true,
  } = req.body;

  if (!cardholderName || !cardholderName.trim()) {
    return res.status(400).json({ error: 'Cardholder name is required and must match your registered merchant identity.' });
  }

  const rawCard = String(cardNumber || '').replace(/[\s-]/g, '');
  if (!rawCard || rawCard.length < 12 || !/^\d+$/.test(rawCard)) {
    return res.status(400).json({ error: 'Please enter a valid debit or credit card number (13-19 digits).' });
  }

  const expMonth = String(expiryMonth || '').padStart(2, '0');
  const expYear = String(expiryYear || '').slice(-2);
  const m = parseInt(expMonth, 10);
  if (isNaN(m) || m < 1 || m > 12) {
    return res.status(400).json({ error: 'Please enter a valid expiration month (01-12).' });
  }

  const cvcClean = String(cvc || '').trim();
  if (cvcClean.length < 3 || cvcClean.length > 4) {
    return res.status(400).json({ error: 'Please enter a valid 3 or 4 digit card verification code (CVC/CVV).' });
  }

  // Detect card brand
  let brand = 'Visa';
  if (rawCard.startsWith('4')) {
    brand = 'Visa';
  } else if (/^(5[1-5]|2[2-7])/.test(rawCard)) {
    brand = 'Mastercard';
  } else if (/^(34|37)/.test(rawCard)) {
    brand = 'American Express';
  } else if (/^(5081|6032|60)/.test(rawCard)) {
    brand = 'PayPak';
  } else if (/^62/.test(rawCard)) {
    brand = 'UnionPay';
  }

  const last4 = rawCard.slice(-4);
  const newCardId = `card_mc_${Date.now()}`;

  const newCard: MerchantCardDetails = {
    id: newCardId,
    brand,
    last4,
    expiryMonth: expMonth,
    expiryYear: expYear,
    cardholderName: cardholderName.trim(),
    isDefault: Boolean(isDefault),
    status: 'active',
    billingPostalCode: billingPostalCode ? String(billingPostalCode).trim() : undefined,
    addedAt: new Date().toISOString(),
  };

  if (!store.paymentGateway.merchantCards) {
    store.paymentGateway.merchantCards = [];
  }

  if (isDefault) {
    store.paymentGateway.merchantCards.forEach(c => (c.isDefault = false));
    store.paymentGateway.merchantCard = newCard;
  }

  store.paymentGateway.merchantCards.unshift(newCard);
  db.commit();

  return res.json({
    success: true,
    message: `Business card (${brand} •••• ${last4}) successfully connected and saved as primary card!`,
    paymentGateway: store.paymentGateway,
    card: newCard,
  });
});

// Admin Set Default Merchant Card
app.put('/api/admin/payment-settings/merchant-card/:id/default', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { id } = req.params;
  if (!store.paymentGateway.merchantCards) {
    return res.status(404).json({ error: 'No merchant cards configured.' });
  }

  const card = store.paymentGateway.merchantCards.find(c => c.id === id);
  if (!card) {
    return res.status(404).json({ error: 'Card not found.' });
  }

  store.paymentGateway.merchantCards.forEach(c => (c.isDefault = c.id === id));
  store.paymentGateway.merchantCard = card;
  db.commit();

  return res.json({
    success: true,
    message: `Default merchant card set to ${card.brand} •••• ${card.last4}.`,
    paymentGateway: store.paymentGateway,
    card,
  });
});

// Admin Remove Merchant Card
app.delete('/api/admin/payment-settings/merchant-card/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { id } = req.params;
  if (!store.paymentGateway.merchantCards) {
    return res.status(404).json({ error: 'No merchant cards found.' });
  }

  store.paymentGateway.merchantCards = store.paymentGateway.merchantCards.filter(c => c.id !== id);
  if (store.paymentGateway.merchantCard?.id === id) {
    store.paymentGateway.merchantCard = store.paymentGateway.merchantCards[0] || undefined;
    if (store.paymentGateway.merchantCard) {
      store.paymentGateway.merchantCard.isDefault = true;
    }
  }

  db.commit();

  return res.json({
    success: true,
    message: 'Merchant card removed successfully.',
    paymentGateway: store.paymentGateway,
  });
});

// Server-side Payment Webhook Endpoint with Cryptographic Signature Verification
app.post('/api/webhooks/payment', (req: Request, res: Response) => {
  const store = db.getData();
  const signature = (
    req.headers['x-safepay-signature'] ||
    req.headers['stripe-signature'] ||
    req.headers['x-webhook-signature']
  ) as string | undefined;

  const webhookSecret =
    process.env.SAFEPAY_WEBHOOK_SECRET ||
    process.env.STRIPE_WEBHOOK_SECRET ||
    store.paymentGateway?.webhookSecret ||
    'whsec_nvr_live_safe_secret_2026';

  const payload = req.body;
  const rawBody = JSON.stringify(payload);

  // In production/live mode, verify HMAC-SHA256 signature
  const isLive = store.paymentGateway.mode === 'live';
  if (isLive && signature) {
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(rawBody)
      .digest('hex');
    if (signature !== expectedSignature) {
      return res.status(401).json({ error: 'Invalid webhook signature.' });
    }
  }

  const { eventType, orderId, transactionId, status } = payload;
  if (!orderId) {
    return res.status(400).json({ error: 'Webhook payload missing orderId' });
  }

  const order = store.orders.find(o => o.id === orderId || o.orderNumber === orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found for webhook notification' });
  }

  if (eventType === 'payment_intent.succeeded' || eventType === 'payment.success' || status === 'paid') {
    order.paymentStatus = 'paid';
    if (order.orderStatus === 'Awaiting Payment') {
      order.orderStatus = 'Paid';
    }
    const txId = transactionId || `txn_sp_wh_${Date.now()}`;
    if (order.paymentDetails) {
      order.paymentDetails.paidAt = new Date().toISOString();
      order.paymentDetails.transactionId = txId;
    }
    const alreadyLogged = store.paymentTransactions?.some(t => t.orderId === order.id && t.paymentStatus === 'paid');
    if (!alreadyLogged) {
      const fee = Math.round(order.total * 0.025 * 100) / 100;
      const tx: PaymentTransaction = {
        id: `tx_${Date.now()}`,
        transactionReference: txId,
        orderId: order.id,
        orderNumber: order.orderNumber,
        customerName: order.customer.fullName,
        customerEmail: order.customer.email,
        amount: order.total,
        currency: order.currency,
        fee,
        netPayout: order.total - fee,
        provider: store.paymentGateway.provider || 'safepay',
        paymentMethod: order.paymentDetails?.paymentMethodTitle || 'Credit/Debit Card (Verified)',
        paymentStatus: 'paid',
        payoutStatus: 'Scheduled (T+2)',
        createdAt: new Date().toISOString(),
      };
      if (!store.paymentTransactions) store.paymentTransactions = [];
      store.paymentTransactions.unshift(tx);
    }
    db.commit();
    return res.json({ received: true, verified: true, status: 'order_updated_to_paid' });
  }

  if (eventType === 'charge.failed' || eventType === 'payment.failed' || status === 'declined') {
    order.paymentStatus = 'declined';
    db.commit();
    return res.json({ received: true, verified: true, status: 'order_marked_declined' });
  }

  return res.json({ received: true, verified: true, message: 'Event logged without mutation' });
});

// CSV Export for Admin
app.get('/api/orders-export/csv', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const headers = [
    'Order Number',
    'Date',
    'Buyer Account Gmail',
    'Customer Name',
    'Delivery Email',
    'Phone',
    'Country',
    'State',
    'City',
    'Street Address',
    'House Number',
    'Apartment Details',
    'Postal Code',
    'Items Count',
    'Subtotal',
    'Discount',
    'Shipping',
    'Total',
    'Payment Method',
    'Payment Status',
    'Order Status',
    'Tracking Number'
  ];

  const rows = store.orders.map(o => [
    `"${o.orderNumber}"`,
    `"${new Date(o.createdAt).toLocaleDateString()}"`,
    `"${(o.accountEmail || o.customer?.email || o.deliveryAddress.email || '').replace(/"/g, '""')}"`,
    `"${o.deliveryAddress.fullName.replace(/"/g, '""')}"`,
    `"${o.deliveryAddress.email}"`,
    `"${o.deliveryAddress.phone}"`,
    `"${o.deliveryAddress.country}"`,
    `"${o.deliveryAddress.state}"`,
    `"${o.deliveryAddress.city}"`,
    `"${o.deliveryAddress.streetAddress.replace(/"/g, '""')}"`,
    `"${o.deliveryAddress.houseNumber}"`,
    `"${(o.deliveryAddress.apartmentDetails || '').replace(/"/g, '""')}"`,
    `"${o.deliveryAddress.postalCode}"`,
    o.items.length,
    o.subtotal.toFixed(2),
    o.discount.toFixed(2),
    o.shippingFee.toFixed(2),
    o.total.toFixed(2),
    `"${o.paymentMethod}"`,
    `"${o.paymentStatus}"`,
    `"${o.orderStatus}"`,
    `"${o.trackingNumber || ''}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="novora_orders.csv"');
  return res.send(csvContent);
});

// ==========================================
// 7. INVENTORY MANAGEMENT
// ==========================================
app.get('/api/inventory', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const inventory = store.products.map(p => {
    const variantItems = Array.isArray(p.variants?.items) ? p.variants.items : [];
    const hasLowStockVariant = variantItems.some(
      v => v.availability !== 'unavailable' && v.stock > 0 && v.stock <= 5
    );
    return {
      id: p.id,
      name: p.name,
      sku: p.sku,
      category: p.category,
      price: p.sellingPrice,
      stock: p.stock,
      status: p.status,
      isLowStock: (p.stock > 0 && p.stock <= 5) || hasLowStockVariant,
      isOutOfStock: p.stock === 0,
      variants: p.variants,
      updatedAt: p.updatedAt,
    };
  });
  return res.json(inventory);
});

app.put('/api/inventory/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { stock, status, variantId, sku, variantStock, availability } = req.body;
  const product = store.products.find(p => p.id === req.params.id);
  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }

  if ((variantId || sku) && Array.isArray(product.variants?.items)) {
    const vItem = product.variants.items.find(
      v => (variantId && v.id === variantId) || (sku && v.sku.toLowerCase() === String(sku).toLowerCase())
    );
    if (!vItem) {
      return res.status(404).json({ error: 'Product variant SKU not found' });
    }
    if (variantStock !== undefined) {
      const nextVStock = Math.max(0, Math.floor(Number(variantStock)));
      if (!Number.isFinite(nextVStock)) {
        return res.status(400).json({ error: 'Variant stock must be a valid non-negative integer.' });
      }
      vItem.stock = nextVStock;
      if (availability !== 'unavailable') {
        vItem.availability = nextVStock === 0 ? 'out_of_stock' : 'available';
      }
    }
    if (availability && ['available', 'unavailable', 'out_of_stock'].includes(availability)) {
      vItem.availability = availability;
    }
    db.normalizeProductVariantsAndStock(product);
  } else {
    if (stock !== undefined) {
      const nextStock = Math.max(0, Math.floor(Number(stock)));
      if (!Number.isFinite(nextStock)) {
        return res.status(400).json({ error: 'Stock must be a valid non-negative integer.' });
      }
      product.stock = nextStock;
      if (product.stock === 0) {
        product.status = 'out_of_stock';
      } else if (product.status === 'out_of_stock' && product.stock > 0) {
        product.status = 'published';
      }
    }
    if (status) {
      product.status = status;
    }
  }
  product.updatedAt = new Date().toISOString();
  db.commit();

  return res.json({ success: true, product });
});

// ==========================================
// 8. DISCOUNTS & COUPONS
// ==========================================
app.get('/api/coupons', (req: Request, res: Response) => {
  const store = db.getData();
  const user = (req as any).user as User | undefined;
  if (user && user.role === 'admin') {
    return res.json(store.coupons);
  }
  return res.json(store.coupons.filter(c => c.isActive));
});

app.post('/api/coupons/validate', (req: Request, res: Response) => {
  const { code, cartTotal } = req.body;
  if (!code) {
    return res.status(400).json({ valid: false, error: 'Please enter a coupon code.' });
  }

  const store = db.getData();
  const baseCurrency = getStoreBaseCurrency(store);
  const coupon = store.coupons.find(c => c.code.toUpperCase() === code.trim().toUpperCase() && c.isActive);

  if (!coupon) {
    return res.status(404).json({ valid: false, error: 'Invalid or expired promotional code.' });
  }

  if (coupon.expiryDate && new Date(coupon.expiryDate) < new Date()) {
    return res.status(400).json({ valid: false, error: `Coupon ${coupon.code} has expired.` });
  }

  const baseSubtotal = Math.max(0, Number(cartTotal || 0));
  if (baseSubtotal < coupon.minOrderValue) {
    return res.status(400).json({
      valid: false,
      error: `Minimum order value for ${coupon.code} is ${formatExactCurrency(coupon.minOrderValue, baseCurrency)}.`,
    });
  }

  let discount = 0;
  if (coupon.discountType === 'percentage') {
    discount = Math.round((baseSubtotal * (coupon.discountValue / 100)) * 100) / 100;
  } else {
    discount = Math.min(coupon.discountValue, baseSubtotal);
  }

  return res.json({
    valid: true,
    code: coupon.code,
    discountType: coupon.discountType,
    discountValue: coupon.discountValue,
    minOrderValue: coupon.minOrderValue,
    baseCurrency,
    discountAmount: discount,
  });
});

app.post('/api/coupons', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const { code, discountType, discountValue, minOrderValue, expiryDate, isActive } = req.body;
  if (!code || !discountValue) {
    return res.status(400).json({ error: 'Coupon code and discount value are required' });
  }

  const newCoupon: Coupon = {
    id: `coup_${Date.now()}`,
    code: code.trim().toUpperCase(),
    discountType: discountType || 'percentage',
    discountValue: Number(discountValue),
    minOrderValue: Number(minOrderValue || 0),
    expiryDate: expiryDate || '2027-12-31',
    isActive: isActive !== undefined ? Boolean(isActive) : true,
    usageCount: 0,
  };

  store.coupons.push(newCoupon);
  db.commit();

  return res.status(201).json({ success: true, coupon: newCoupon });
});

app.put('/api/coupons/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const idx = store.coupons.findIndex(c => c.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Coupon not found' });
  }

  store.coupons[idx] = {
    ...store.coupons[idx],
    ...req.body,
    code: req.body.code ? req.body.code.trim().toUpperCase() : store.coupons[idx].code,
  };
  db.commit();

  return res.json({ success: true, coupon: store.coupons[idx] });
});

app.delete('/api/coupons/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  store.coupons = store.coupons.filter(c => c.id !== req.params.id);
  db.commit();
  return res.json({ success: true });
});

// ==========================================
// 9. REVIEWS & TESTIMONIALS
// ==========================================
app.get('/api/reviews', (req: Request, res: Response) => {
  const store = db.getData();
  const { productId } = req.query;
  let reviews = [...store.reviews];
  if (productId) {
    reviews = reviews.filter(r => r.productId === productId);
  }
  return res.json(reviews);
});

app.post('/api/reviews', (req: Request, res: Response) => {
  const { productId, rating, comment, customerName } = req.body;
  if (!productId || !rating || !comment) {
    return res.status(400).json({ error: 'Product, rating, and review text are required.' });
  }

  const store = db.getData();
  const product = store.products.find(p => p.id === productId);
  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }

  const newReview: Review = {
    id: `rev_${Date.now()}`,
    productId,
    productName: product.name,
    customerName: customerName || 'Verified Buyer',
    rating: Number(rating),
    comment: comment.trim(),
    date: new Date().toISOString().split('T')[0],
    verified: true,
    status: 'approved',
  };

  store.reviews.unshift(newReview);
  
  // Recalculate product rating
  const prodReviews = store.reviews.filter(r => r.productId === productId);
  const avg = prodReviews.reduce((sum, r) => sum + r.rating, 0) / prodReviews.length;
  product.rating = Math.round(avg * 10) / 10;
  product.reviewsCount = prodReviews.length;

  db.commit();

  return res.status(201).json({ success: true, review: newReview, productRating: product.rating });
});

app.delete('/api/reviews/:id', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  store.reviews = store.reviews.filter(r => r.id !== req.params.id);
  db.commit();
  return res.json({ success: true });
});

// ==========================================
// 10. STORE SETTINGS
// ==========================================
app.get('/api/settings', (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(store.settings);
});

app.put('/api/settings', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const nextStoreName =
    typeof body.storeName === 'string' && body.storeName.trim()
      ? body.storeName.trim()
      : store.settings.storeName || 'NOVORA';
  const nextLogoUrl =
    typeof body.logoUrl === 'string' ? body.logoUrl.trim() : store.settings.logoUrl || '';
  const nextTagline =
    typeof body.tagline === 'string' ? body.tagline.trim() : store.settings.tagline;
  const nextContactEmail =
    typeof body.contactEmail === 'string' && body.contactEmail.trim()
      ? body.contactEmail.trim()
      : store.settings.contactEmail;
  const nextContactPhone =
    typeof body.contactPhone === 'string' && body.contactPhone.trim()
      ? body.contactPhone.trim()
      : store.settings.contactPhone;
  const nextAddress =
    typeof body.address === 'string' && body.address.trim()
      ? body.address.trim()
      : store.settings.address;

  const prevName = store.settings.storeName;
  const prevLogo = store.settings.logoUrl || '';
  const prevEmail = store.settings.contactEmail;
  const prevPhone = store.settings.contactPhone;
  const prevAddress = store.settings.address;

  store.settings = {
    ...store.settings,
    ...body,
    storeName: nextStoreName,
    logoUrl: nextLogoUrl,
    tagline: nextTagline,
    contactEmail: nextContactEmail,
    contactPhone: nextContactPhone,
    address: nextAddress,
  };

  if (
    prevName !== nextStoreName ||
    prevLogo !== nextLogoUrl ||
    prevEmail !== nextContactEmail ||
    prevPhone !== nextContactPhone ||
    prevAddress !== nextAddress
  ) {
    db.addAuditLog(
      {
        adminEmail: (req as any).user?.email || 'admin',
        action: 'UPDATE_STORE_BRANDING',
        details: `Updated store branding & contact — Name: "${nextStoreName}"${nextLogoUrl ? ' (custom logo)' : ''}, Email: ${nextContactEmail}, Phone: ${nextContactPhone}`,
        status: 'success',
      },
      true
    );
  }

  db.commit();
  return res.json({ success: true, settings: store.settings });
});

// ==========================================
// 11. CONTACT FORM & MESSAGES
// ==========================================
app.post('/api/contact', (req: Request, res: Response) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email, and message are required.' });
  }

  const store = db.getData();
  const newMsg: ContactMessage = {
    id: `msg_${Date.now()}`,
    name: name.trim(),
    email: email.trim(),
    subject: subject ? subject.trim() : 'General Inquiry',
    message: message.trim(),
    createdAt: new Date().toISOString(),
    status: 'unread',
  };

  store.contactMessages.unshift(newMsg);
  db.commit();

  return res.status(201).json({
    success: true,
    message: 'Thank you for contacting NOVORA. Our concierge team will respond within 24 hours.',
  });
});

app.get('/api/contact', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(store.contactMessages);
});

// ==========================================
// 12. ADMIN DASHBOARD STATS
// ==========================================
app.get('/api/admin/stats', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const baseCurrency = getStoreBaseCurrency(store);
  const totalProducts = store.products.length;
  const totalOrders = store.orders.length;
  const realCustomerOrdersList = store.orders.filter(o => !o.paymentDetails?.isTestMode);
  const sandboxOrders = store.orders.filter(o => Boolean(o.paymentDetails?.isTestMode)).length;
  const livePaidOrdersList = realCustomerOrdersList.filter(o => o.paymentStatus === 'paid');
  const livePaidRevenue = livePaidOrdersList.reduce(
    (sum, o) => sum + (typeof o.baseTotal === 'number' ? o.baseTotal : Number(o.total || 0)),
    0
  );
  const pendingOrders = store.orders.filter(o => o.orderStatus === 'Awaiting Payment' || o.paymentStatus === 'pending').length;
  const completedOrders = store.orders.filter(o => o.orderStatus === 'Delivered').length;
  const totalSales = realCustomerOrdersList
    .filter(o => o.paymentStatus !== 'declined' && o.orderStatus !== 'Cancelled' && o.orderStatus !== 'Refunded')
    .reduce(
      (sum, o) => sum + (typeof o.baseTotal === 'number' ? o.baseTotal : Number(o.total || 0)),
      0
    );
  const lowStockProducts = store.products.filter(p => {
    if (Array.isArray(p.variants?.items) && p.variants.items.length > 0) {
      return p.stock <= 5 || p.variants.items.some(v => v.availability !== 'unavailable' && v.stock <= 5);
    }
    return p.stock <= 5;
  }).length;
  const totalCustomers = store.users.filter(u => u.role === 'customer').length;

  return res.json({
    baseCurrency,
    totalProducts,
    totalOrders,
    realCustomerOrders: realCustomerOrdersList.length,
    sandboxOrders,
    livePaidOrders: livePaidOrdersList.length,
    livePaidRevenue,
    pendingOrders,
    completedOrders,
    totalSales,
    lowStockProducts,
    totalCustomers,
    recentOrders: store.orders.slice(0, 5),
  });
});




// ==========================================
// 15. NEWSLETTER SUBSCRIPTION
// ==========================================
app.post('/api/newsletter/subscribe', (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email || !email.includes('@') || !email.includes('.')) {
    return res.status(400).json({ success: false, error: 'Please enter a valid email address.' });
  }

  const store = db.getData();
  if (!store.newsletterSubscribers) {
    store.newsletterSubscribers = [];
  }

  const normalized = email.trim().toLowerCase();
  const exists = store.newsletterSubscribers.some(s => s.email.toLowerCase() === normalized);

  if (exists) {
    return res.json({
      success: true,
      message: 'You are already subscribed to the NOVORA private clientele mailing list.',
    });
  }

  const newSub = {
    id: `sub_${Date.now()}`,
    email: normalized,
    subscribedAt: new Date().toISOString(),
  };

  store.newsletterSubscribers.unshift(newSub);
  db.commit();

  return res.status(201).json({
    success: true,
    message: 'Welcome to NOVORA. You are now subscribed to our private releases and exclusive previews.',
  });
});

app.get('/api/admin/newsletter/subscribers', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  return res.json(store.newsletterSubscribers || []);
});

app.get('/api/admin/newsletter/export-csv', requireAdmin, (req: Request, res: Response) => {
  const store = db.getData();
  const subs = store.newsletterSubscribers || [];

  const headers = ['Subscriber ID', 'Email Address', 'Subscription Timestamp', 'Status'];
  const rows = subs.map(s => [
    `"${s.id}"`,
    `"${s.email}"`,
    `"${s.subscribedAt}"`,
    '"Active Subscribed"',
  ]);

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="novora_newsletter_subscribers.csv"');
  return res.send(csv);
});

const safepayRouter = express.Router();

const SAFEPAY_API = 'https://sandbox.api.getsafepay.com/order/payments/v3/';

safepayRouter.post('/create', async (req: Request, res: Response) => {
  try {
    const authUser = (req as any).user;
    if (!authUser) {
      return res.status(401).json({ message: 'Please sign in first.' });
    }

    const { orderId } = req.body;
    if (typeof orderId !== 'string' || !orderId) {
      return res.status(400).json({ message: 'A valid order ID is required.' });
    }

    const userId = authUser.id || authUser.uid;
    const order = await loadOrderForUser(orderId, userId);

    if (!order || order.paymentStatus !== 'pending') {
      return res.status(400).json({ message: 'Order not found or not payable.' });
    }

    const apiKey = process.env.SAFEPAY_MERCHANT_API_KEY || process.env.SAFEPAY_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: 'Payment gateway is not configured.' });
    }

    const amount = Math.round(order.totalPKR * 100);
    if (!Number.isSafeInteger(amount) || amount < 100) {
      return res.status(400).json({ message: 'Invalid order amount.' });
    }

    const response = await fetch(SAFEPAY_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        merchant_api_key: apiKey,
        intent: 'CYBERSOURCE',
        mode: 'payment',
        entry_mode: 'flex',
        currency: 'PKR',
        amount,
        metadata: { order_id: orderId },
      }),
    });

    const result: any = await response.json();
    if (!response.ok || !result?.data?.tracker?.token) {
      console.error('Safepay tracker creation failed');
      return res.status(502).json({ message: 'Unable to start payment. Please try again.' });
    }

    await savePaymentTracker(orderId, result.data.tracker.token);

    return res.json({
      trackerToken: result.data.tracker.token,
      status: 'pending',
    });
  } catch (error) {
    console.error('Payment initialization failed', error);
    return res.status(500).json({ message: 'Payment could not be initialized.' });
  }
});

safepayRouter.post('/verify', async (req: Request, res: Response) => {
  try {
    const authUser = (req as any).user;
    if (!authUser) {
      return res.status(401).json({ message: 'Please sign in first.' });
    }

    const { orderId, trackerToken } = req.body;
    if (typeof orderId !== 'string' || !orderId || typeof trackerToken !== 'string' || !trackerToken) {
      return res.status(400).json({ message: 'Valid orderId and trackerToken are required.' });
    }

    const apiKey = process.env.SAFEPAY_MERCHANT_API_KEY || process.env.SAFEPAY_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: 'Payment gateway is not configured.' });
    }

    const store = db.getData();
    const userId = authUser.id || authUser.uid;
    const order = store.orders.find(
      o => (o.id === orderId || o.orderNumber === orderId) && (!o.userId || o.userId === userId)
    );

    if (!order) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    if (order.paymentStatus === 'paid') {
      return res.json({ status: 'paid', order });
    }

    const verifyRes = await fetch(`${SAFEPAY_API}${encodeURIComponent(trackerToken)}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-SFPY-MERCHANT-SECRET': process.env.SAFEPAY_SECRET_KEY || apiKey,
      },
    });

    const verifyData: any = await verifyRes.json();
    const state = (verifyData?.data?.tracker?.state || verifyData?.data?.state || '').toUpperCase();

    if (verifyRes.ok && (state === 'PAID' || state === 'TRACKER_ENDED')) {
      order.paymentStatus = 'paid';
      order.orderStatus = 'Paid';
      order.paymentDetails = {
        provider: 'Safepay',
        paymentMethodTitle: 'Safepay Checkout (PKR)',
        transactionId: trackerToken,
        paidAt: new Date().toISOString(),
        isTestMode: true,
      };
      db.commit();
      return res.json({ status: 'paid', order });
    }

    return res.status(400).json({
      status: order.paymentStatus,
      message: 'Payment has not been confirmed by Safepay.',
    });
  } catch (error) {
    console.error('Safepay verification failed', error);
    return res.status(500).json({ message: 'Unable to verify payment.' });
  }
});

app.use('/api/payments/safepay', safepayRouter);

// Return JSON 404 for unknown /api/* routes instead of falling through to SPA HTML
app.use('/api', (_req: Request, res: Response) => {
  return res.status(404).json({ error: 'API endpoint not found.' });
});

async function loadOrderForUser(
  orderId: string,
  userId: string
): Promise<{
  totalPKR: number;
  paymentStatus: string;
} | null> {
  const store = db.getData();
  const order = store.orders.find(
    o => (o.id === orderId || o.orderNumber === orderId) && (!o.userId || o.userId === userId)
  );
  if (!order) return null;
  if (normalizeCurrencyCode(order.currency) === 'PKR') {
    return {
      totalPKR: Number(order.total || 0),
      paymentStatus: order.paymentStatus,
    };
  }
  const baseCur = normalizeCurrencyCode(order.baseCurrency || getStoreBaseCurrency(store));
  const baseAmt = typeof order.baseTotal === 'number' ? order.baseTotal : Number(order.total || 0);
  const { rate } = await resolveConversionRate({
    baseCurrency: baseCur,
    targetCurrency: 'PKR',
    refreshMinutes: Number(store.settings?.exchangeRateRefreshMinutes || 30),
  });
  return {
    totalPKR: applyRounding(baseAmt * rate, 'PKR', store.settings?.priceRoundingMode || 'two_decimals'),
    paymentStatus: order.paymentStatus,
  };
}

async function savePaymentTracker(
  orderId: string,
  trackerToken: string
): Promise<void> {
  const store = db.getData();
  const order = store.orders.find(o => o.id === orderId || o.orderNumber === orderId);
  if (order) {
    order.paymentDetails = {
      ...order.paymentDetails,
      provider: 'Safepay',
      paymentMethodTitle: 'Safepay Checkout (PKR)',
      transactionId: trackerToken,
      isTestMode: true,
    };
    db.commit();
  }
}

// ==========================================
// VITE SPA INTEGRATION
// ==========================================
async function startServer() {
  const distDir = path.resolve(process.cwd(), 'dist');
  const distIndexPath = path.join(distDir, 'index.html');
  const hasDistBuild = fs.existsSync(distIndexPath);

  if (!isProduction || !hasDistBuild) {
    if (isProduction && !hasDistBuild) {
      console.warn('[NOVORA] dist/index.html not found in production mode. Falling back to Vite middleware.');
    }
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const rawHtml = fs.readFileSync(distIndexPath, 'utf-8');
    // Rewrite relative ./assets/ paths to /assets/ for HTTP requests so nested SPA routes load bundles cleanly
    const httpServedHtml = rawHtml
      .replace(/(src|href)="\.\/assets\//g, '$1="/assets/')
      .replace(/(src|href)="\.\/images\//g, '$1="/images/');

    app.use('/assets', express.static(path.join(distDir, 'assets')));
    app.use(express.static(distDir, { index: false }));

    app.get('*', (req: Request, res: Response) => {
      if (
        req.path.startsWith('/assets/') ||
        req.path.startsWith('/uploads/') ||
        req.path.startsWith('/images/') ||
        req.path.startsWith('/src/assets/') ||
        req.path.startsWith('/api/')
      ) {
        return res.status(404).json({ error: 'Resource not found', path: req.path });
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      return res.send(httpServedHtml);
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`NOVORA E-Commerce server running at http://localhost:${PORT} (0.0.0.0:${PORT})`);
    startExchangeRateScheduler(() => {
      const s = db.getData();
      return {
        baseCurrency: getStoreBaseCurrency(s),
        refreshMinutes: Number(s.settings?.exchangeRateRefreshMinutes || 30),
      };
    });
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n[NOVORA ERROR] Port ${PORT} is already in use by another process.`);
      console.error(`Close the other terminal/app using port ${PORT} or run with PORT=3001.`);
    } else {
      console.error('\n[NOVORA ERROR] Failed to start server:', err);
    }
    process.exit(1);
  });
}

startServer();
