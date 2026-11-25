# NOVORA E-Commerce Store

NOVORA is a full-stack luxury e-commerce application featuring a curated product catalog, patron authentication (Email/Password + Google Sign-In), shopping bag, multi-currency pricing, checkout with Cash on Delivery and card gateways, order tracking, and an owner-protected admin console.

---

## Opening Directly via `index.html` (No CMD Required)

NOVORA builds into a self-contained pure web storefront that opens directly through `index.html`:

1. **Direct Browser Open**: Open `dist/index.html` (or double-click `index.html` in the project root after building) directly in Chrome, Edge, Safari, or Firefox — no Command Prompt or batch launcher is required.
2. **Static Web Hosting**: Deploy the `dist/` folder directly to Firebase Hosting, Netlify, Vercel, GitHub Pages, or any standard web host (`index.html` serves the full React storefront, catalog, cart, checkout, and Firebase features).
3. **Optional Local Dev / Full-Stack Mode**: Run `npm run build` to refresh `dist/index.html`, or `npm start` for optional local Node/Express backend endpoints on `http://localhost:3000`.

---

## Available Scripts

| Script | Command | Purpose |
| :--- | :--- | :--- |
| **Development Server** | `npm run dev` | Starts full-stack Express + Vite server on `http://localhost:3000` |
| **Production Build** | `npm run build` | Compiles the frontend bundle into `/dist` |
| **Production Start** | `npm start` | Starts the Node/Express full-stack server (`tsx server.ts`) |
| **Typecheck** | `npm run lint` | Verifies TypeScript types via `tsc --noEmit` |

---

## Deploying to Production (Node Hosting / Cloud Run / VPS)

Deploy the repository to any Node.js runtime (Cloud Run, Railway, Render, Fly.io, or a VPS):

1. **Install & Build**:
   ```bash
   npm install
   npm run build
   ```
2. **Start Command**:
   ```bash
   NODE_ENV=production npm start
   ```
3. Persistent data lives in `/data/` (`store.json`, `novora.db`) and uploaded media lives in `/uploads/`. All default storefront banners, category imagery, product photos, and the brand opening film live in `/public/` and are bundled automatically into `/dist/`.

---

## Firebase Authentication & Authorized Domains

Google Sign-In and Email authentication are pre-configured via `firebase-applet-config.json`. When deploying to a custom domain:

1. Open the [Firebase Console](https://console.firebase.google.com/) for project `gen-lang-client-0358244177`.
2. Go to **Authentication** > **Settings** > **Authorized domains**.
3. Ensure `localhost` (for local runs) and your live production domain are listed.

---

## Administrator Access

- Standard customer sign-ups always receive `customer` access.
- Administrator access is restricted strictly to `huzaifa60010@gmail.com` across both backend routes and Firestore security rules.
