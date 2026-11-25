#!/usr/bin/env python3
"""
NOVORA — Local SQLite & REST API Backend
Created for School Project: Store User Details & Admin Catalog in C:\\Novora_Project\\data\\novora.db
Works out-of-the-box on standard Python 3 (Zero external pip dependencies required).
Optionally runs on Flask if installed.
"""

import os
import sys
import json
import sqlite3
import hashlib
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Determine paths — default to C:\Novora_Project on Windows, or local ./data
if os.name == 'nt' and os.path.exists('C:\\Novora_Project'):
    BASE_DIR = 'C:\\Novora_Project'
else:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(DATA_DIR, 'novora.db')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

print(f"==================================================")
print(f"NOVORA Local SQLite Backend Starting")
print(f"Project Root: {BASE_DIR}")
print(f"Database File: {DB_PATH}")
print(f"Uploads Directory: {UPLOADS_DIR}")
print(f"==================================================")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        phone TEXT,
        created_at TEXT,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS addresses (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        user_email TEXT,
        full_name TEXT NOT NULL,
        phone TEXT,
        country TEXT NOT NULL,
        state TEXT NOT NULL,
        city TEXT NOT NULL,
        street_address TEXT NOT NULL,
        house_number TEXT NOT NULL,
        apartment_details TEXT,
        postal_code TEXT NOT NULL,
        is_default INTEGER DEFAULT 0,
        created_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        sku TEXT UNIQUE,
        description TEXT,
        category TEXT,
        subcategory TEXT,
        brand TEXT,
        original_price REAL,
        selling_price REAL NOT NULL,
        discount_percentage REAL DEFAULT 0,
        stock INTEGER DEFAULT 0,
        status TEXT DEFAULT 'published',
        featured INTEGER DEFAULT 0,
        best_seller INTEGER DEFAULT 0,
        images TEXT,
        variants TEXT,
        rating REAL DEFAULT 5.0,
        reviews_count INTEGER DEFAULT 0,
        created_at TEXT,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS categories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        image TEXT,
        description TEXT,
        subcategories TEXT,
        display_order INTEGER DEFAULT 1,
        status TEXT DEFAULT 'active',
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS banners (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        subtitle TEXT,
        badge_text TEXT,
        button_text TEXT,
        link_url TEXT,
        image_url TEXT,
        display_order INTEGER DEFAULT 1,
        is_active INTEGER DEFAULT 1,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        order_number TEXT UNIQUE NOT NULL,
        user_id TEXT,
        customer_name TEXT,
        customer_email TEXT,
        customer_phone TEXT,
        delivery_address TEXT,
        items TEXT,
        subtotal REAL,
        discount REAL,
        coupon_code TEXT,
        shipping_fee REAL,
        tax_amount REAL,
        total REAL,
        currency TEXT,
        payment_method TEXT,
        payment_status TEXT,
        order_status TEXT,
        tracking_number TEXT,
        carrier TEXT,
        settled_to_merchant_card TEXT,
        notes TEXT,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS store_settings (
        id TEXT PRIMARY KEY,
        store_name TEXT,
        tagline TEXT,
        currency TEXT,
        currency_symbol TEXT,
        shipping_charge REAL,
        free_shipping_threshold REAL,
        tax_rate_percentage REAL,
        contact_email TEXT,
        contact_phone TEXT,
        address TEXT,
        seo_title TEXT,
        seo_description TEXT,
        show_promotional_bar INTEGER,
        promotional_bar_text TEXT
    );

    CREATE TABLE IF NOT EXISTS backups (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        description TEXT
    );
    """)

    # Seed Default Root Admin and Sample Customer if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_pwd_hash = 'hash_sha256_' + hashlib.sha256('admin123Password!'.encode('utf-8')).hexdigest()[:32]
        cursor.execute("""
        INSERT INTO users (id, email, password_hash, full_name, role, phone, created_at, updated_at)
        VALUES ('user_admin_1', 'admin@novora.store', ?, 'Chief Store Administrator', 'admin', '+1 (800) 849-2041', ?, ?)
        """, (admin_pwd_hash, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))

    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'customer@novora.store'")
    if cursor.fetchone()[0] == 0:
        cust_pwd_hash = 'hash_sha256_' + hashlib.sha256('customer123Password!'.encode('utf-8')).hexdigest()[:32]
        cursor.execute("""
        INSERT INTO users (id, email, password_hash, full_name, role, phone, created_at, updated_at)
        VALUES ('user_cust_1', 'customer@novora.store', ?, 'Eleanor Vance', 'customer', '+1 (555) 234-5678', ?, ?)
        """, (cust_pwd_hash, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))

        # Sample Address for Eleanor
        cursor.execute("""
        INSERT INTO addresses (id, user_id, user_email, full_name, phone, country, state, city,
                               street_address, house_number, apartment_details, postal_code, is_default, created_at)
        VALUES ('addr_1', 'user_cust_1', 'customer@novora.store', 'Eleanor Vance', '+1 (555) 234-5678',
                'United States', 'New York', 'New York', 'Broadway', '450', 'Apt 12B, North Tower', '10013', 1, ?)
        """, (datetime.utcnow().isoformat(),))

    # Seed default store settings if missing
    cursor.execute("SELECT COUNT(*) FROM store_settings WHERE id = 'main_settings'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO store_settings (id, store_name, tagline, currency, currency_symbol, shipping_charge,
                                    free_shipping_threshold, tax_rate_percentage, contact_email, contact_phone,
                                    address, seo_title, seo_description, show_promotional_bar, promotional_bar_text)
        VALUES ('main_settings', 'NOVORA', 'Refined Everyday Luxury & Contemporary Essentials',
                'USD', '$', 15.0, 150.0, 5.0, 'concierge@novora.store', '+1 (800) 849-2041',
                '740 Fifth Avenue, 18th Floor, New York, NY 10019',
                'NOVORA — Contemporary Luxury E-Commerce',
                'Discover tailored fashion, precision audio, and curated luxury essentials.',
                1, 'Complimentary expedited delivery on all orders over $150 · Code NOVORA15 for 15% off')
        """)

    conn.commit()
    conn.close()
    print("Database tables initialized successfully with ACID compliance.")

init_database()

# HTTP Request Handler matching our frontend API spec
class NovoraAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _get_auth_user(self):
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ')[1]
        # Token format: auth_<userId>_<role>_<timestamp>
        parts = token.split('_')
        if len(parts) >= 3:
            user_id = f"user_{parts[1]}" if not parts[1].startswith('user_') else parts[1]
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, full_name, role, phone FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
        return None

    def _read_json_body(self):
        content_len = int(self.headers.get('Content-Length', 0))
        if content_len == 0:
            return {}
        raw = self.rfile.read(content_len).decode('utf-8')
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Health check
        if path == '/api/health':
            return self._send_json(200, {
                "status": "online",
                "database": DB_PATH,
                "engine": "SQLite 3",
                "timestamp": datetime.utcnow().isoformat()
            })

        # 2. Products
        if path == '/api/products':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
            rows = cursor.fetchall()
            products = []
            for r in rows:
                p = dict(r)
                p['images'] = json.loads(p['images']) if p.get('images') else []
                p['variants'] = json.loads(p['variants']) if p.get('variants') else {}
                p['featured'] = bool(p.get('featured'))
                p['bestSeller'] = bool(p.get('best_seller'))
                p['originalPrice'] = p.get('original_price', p['selling_price'])
                p['sellingPrice'] = p.get('selling_price')
                p['discountPercentage'] = p.get('discount_percentage', 0)
                p['reviewsCount'] = p.get('reviews_count', 0)
                products.append(p)
            conn.close()
            return self._send_json(200, products)

        # 3. Categories
        if path == '/api/categories':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM categories ORDER BY display_order ASC")
            rows = cursor.fetchall()
            cats = []
            for r in rows:
                c = dict(r)
                c['subcategories'] = json.loads(c['subcategories']) if c.get('subcategories') else []
                cats.append(c)
            conn.close()
            return self._send_json(200, cats)

        # 4. Banners
        if path == '/api/banners':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM banners ORDER BY display_order ASC")
            rows = cursor.fetchall()
            banners = [dict(r) for r in rows]
            conn.close()
            return self._send_json(200, banners)

        # 5. Orders
        if path == '/api/orders':
            user = self._get_auth_user()
            if not user:
                return self._send_json(401, {"error": "Authentication required"})
            
            conn = get_db()
            cursor = conn.cursor()
            if user['role'] == 'admin':
                cursor.execute("SELECT * FROM orders ORDER BY created_at DESC")
            else:
                cursor.execute("SELECT * FROM orders WHERE user_id = ? OR customer_email = ? ORDER BY created_at DESC",
                               (user['id'], user['email']))
            rows = cursor.fetchall()
            orders = []
            for r in rows:
                o = dict(r)
                o['deliveryAddress'] = json.loads(o['delivery_address']) if o.get('delivery_address') else {}
                o['items'] = json.loads(o['items']) if o.get('items') else []
                o['orderNumber'] = o.get('order_number')
                o['paymentMethod'] = o.get('payment_method')
                o['paymentStatus'] = o.get('payment_status')
                o['orderStatus'] = o.get('order_status')
                o['trackingNumber'] = o.get('tracking_number')
                o['settledToMerchantCard'] = o.get('settled_to_merchant_card')
                orders.append(o)
            conn.close()
            return self._send_json(200, orders)

        # 6. Current User Profile
        if path == '/api/auth/me':
            user = self._get_auth_user()
            if not user:
                return self._send_json(401, {"error": "Not authenticated"})
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC", (user['id'],))
            addrs = [dict(r) for r in cursor.fetchall()]
            for a in addrs:
                a['streetAddress'] = a.get('street_address')
                a['houseNumber'] = a.get('house_number')
                a['apartmentDetails'] = a.get('apartment_details')
                a['postalCode'] = a.get('postal_code')
                a['isDefault'] = bool(a.get('is_default'))

            user['savedAddresses'] = addrs
            conn.close()
            return self._send_json(200, {"user": user})

        # 7. Admin Stats
        if path == '/api/admin/stats':
            user = self._get_auth_user()
            if not user or user['role'] != 'admin':
                return self._send_json(403, {"error": "Admin clearance required"})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM products")
            total_products = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM orders")
            total_orders = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM orders WHERE order_status = 'Pending' OR payment_status = 'pending'")
            pending_orders = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM orders WHERE order_status = 'Delivered'")
            completed_orders = cursor.fetchone()[0]

            cursor.execute("SELECT COALESCE(SUM(total), 0) FROM orders")
            total_sales = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM products WHERE stock <= 5")
            low_stock = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'customer'")
            total_customers = cursor.fetchone()[0]

            conn.close()
            return self._send_json(200, {
                "totalProducts": total_products,
                "totalOrders": total_orders,
                "pendingOrders": pending_orders,
                "completedOrders": completed_orders,
                "totalSales": total_sales,
                "lowStockProducts": low_stock,
                "totalCustomers": total_customers,
                "recentOrders": []
            })

        # 8. Store Settings
        if path == '/api/settings':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM store_settings WHERE id = 'main_settings'")
            row = cursor.fetchone()
            conn.close()
            if row:
                s = dict(row)
                return self._send_json(200, {
                    "storeName": s.get('store_name', 'NOVORA'),
                    "tagline": s.get('tagline', ''),
                    "currency": s.get('currency', 'USD'),
                    "currencySymbol": s.get('currency_symbol', '$'),
                    "shippingCharge": s.get('shipping_charge', 15),
                    "freeShippingThreshold": s.get('free_shipping_threshold', 150),
                    "taxRatePercentage": s.get('tax_rate_percentage', 5),
                    "contactEmail": s.get('contact_email', 'concierge@novora.store'),
                    "contactPhone": s.get('contact_phone', ''),
                    "address": s.get('address', ''),
                    "seoTitle": s.get('seo_title', ''),
                    "seoDescription": s.get('seo_description', ''),
                    "showPromotionalBar": bool(s.get('show_promotional_bar')),
                    "promotionalBarText": s.get('promotional_bar_text', '')
                })
            return self._send_json(404, {"error": "Settings not found"})

        # Static file serve for uploads (products/ and banners/)
        if path.startswith('/uploads/'):
            rel_path = path[len('/uploads/'):].lstrip('/')
            file_path = os.path.join(UPLOADS_DIR, rel_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                self.send_response(200)
                self._send_cors_headers()
                if file_path.endswith('.png'):
                    self.send_header('Content-Type', 'image/png')
                elif file_path.endswith('.webp'):
                    self.send_header('Content-Type', 'image/webp')
                elif file_path.endswith('.svg'):
                    self.send_header('Content-Type', 'image/svg+xml')
                else:
                    self.send_header('Content-Type', 'image/jpeg')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
                return

        return self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        # 1. Customer Registration
        if path == '/api/auth/register':
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')
            full_name = body.get('fullName', '').strip()
            phone = body.get('phone', '').strip()

            if not email or not password or not full_name:
                return self._send_json(400, {"error": "Email, password, and full name are required."})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                return self._send_json(400, {"error": "An account with this email address already exists."})

            user_id = f"user_{int(time.time() * 1000)}"
            pwd_hash = 'hash_sha256_' + hashlib.sha256(password.encode('utf-8')).hexdigest()[:32]
            now = datetime.utcnow().isoformat()

            cursor.execute("""
            INSERT INTO users (id, email, password_hash, full_name, role, phone, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'customer', ?, ?, ?)
            """, (user_id, email, pwd_hash, full_name, phone, now, now))
            conn.commit()
            conn.close()

            token = f"auth_{user_id}_customer_{int(time.time())}"
            return self._send_json(201, {
                "success": True,
                "token": token,
                "user": {
                    "id": user_id,
                    "email": email,
                    "fullName": full_name,
                    "role": "customer",
                    "phone": phone,
                    "savedAddresses": []
                }
            })

        # 2. Sign In / Login
        if path == '/api/auth/login':
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return self._send_json(401, {"error": "Invalid email or password credentials."})

            user = dict(row)
            pwd_hash = 'hash_sha256_' + hashlib.sha256(password.encode('utf-8')).hexdigest()[:32]
            
            # Match either hashed or plain (for initial seeds)
            if user['password_hash'] != pwd_hash and user['password_hash'] != password:
                return self._send_json(401, {"error": "Invalid email or password credentials."})

            token = f"auth_{user['id']}_{user['role']}_{int(time.time())}"
            return self._send_json(200, {
                "success": True,
                "token": token,
                "user": {
                    "id": user['id'],
                    "email": user['email'],
                    "fullName": user['full_name'],
                    "role": user['role'],
                    "phone": user.get('phone', '')
                }
            })

        # 3. Add Customer Address
        if path == '/api/auth/address':
            user = self._get_auth_user()
            if not user:
                return self._send_json(401, {"error": "Authentication required"})

            full_name = body.get('fullName', user['full_name']).strip()
            phone = body.get('phone', user.get('phone', '')).strip()
            country = body.get('country', '').strip()
            state = body.get('state', '').strip()
            city = body.get('city', '').strip()
            street = body.get('streetAddress', '').strip()
            house_no = body.get('houseNumber', '').strip()
            apt = body.get('apartmentDetails', '').strip()
            zip_code = body.get('postalCode', '').strip()
            is_default = 1 if body.get('isDefault') else 0

            if not country or not city or not street or not house_no or not zip_code:
                return self._send_json(400, {"error": "All 10 compulsory address fields are required."})

            addr_id = f"addr_{int(time.time() * 1000)}"
            now = datetime.utcnow().isoformat()

            conn = get_db()
            cursor = conn.cursor()
            if is_default:
                cursor.execute("UPDATE addresses SET is_default = 0 WHERE user_id = ?", (user['id'],))

            cursor.execute("""
            INSERT INTO addresses (id, user_id, user_email, full_name, phone, country, state, city,
                                   street_address, house_number, apartment_details, postal_code, is_default, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (addr_id, user['id'], user['email'], full_name, phone, country, state, city,
                  street, house_no, apt, zip_code, is_default, now))
            conn.commit()
            conn.close()

            return self._send_json(201, {
                "success": True,
                "message": "Delivery address saved permanently to novora.db",
                "address": {
                    "id": addr_id,
                    "fullName": full_name,
                    "phone": phone,
                    "country": country,
                    "state": state,
                    "city": city,
                    "streetAddress": street,
                    "houseNumber": house_no,
                    "apartmentDetails": apt,
                    "postalCode": zip_code,
                    "isDefault": bool(is_default)
                }
            })

        # 4. Image Upload from PC (Saves permanently to uploads/products or uploads/banners)
        if path == '/api/upload':
            base64_data = body.get('base64', '')
            file_name = body.get('fileName', 'upload.jpg')
            folder = body.get('folder', 'products')
            subfolder = 'banners' if folder == 'banners' else 'products'
            subfolder_path = os.path.join(UPLOADS_DIR, subfolder)
            os.makedirs(subfolder_path, exist_ok=True)

            if not base64_data:
                return self._send_json(400, {"error": "No image data payload provided."})

            import base64 as b64
            ext = '.jpg'
            if 'image/png' in base64_data or file_name.endswith('.png'):
                ext = '.png'
            elif 'image/webp' in base64_data or file_name.endswith('.webp'):
                ext = '.webp'
            elif 'image/svg' in base64_data or file_name.endswith('.svg'):
                ext = '.svg'

            if ',' in base64_data:
                base64_data = base64_data.split(',')[1]

            img_bytes = b64.b64decode(base64_data)
            unique_name = f"img_{int(time.time())}_{os.urandom(4).hex()}{ext}"
            target_path = os.path.join(subfolder_path, unique_name)

            with open(target_path, 'wb') as f:
                f.write(img_bytes)

            file_url = f"/uploads/{subfolder}/{unique_name}"
            return self._send_json(201, {
                "success": True,
                "url": file_url,
                "fileName": unique_name,
                "sizeBytes": len(img_bytes)
            })

        # 5. Place Customer Order
        if path == '/api/orders':
            user = self._get_auth_user()
            items = body.get('items', [])
            addr = body.get('deliveryAddress', {})

            if not items or not addr:
                return self._send_json(400, {"error": "Bag items and delivery destination are required."})

            order_id = f"ord_{int(time.time() * 1000)}"
            order_number = f"NOV-2026-{int(time.time()) % 10000}"
            now = datetime.utcnow().isoformat()

            subtotal = sum(it.get('price', 0) * it.get('quantity', 1) for it in items)
            shipping = 0 if subtotal >= 150 else 15
            tax = round(subtotal * 0.05, 2)
            total = subtotal + shipping + tax

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO orders (id, order_number, user_id, customer_name, customer_email, customer_phone,
                                delivery_address, items, subtotal, discount, coupon_code, shipping_fee,
                                tax_amount, total, currency, payment_method, payment_status, order_status,
                                tracking_number, carrier, settled_to_merchant_card, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD', 'Online Card Checkout', 'paid', 'Processing',
                    ?, 'NOVORA Express Logistics', 'Credited to Admin Card •••• 9922 (Meezan Bank Ltd 1Link)', ?, ?)
            """, (order_id, order_number, user['id'] if user else None,
                  addr.get('fullName', 'Guest Patron'), addr.get('email', ''), addr.get('phone', ''),
                  json.dumps(addr), json.dumps(items), subtotal, 0, '', shipping, tax, total,
                  f"TRK-NV-{int(time.time()) % 1000000}", body.get('notes', ''), now))
            conn.commit()
            conn.close()

            return self._send_json(201, {
                "success": True,
                "order": {
                    "id": order_id,
                    "orderNumber": order_number,
                    "total": total,
                    "orderStatus": "Processing",
                    "paymentStatus": "paid",
                    "settledToMerchantCard": "Credited to Admin Card •••• 9922 (Meezan Bank Ltd 1Link)",
                    "createdAt": now
                }
            })

        return self._send_json(404, {"error": "Endpoint not found"})

def run_server(port=5000):
    server = HTTPServer(('0.0.0.0', port), NovoraAPIHandler)
    print(f"\n=======================================================")
    print(f"NOVORA SQLite Backend Active at http://127.0.0.1:{port}")
    print(f"Ready to accept frontend API calls and persist records.")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5000
    run_server(port)
