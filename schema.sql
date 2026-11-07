DROP TABLE IF EXISTS settings;
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES 
('wallet_usdt', 'در انتظار ثبت توسط مدیریت'),
('wallet_trx', 'در انتظار ثبت توسط مدیریت');

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS deposits;
CREATE TABLE deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount_usd REAL NOT NULL,
    crypto_type TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS google_campaigns;
CREATE TABLE google_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    website_url TEXT NOT NULL,
    budget_search REAL DEFAULT 0.0,
    budget_display REAL DEFAULT 0.0,
    budget_youtube REAL DEFAULT 0.0,
    total_budget REAL NOT NULL,
    status TEXT DEFAULT 'در حال بررسی و اجرا',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
