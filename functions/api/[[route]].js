export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname.replace('/api/', '');
    const method = request.method;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Admin-User, X-Admin-Pass',
        'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    const ensureColumn = async (table, column, definition) => {
        const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
        if (!info.results.some(col => col.name === column)) {
            await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
        }
    };
    const ensureProfileAndDepositColumns = async () => {
        await ensureColumn('users', 'first_name', "TEXT DEFAULT ''");
        await ensureColumn('users', 'last_name', "TEXT DEFAULT ''");
        await ensureColumn('users', 'mobile', "TEXT DEFAULT ''");
        await ensureColumn('users', 'address', "TEXT DEFAULT ''");
        await ensureColumn('users', 'postal_code', "TEXT DEFAULT ''");
        await ensureColumn('deposits', 'amount_crypto', 'REAL');
        await ensureColumn('deposits', 'trx_usd_rate', 'REAL');
    };

    const ADMIN_USER = env.ADMIN_USER || "admin";
    const ADMIN_PASS = env.ADMIN_PASS || "admin123456";

    try {
        // نرخ لحظه‌ای ترون به دلار (قیمت عمومی بازار، صرفاً برای برآورد و نمایش)
        if (path === 'crypto/trx-price' && method === 'GET') {
            let price = 0;
            let source = '';
            // Primary source: CoinGecko USD spot price.
            try {
                const priceRes = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=usd', {
                    headers: { 'Accept': 'application/json' }
                });
                if (priceRes.ok) {
                    const priceData = await priceRes.json();
                    price = Number(priceData?.tron?.usd);
                    if (Number.isFinite(price) && price > 0) source = 'CoinGecko';
                }
            } catch (_) {}
            // Fallback source: Binance TRX/USDT spot ticker (USDT ≈ USD).
            if (!(price > 0)) {
                try {
                    const fallbackRes = await fetch('https://api.binance.com/api/v3/ticker/price?symbol=TRXUSDT', {
                        headers: { 'Accept': 'application/json' }
                    });
                    if (fallbackRes.ok) {
                        const fallbackData = await fallbackRes.json();
                        price = Number(fallbackData?.price);
                        if (Number.isFinite(price) && price > 0) source = 'Binance TRX/USDT';
                    }
                } catch (_) {}
            }
            if (!(price > 0)) throw new Error('دریافت نرخ زنده TRX از منابع قیمت ممکن نشد');
            return new Response(JSON.stringify({ price_usd: price, usdt_per_trx: price, trx_per_usd: 1 / price, source, updated_at: new Date().toISOString() }), { headers: corsHeaders });
        }

        // ۱. ثبت‌نام
        if (path === 'register' && method === 'POST') {
            const { username, email, password } = await request.json();
            if (!username || !email || !password) {
                return new Response(JSON.stringify({ error: 'لطفاً تمام فیلدها را وارد کنید' }), { status: 400, headers: corsHeaders });
            }

            const cleanUser = username.trim();
            const cleanEmail = email.trim().toLowerCase();
            const cleanPass = String(password);

            const hasMinLen = cleanPass.length >= 10;
            const hasUpper = /[A-Z]/.test(cleanPass);
            const hasLower = /[a-z]/.test(cleanPass);
            const hasSymbol = /[^A-Za-z0-9]/.test(cleanPass);

            if (!hasMinLen || !hasUpper || !hasLower || !hasSymbol) {
                return new Response(JSON.stringify({ error: 'رمز عبور ضعیف است!' }), { status: 400, headers: corsHeaders });
            }

            const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ? OR email = ?').bind(cleanUser, cleanEmail).first();
            if (existing) return new Response(JSON.stringify({ error: 'این نام کاربری یا ایمیل تکراری است' }), { status: 400, headers: corsHeaders });

            const result = await env.DB.prepare('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, 0.0)').bind(cleanUser, cleanEmail, cleanPass).run();
            const newUser = await env.DB.prepare('SELECT id, username, email, balance FROM users WHERE id = ?').bind(result.meta.last_row_id).first();
            return new Response(JSON.stringify({ user: newUser }), { headers: corsHeaders });
        }

        // ۲. ورود
        if (path === 'login' && method === 'POST') {
            const { identifier, password } = await request.json();
            const cleanId = identifier.trim();
            const cleanEmail = cleanId.toLowerCase();

            const user = await env.DB.prepare('SELECT id, username, email, balance FROM users WHERE (username = ? OR email = ?) AND password = ?').bind(cleanId, cleanEmail, String(password)).first();
            if (!user) return new Response(JSON.stringify({ error: 'اطلاعات ورود اشتباه است' }), { status: 401, headers: corsHeaders });
            
            return new Response(JSON.stringify({ user }), { headers: corsHeaders });
        }

        // ۳. دریافت اطلاعات داشبورد مشتری
        if (path === 'user/data' && method === 'GET') {
            await ensureProfileAndDepositColumns();
            const userId = url.searchParams.get('user_id');
            const user = await env.DB.prepare('SELECT id, username, email, balance, first_name, last_name, mobile, address, postal_code FROM users WHERE id = ?').bind(userId).first();
            if (!user) return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { status: 404, headers: corsHeaders });

            const deposits = await env.DB.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const googleCampaigns = await env.DB.prepare('SELECT * FROM google_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const telegramCampaigns = await env.DB.prepare('SELECT * FROM telegram_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const instagramCampaigns = await env.DB.prepare('SELECT * FROM instagram_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const verifyServices = await env.DB.prepare('SELECT * FROM verify_services WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const tickets = await env.DB.prepare('SELECT * FROM tickets WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const settingsRows = await env.DB.prepare('SELECT * FROM settings').all();

            const wallets = { usdt: '', trx: '' };
            for (const row of settingsRows.results) {
                if (row.key === 'wallet_usdt') wallets.usdt = row.value;
                if (row.key === 'wallet_trx') wallets.trx = row.value;
            }

            return new Response(JSON.stringify({
                user, deposits: deposits.results, google_campaigns: googleCampaigns.results, 
                telegram_campaigns: telegramCampaigns.results, instagram_campaigns: instagramCampaigns.results,
                verify_services: verifyServices.results, tickets: tickets.results, wallets
            }), { headers: corsHeaders });
        }

        // ذخیره و به‌روزرسانی اطلاعات تکمیلی پروفایل کاربر
        if (path === 'user/profile' && method === 'POST') {
            await ensureProfileAndDepositColumns();
            const { user_id, first_name, last_name, mobile, address, postal_code } = await request.json();
            if (!user_id) return new Response(JSON.stringify({ error: 'شناسه کاربر معتبر نیست' }), { status: 400, headers: corsHeaders });
            if (mobile && !/^[0-9+()\\s-]{7,20}$/.test(String(mobile))) {
                return new Response(JSON.stringify({ error: 'شماره همراه معتبر نیست' }), { status: 400, headers: corsHeaders });
            }
            await env.DB.prepare('UPDATE users SET first_name = ?, last_name = ?, mobile = ?, address = ?, postal_code = ? WHERE id = ?')
                .bind(String(first_name || '').trim(), String(last_name || '').trim(), String(mobile || '').trim(), String(address || '').trim(), String(postal_code || '').trim(), user_id).run();
            const user = await env.DB.prepare('SELECT id, username, email, balance, first_name, last_name, mobile, address, postal_code FROM users WHERE id = ?').bind(user_id).first();
            return new Response(JSON.stringify({ success: true, user }), { headers: corsHeaders });
        }

        // ۴. ثبت فیش واریزی؛ مبلغ TRX و معادل دلاری آن جداگانه ذخیره می‌شود
        if (path === 'user/deposit' && method === 'POST') {
            await ensureProfileAndDepositColumns();
            const { user_id, amount_usd, amount_crypto, crypto_type, tx_hash } = await request.json();
            if (!user_id || !tx_hash || !crypto_type) return new Response(JSON.stringify({ error: 'اطلاعات واریز ناقص است' }), { status: 400, headers: corsHeaders });
            const isTrx = String(crypto_type).toUpperCase().includes('TRX');
            let usdValue, cryptoValue = null, trxRate = null;
            if (isTrx) {
                cryptoValue = Number(amount_crypto);
                if (!Number.isFinite(cryptoValue) || cryptoValue <= 0) return new Response(JSON.stringify({ error: 'مقدار TRX معتبر نیست' }), { status: 400, headers: corsHeaders });
                // Match the same live-price sources used by the wallet quote endpoint.
                try {
                    const priceRes = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=usd', { headers: { 'Accept': 'application/json' } });
                    if (priceRes.ok) {
                        const priceData = await priceRes.json();
                        trxRate = Number(priceData?.tron?.usd);
                    }
                } catch (_) {}
                if (!(trxRate > 0)) {
                    try {
                        const fallbackRes = await fetch('https://api.binance.com/api/v3/ticker/price?symbol=TRXUSDT', { headers: { 'Accept': 'application/json' } });
                        if (fallbackRes.ok) {
                            const fallbackData = await fallbackRes.json();
                            trxRate = Number(fallbackData?.price);
                        }
                    } catch (_) {}
                }
                if (!Number.isFinite(trxRate) || trxRate <= 0) throw new Error('دریافت نرخ زنده TRX ممکن نشد؛ کمی بعد دوباره تلاش کنید');
                usdValue = cryptoValue * trxRate;
            } else {
                usdValue = Number(amount_usd);
                if (!Number.isFinite(usdValue) || usdValue <= 0) return new Response(JSON.stringify({ error: 'مبلغ USDT معتبر نیست' }), { status: 400, headers: corsHeaders });
            }
            await env.DB.prepare('INSERT INTO deposits (user_id, amount_usd, crypto_type, tx_hash, amount_crypto, trx_usd_rate) VALUES (?, ?, ?, ?, ?, ?)')
                .bind(user_id, usdValue, crypto_type, String(tx_hash).trim(), cryptoValue, trxRate).run();
            return new Response(JSON.stringify({ success: true, amount_usd: usdValue, amount_crypto: cryptoValue, trx_usd_rate: trxRate }), { headers: corsHeaders });
        }

        // ۵. کمپین گوگل
        if (path === 'user/campaign/google' && method === 'POST') {
            const { user_id, website_url, product_info, keywords, budget_search, budget_display, budget_youtube } = await request.json();
            const total = (parseFloat(budget_search) || 0) + (parseFloat(budget_display) || 0) + (parseFloat(budget_youtube) || 0);

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) return new Response(JSON.stringify({ error: 'موجودی ناکافی است.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(total, user_id),
                env.DB.prepare('INSERT INTO google_campaigns (user_id, website_url, product_info, keywords, budget_search, budget_display, budget_youtube, total_budget, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(user_id, website_url.trim(), product_info.trim(), keywords.trim(), (parseFloat(budget_search) || 0), (parseFloat(budget_display) || 0), (parseFloat(budget_youtube) || 0), total, 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۶. کمپین تلگرام
        if (path === 'user/campaign/telegram' && method === 'POST') {
            const { user_id, channel_url, budget, description } = await request.json();
            const total = parseFloat(budget) || 0;

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) return new Response(JSON.stringify({ error: 'موجودی ناکافی است.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(total, user_id),
                env.DB.prepare('INSERT INTO telegram_campaigns (user_id, channel_url, budget, description, status) VALUES (?, ?, ?, ?, ?)').bind(user_id, channel_url.trim(), total, description.trim(), 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۷. کمپین اینستاگرام
        if (path === 'user/campaign/instagram' && method === 'POST') {
            const { user_id, post_link, budget } = await request.json();
            const advBudget = parseFloat(budget) || 0;
            const totalCost = advBudget * 2; 

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < totalCost) return new Response(JSON.stringify({ error: 'موجودی ناکافی است.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(totalCost, user_id),
                env.DB.prepare('INSERT INTO instagram_campaigns (user_id, post_link, budget, total_cost, status) VALUES (?, ?, ?, ?, ?)').bind(user_id, post_link.trim(), advBudget, totalCost, 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۸. خدمات وریفای
        if (path === 'user/verify/purchase' && method === 'POST') {
            const { user_id, service_name, price } = await request.json();
            const cost = parseFloat(price);

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < cost) return new Response(JSON.stringify({ error: 'موجودی کافی نیست.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(cost, user_id),
                env.DB.prepare('INSERT INTO verify_services (user_id, service_name, price, status) VALUES (?, ?, ?, ?)').bind(user_id, service_name, cost, 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۹. سیستم تیکت پشتیبانی (ایجاد تیکت جدید)
        if (path === 'user/ticket' && method === 'POST') {
            const { user_id, subject, message } = await request.json();
            if (!subject || !message) return new Response(JSON.stringify({ error: 'موضوع و متن پیام الزامی است' }), { status: 400, headers: corsHeaders });
            
            const conv = JSON.stringify([{ sender: 'user', text: message.trim(), date: new Date().toISOString() }]);
            await env.DB.prepare('INSERT INTO tickets (user_id, subject, conversation, status) VALUES (?, ?, ?, ?)').bind(user_id, subject.trim(), conv, 'open').run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۱۰. سیستم تیکت پشتیبانی (پاسخ کاربر به تیکت موجود)
        if (path === 'user/ticket/reply' && method === 'POST') {
            const { user_id, ticket_id, message } = await request.json();
            if (!ticket_id || !message) return new Response(JSON.stringify({ error: 'متن پیام الزامی است' }), { status: 400, headers: corsHeaders });
            
            const tk = await env.DB.prepare('SELECT conversation FROM tickets WHERE id = ? AND user_id = ?').bind(ticket_id, user_id).first();
            if(!tk) return new Response(JSON.stringify({ error: 'تیکت یافت نشد' }), { status: 404, headers: corsHeaders });
            
            let conv = JSON.parse(tk.conversation || '[]');
            conv.push({ sender: 'user', text: message.trim(), date: new Date().toISOString() });
            
            await env.DB.prepare("UPDATE tickets SET conversation = ?, status = 'open' WHERE id = ?").bind(JSON.stringify(conv), ticket_id).run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ==========================================
        // مسیرهای پنل ادمین
        // ==========================================
        if (path === 'admin/login' && method === 'POST') {
            const { username, password } = await request.json();
            if (username === ADMIN_USER && password === ADMIN_PASS) return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            return new Response(JSON.stringify({ error: 'اطلاعات ادمین اشتباه است' }), { status: 401, headers: corsHeaders });
        }

        if (path.startsWith('admin/')) {
            const reqUser = request.headers.get('X-Admin-User');
            const reqPass = request.headers.get('X-Admin-Pass');
            if (reqUser !== ADMIN_USER || reqPass !== ADMIN_PASS) return new Response(JSON.stringify({ error: 'عدم دسترسی مجاز' }), { status: 403, headers: corsHeaders });

            if (path === 'admin/overview' && method === 'GET') {
                const users = await env.DB.prepare('SELECT id, username, email, password, balance, created_at FROM users ORDER BY id DESC').all();
                const deposits = await env.DB.prepare('SELECT deposits.*, users.username, users.email FROM deposits JOIN users ON deposits.user_id = users.id ORDER BY deposits.id DESC').all();
                const googleCampaigns = await env.DB.prepare('SELECT google_campaigns.*, users.username FROM google_campaigns JOIN users ON google_campaigns.user_id = users.id ORDER BY google_campaigns.id DESC').all();
                const telegramCampaigns = await env.DB.prepare('SELECT telegram_campaigns.*, users.username FROM telegram_campaigns JOIN users ON telegram_campaigns.user_id = users.id ORDER BY telegram_campaigns.id DESC').all();
                const instagramCampaigns = await env.DB.prepare('SELECT instagram_campaigns.*, users.username FROM instagram_campaigns JOIN users ON instagram_campaigns.user_id = users.id ORDER BY instagram_campaigns.id DESC').all();
                const verifyServices = await env.DB.prepare('SELECT verify_services.*, users.username FROM verify_services JOIN users ON verify_services.user_id = users.id ORDER BY verify_services.id DESC').all();
                const tickets = await env.DB.prepare('SELECT tickets.*, users.username, users.email FROM tickets JOIN users ON tickets.user_id = users.id ORDER BY tickets.id DESC').all();
                const settingsRows = await env.DB.prepare('SELECT * FROM settings').all();

                const wallets = { usdt: '', trx: '' };
                for (const row of settingsRows.results) {
                    if (row.key === 'wallet_usdt') wallets.usdt = row.value;
                    if (row.key === 'wallet_trx') wallets.trx = row.value;
                }

                return new Response(JSON.stringify({
                    users: users.results, deposits: deposits.results, google_campaigns: googleCampaigns.results, 
                    telegram_campaigns: telegramCampaigns.results, instagram_campaigns: instagramCampaigns.results, 
                    verify_services: verifyServices.results, tickets: tickets.results, wallets
                }), { headers: corsHeaders });
            }

            if (path === 'admin/settings/wallet' && method === 'POST') {
                const { wallet_usdt, wallet_trx } = await request.json();
                await env.DB.batch([
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_usdt', ?)").bind(wallet_usdt.trim()),
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_trx', ?)").bind(wallet_trx.trim())
                ]);
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            if (path === 'admin/users' && method === 'POST') {
                const { username, email, password, initial_balance } = await request.json();
                await env.DB.prepare('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)').bind(username.trim(), email.trim().toLowerCase(), password.trim(), parseFloat(initial_balance) || 0).run();
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            if (path === 'admin/users/update-balance' && method === 'POST') {
                const { user_id, new_balance } = await request.json();
                await env.DB.prepare('UPDATE users SET balance = ? WHERE id = ?').bind(parseFloat(new_balance), user_id).run();
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            if (path === 'admin/users/delete' && method === 'POST') {
                const { user_id } = await request.json();
                await env.DB.batch([
                    env.DB.prepare('DELETE FROM deposits WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM google_campaigns WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM telegram_campaigns WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM instagram_campaigns WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM verify_services WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM tickets WHERE user_id = ?').bind(user_id),
                    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user_id)
                ]);
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            if (path === 'admin/deposits/action' && method === 'POST') {
                const { deposit_id, action } = await request.json();
                const dep = await env.DB.prepare('SELECT * FROM deposits WHERE id = ?').bind(deposit_id).first();
                if (action === 'approve') {
                    if (String(dep.crypto_type).toUpperCase().includes('TRX') && !(Number(dep.amount_crypto) > 0)) {
                        return new Response(JSON.stringify({ error: 'این واریزی ترون با نسخه قدیمی ثبت شده و مقدار TRX/معادل دلاری معتبر ندارد؛ پیش از تایید باید دستی بررسی شود.' }), { status: 400, headers: corsHeaders });
                    }
                    await env.DB.batch([
                        env.DB.prepare("UPDATE deposits SET status = 'approved' WHERE id = ?").bind(deposit_id),
                        env.DB.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").bind(dep.amount_usd, dep.user_id)
                    ]);
                } else {
                    await env.DB.prepare("UPDATE deposits SET status = 'rejected' WHERE id = ?").bind(deposit_id).run();
                }
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            if (path === 'admin/campaigns/action' && method === 'POST') {
                const { campaign_type, campaign_id, action } = await request.json();
                let table, refundAmountField;

                if (campaign_type === 'google') { table = 'google_campaigns'; refundAmountField = 'total_budget'; }
                else if (campaign_type === 'telegram') { table = 'telegram_campaigns'; refundAmountField = 'budget'; }
                else if (campaign_type === 'instagram') { table = 'instagram_campaigns'; refundAmountField = 'total_cost'; }
                else if (campaign_type === 'verify') { table = 'verify_services'; refundAmountField = 'price'; }
                else return new Response(JSON.stringify({ error: 'نوع سرویس نامعتبر است' }), { status: 400, headers: corsHeaders });

                const camp = await env.DB.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(campaign_id).first();

                if (action === 'approve') {
                    await env.DB.prepare(`UPDATE ${table} SET status = 'active' WHERE id = ?`).bind(campaign_id).run();
                } else {
                    await env.DB.batch([
                        env.DB.prepare(`UPDATE ${table} SET status = 'rejected' WHERE id = ?`).bind(campaign_id),
                        env.DB.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").bind(camp[refundAmountField], camp.user_id)
                    ]);
                }
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // ادمین ریپلای به تیکت
            if (path === 'admin/tickets/reply' && method === 'POST') {
                const { ticket_id, admin_reply } = await request.json();
                if (!ticket_id || !admin_reply) return new Response(JSON.stringify({ error: 'متن پاسخ نمی‌تواند خالی باشد' }), { status: 400, headers: corsHeaders });

                const tk = await env.DB.prepare('SELECT conversation FROM tickets WHERE id = ?').bind(ticket_id).first();
                if(!tk) return new Response(JSON.stringify({ error: 'تیکت یافت نشد' }), { status: 404, headers: corsHeaders });

                let conv = JSON.parse(tk.conversation || '[]');
                conv.push({ sender: 'admin', text: admin_reply.trim(), date: new Date().toISOString() });
                
                await env.DB.prepare("UPDATE tickets SET conversation = ?, status = 'answered' WHERE id = ?").bind(JSON.stringify(conv), ticket_id).run();
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }
        }

        return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers: corsHeaders });
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
}
