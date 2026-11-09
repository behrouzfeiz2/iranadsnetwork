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

    const ADMIN_USER = env.ADMIN_USER || "admin";
    const ADMIN_PASS = env.ADMIN_PASS || "admin123456";

    try {
        // ۱. ثبت‌نام
        if (path === 'register' && method === 'POST') {
            const { username, email, password } = await request.json();
            if (!username || !email || !password) return new Response(JSON.stringify({ error: 'لطفاً نام کاربری، ایمیل و رمز عبور را کامل وارد کنید' }), { status: 400, headers: corsHeaders });

            const cleanUser = username.trim();
            const cleanEmail = email.trim().toLowerCase();
            const cleanPass = String(password);

            const hasMinLen = cleanPass.length >= 10;
            const hasUpper = /[A-Z]/.test(cleanPass);
            const hasLower = /[a-z]/.test(cleanPass);
            const hasSymbol = /[^A-Za-z0-9]/.test(cleanPass);

            if (!hasMinLen || !hasUpper || !hasLower || !hasSymbol) {
                return new Response(JSON.stringify({ error: 'رمز عبور ضعیف است! رمز باید حداقل ۱۰ کاراکتر بوده و شامل حروف بزرگ، کوچک و علامت باشد.' }), { status: 400, headers: corsHeaders });
            }

            const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ? OR email = ?').bind(cleanUser, cleanEmail).first();
            if (existing) return new Response(JSON.stringify({ error: 'این نام کاربری یا ایمیل قبلاً ثبت شده است' }), { status: 400, headers: corsHeaders });

            const result = await env.DB.prepare('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, 0.0)').bind(cleanUser, cleanEmail, cleanPass).run();
            const newUser = await env.DB.prepare('SELECT id, username, email, balance FROM users WHERE id = ?').bind(result.meta.last_row_id).first();
            return new Response(JSON.stringify({ user: newUser }), { headers: corsHeaders });
        }

        // ۲. ورود
        if (path === 'login' && method === 'POST') {
            const { identifier, password } = await request.json();
            if (!identifier || !password) return new Response(JSON.stringify({ error: 'لطفاً اطلاعات ورود را کامل وارد کنید' }), { status: 400, headers: corsHeaders });

            const cleanId = identifier.trim();
            const cleanEmail = cleanId.toLowerCase();

            const user = await env.DB.prepare('SELECT id, username, email, balance FROM users WHERE (username = ? OR email = ?) AND password = ?').bind(cleanId, cleanEmail, String(password)).first();
            if (!user) return new Response(JSON.stringify({ error: 'ایمیل/نام کاربری یا رمز عبور اشتباه است' }), { status: 401, headers: corsHeaders });
            
            return new Response(JSON.stringify({ user }), { headers: corsHeaders });
        }

        // ۳. دریافت اطلاعات داشبورد مشتری
        if (path === 'user/data' && method === 'GET') {
            const userId = url.searchParams.get('user_id');
            const user = await env.DB.prepare('SELECT id, username, email, balance FROM users WHERE id = ?').bind(userId).first();
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

        // ۴. ثبت فیش واریزی
        if (path === 'user/deposit' && method === 'POST') {
            const { user_id, amount_usd, crypto_type, tx_hash } = await request.json();
            if (!amount_usd || amount_usd <= 0 || !tx_hash) return new Response(JSON.stringify({ error: 'لطفاً مبلغ و کد هش تراکنش را به درستی وارد کنید' }), { status: 400, headers: corsHeaders });

            await env.DB.prepare('INSERT INTO deposits (user_id, amount_usd, crypto_type, tx_hash) VALUES (?, ?, ?, ?)').bind(user_id, parseFloat(amount_usd), crypto_type, tx_hash.trim()).run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۵. کمپین گوگل
        if (path === 'user/campaign/google' && method === 'POST') {
            const { user_id, website_url, product_info, keywords, budget_search, budget_display, budget_youtube } = await request.json();
            const total = (parseFloat(budget_search) || 0) + (parseFloat(budget_display) || 0) + (parseFloat(budget_youtube) || 0);

            if (total <= 0 || !website_url || !product_info || !keywords) return new Response(JSON.stringify({ error: 'لطفاً تمام فیلدها و حداقل یکی از بودجه‌ها را وارد کنید' }), { status: 400, headers: corsHeaders });

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) return new Response(JSON.stringify({ error: 'مجموع بودجه انتخابی از موجودی کیف پول شما بیشتر است.' }), { status: 400, headers: corsHeaders });

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

            if (total <= 0 || !channel_url || !description) return new Response(JSON.stringify({ error: 'لطفاً فیلدها را کامل وارد کنید' }), { status: 400, headers: corsHeaders });

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) return new Response(JSON.stringify({ error: 'بودجه وارد شده از موجودی شما بیشتر است.' }), { status: 400, headers: corsHeaders });

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

            if (advBudget < 20 || !post_link) return new Response(JSON.stringify({ error: 'حداقل بودجه ۲۰ دلار است.' }), { status: 400, headers: corsHeaders });

            const totalCost = advBudget * 2; // ۱۰۰٪ کارمزد
            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            
            if (!user || user.balance < totalCost) return new Response(JSON.stringify({ error: 'موجودی ناکافی است.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(totalCost, user_id),
                env.DB.prepare('INSERT INTO instagram_campaigns (user_id, post_link, budget, total_cost, status) VALUES (?, ?, ?, ?, ?)').bind(user_id, post_link.trim(), advBudget, totalCost, 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۸. خدمات وریفای (جدید)
        if (path === 'user/verify/purchase' && method === 'POST') {
            const { user_id, service_name, price } = await request.json();
            const cost = parseFloat(price);

            if (!user_id || !service_name || isNaN(cost) || cost <= 0) return new Response(JSON.stringify({ error: 'اطلاعات سرویس نامعتبر است' }), { status: 400, headers: corsHeaders });

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < cost) return new Response(JSON.stringify({ error: 'موجودی کیف پول برای خرید این سرویس کافی نیست.' }), { status: 400, headers: corsHeaders });

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(cost, user_id),
                env.DB.prepare('INSERT INTO verify_services (user_id, service_name, price, status) VALUES (?, ?, ?, ?)').bind(user_id, service_name, cost, 'pending')
            ]);
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۹. تیکت پشتیبانی
        if (path === 'user/ticket' && method === 'POST') {
            const { user_id, subject, message } = await request.json();
            if (!subject || !message) return new Response(JSON.stringify({ error: 'موضوع و متن پیام الزامی است' }), { status: 400, headers: corsHeaders });

            await env.DB.prepare('INSERT INTO tickets (user_id, subject, message, status) VALUES (?, ?, ?, ?)').bind(user_id, subject.trim(), message.trim(), 'open').run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ==========================================
        // ۱۰. مسیرهای پنل ادمین
        // ==========================================
        if (path === 'admin/login' && method === 'POST') {
            const { username, password } = await request.json();
            if (username === ADMIN_USER && password === ADMIN_PASS) return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            return new Response(JSON.stringify({ error: 'نام کاربری یا رمز عبور ادمین اشتباه است' }), { status: 401, headers: corsHeaders });
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
                    await env.DB.batch([
                        env.DB.prepare("UPDATE deposits SET status = 'approved' WHERE id = ?").bind(deposit_id),
                        env.DB.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").bind(dep.amount_usd, dep.user_id)
                    ]);
                } else {
                    await env.DB.prepare("UPDATE deposits SET status = 'rejected' WHERE id = ?").bind(deposit_id).run();
                }
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // اکشن یکپارچه برای تایید یا رد تمام درخواست‌های مالی (کمپین‌ها و خدمات)
            if (path === 'admin/campaigns/action' && method === 'POST') {
                const { campaign_type, campaign_id, action } = await request.json();
                let table, refundAmountField;

                if (campaign_type === 'google') { table = 'google_campaigns'; refundAmountField = 'total_budget'; }
                else if (campaign_type === 'telegram') { table = 'telegram_campaigns'; refundAmountField = 'budget'; }
                else if (campaign_type === 'instagram') { table = 'instagram_campaigns'; refundAmountField = 'total_cost'; }
                else if (campaign_type === 'verify') { table = 'verify_services'; refundAmountField = 'price'; }
                else { return new Response(JSON.stringify({ error: 'نوع سرویس نامعتبر است' }), { status: 400, headers: corsHeaders }); }

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

            if (path === 'admin/tickets/reply' && method === 'POST') {
                const { ticket_id, admin_reply } = await request.json();
                await env.DB.prepare("UPDATE tickets SET admin_reply = ?, status = 'answered' WHERE id = ?").bind(admin_reply.trim(), ticket_id).run();
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }
        }

        return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers: corsHeaders });
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
}
