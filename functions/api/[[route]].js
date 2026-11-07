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
        // ۱. ورود مشتری
        if (path === 'login' && method === 'POST') {
            const { username, password } = await request.json();
            const user = await env.DB.prepare(
                'SELECT id, username, balance FROM users WHERE username = ? AND password = ?'
            ).bind(username, password).first();

            if (!user) {
                return new Response(JSON.stringify({ error: 'نام کاربری یا رمز عبور اشتباه است' }), { status: 401, headers: corsHeaders });
            }
            return new Response(JSON.stringify({ user }), { headers: corsHeaders });
        }

        // ۲. دریافت اطلاعات داشبورد مشتری
        if (path === 'user/data' && method === 'GET') {
            const userId = url.searchParams.get('user_id');
            const user = await env.DB.prepare('SELECT id, username, balance FROM users WHERE id = ?').bind(userId).first();
            if (!user) return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { status: 404, headers: corsHeaders });

            const deposits = await env.DB.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const googleCampaigns = await env.DB.prepare('SELECT * FROM google_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const telegramCampaigns = await env.DB.prepare('SELECT * FROM telegram_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const settingsRows = await env.DB.prepare('SELECT * FROM settings').all();

            const wallets = { usdt: '', trx: '' };
            for (const row of settingsRows.results) {
                if (row.key === 'wallet_usdt') wallets.usdt = row.value;
                if (row.key === 'wallet_trx') wallets.trx = row.value;
            }

            return new Response(JSON.stringify({
                user,
                deposits: deposits.results,
                google_campaigns: googleCampaigns.results,
                telegram_campaigns: telegramCampaigns.results,
                wallets
            }), { headers: corsHeaders });
        }

        // ۳. ثبت فیش واریزی کریپتو
        if (path === 'user/deposit' && method === 'POST') {
            const { user_id, amount_usd, crypto_type, tx_hash } = await request.json();
            if (!amount_usd || amount_usd <= 0 || !tx_hash) {
                return new Response(JSON.stringify({ error: 'لطفاً مبلغ و کد هش تراکنش را به درستی وارد کنید' }), { status: 400, headers: corsHeaders });
            }
            await env.DB.prepare(
                'INSERT INTO deposits (user_id, amount_usd, crypto_type, tx_hash) VALUES (?, ?, ?, ?)'
            ).bind(user_id, parseFloat(amount_usd), crypto_type, tx_hash.trim()).run();

            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۴. ثبت کمپین گوگل (همراه با معرفی محصول و کلمات کلیدی + بررسی موجودی)
        if (path === 'user/campaign/google' && method === 'POST') {
            const { user_id, website_url, product_info, keywords, budget_search, budget_display, budget_youtube } = await request.json();
            const s = parseFloat(budget_search) || 0;
            const d = parseFloat(budget_display) || 0;
            const y = parseFloat(budget_youtube) || 0;
            const total = s + d + y;

            if (total <= 0 || !website_url || !product_info || !keywords) {
                return new Response(JSON.stringify({ error: 'لطفاً تمام فیلدها (آدرس سایت، معرفی محصول، کلمات کلیدی) و حداقل یکی از بودجه‌ها را وارد کنید' }), { status: 400, headers: corsHeaders });
            }

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) {
                return new Response(JSON.stringify({ error: 'مجموع بودجه انتخابی از موجودی کیف پول شما بیشتر است. لطفاً ابتدا حساب خود را شارژ کنید.' }), { status: 400, headers: corsHeaders });
            }

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(total, user_id),
                env.DB.prepare(
                    'INSERT INTO google_campaigns (user_id, website_url, product_info, keywords, budget_search, budget_display, budget_youtube, total_budget, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
                ).bind(user_id, website_url.trim(), product_info.trim(), keywords.trim(), s, d, y, total, 'pending')
            ]);

            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ۵. ثبت کمپین تلگرام + بررسی موجودی
        if (path === 'user/campaign/telegram' && method === 'POST') {
            const { user_id, channel_url, budget, description } = await request.json();
            const total = parseFloat(budget) || 0;

            if (total <= 0 || !channel_url || !description) {
                return new Response(JSON.stringify({ error: 'لطفاً آدرس کانال، بودجه و توضیحات کمپین تلگرام را کامل وارد کنید' }), { status: 400, headers: corsHeaders });
            }

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) {
                return new Response(JSON.stringify({ error: 'بودجه وارد شده از موجودی کیف پول شما بیشتر است. لطفاً ابتدا کیف پول را شارژ کنید.' }), { status: 400, headers: corsHeaders });
            }

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(total, user_id),
                env.DB.prepare(
                    'INSERT INTO telegram_campaigns (user_id, channel_url, budget, description, status) VALUES (?, ?, ?, ?, ?)'
                ).bind(user_id, channel_url.trim(), total, description.trim(), 'pending')
            ]);

            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ==========================================
        // ۶. مسیرهای پنل ادمین (admin.html)
        // ==========================================
        if (path === 'admin/login' && method === 'POST') {
            const { username, password } = await request.json();
            if (username === ADMIN_USER && password === ADMIN_PASS) {
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }
            return new Response(JSON.stringify({ error: 'نام کاربری یا رمز عبور ادمین اشتباه است' }), { status: 401, headers: corsHeaders });
        }

        if (path.startsWith('admin/')) {
            const reqUser = request.headers.get('X-Admin-User');
            const reqPass = request.headers.get('X-Admin-Pass');

            if (reqUser !== ADMIN_USER || reqPass !== ADMIN_PASS) {
                return new Response(JSON.stringify({ error: 'عدم دسترسی مجاز' }), { status: 403, headers: corsHeaders });
            }

            // دریافت کل اطلاعات در پنل ادمین
            if (path === 'admin/overview' && method === 'GET') {
                const users = await env.DB.prepare('SELECT id, username, password, balance, created_at FROM users ORDER BY id DESC').all();
                const deposits = await env.DB.prepare(`
                    SELECT deposits.*, users.username 
                    FROM deposits JOIN users ON deposits.user_id = users.id 
                    ORDER BY deposits.id DESC
                `).all();
                const googleCampaigns = await env.DB.prepare(`
                    SELECT google_campaigns.*, users.username 
                    FROM google_campaigns JOIN users ON google_campaigns.user_id = users.id 
                    ORDER BY google_campaigns.id DESC
                `).all();
                const telegramCampaigns = await env.DB.prepare(`
                    SELECT telegram_campaigns.*, users.username 
                    FROM telegram_campaigns JOIN users ON telegram_campaigns.user_id = users.id 
                    ORDER BY telegram_campaigns.id DESC
                `).all();
                const settingsRows = await env.DB.prepare('SELECT * FROM settings').all();

                const wallets = { usdt: '', trx: '' };
                for (const row of settingsRows.results) {
                    if (row.key === 'wallet_usdt') wallets.usdt = row.value;
                    if (row.key === 'wallet_trx') wallets.trx = row.value;
                }

                return new Response(JSON.stringify({
                    users: users.results,
                    deposits: deposits.results,
                    google_campaigns: googleCampaigns.results,
                    telegram_campaigns: telegramCampaigns.results,
                    wallets
                }), { headers: corsHeaders });
            }

            // ذخیره آدرس کیف پول‌ها
            if (path === 'admin/settings/wallet' && method === 'POST') {
                const { wallet_usdt, wallet_trx } = await request.json();
                await env.DB.batch([
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_usdt', ?)").bind(wallet_usdt.trim()),
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_trx', ?)").bind(wallet_trx.trim())
                ]);
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // ساخت کاربر جدید
            if (path === 'admin/users' && method === 'POST') {
                const { username, password, initial_balance } = await request.json();
                await env.DB.prepare(
                    'INSERT INTO users (username, password, balance) VALUES (?, ?, ?)'
                ).bind(username.trim(), password.trim(), parseFloat(initial_balance) || 0).run();
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // تایید یا رد واریزی
            if (path === 'admin/deposits/action' && method === 'POST') {
                const { deposit_id, action } = await request.json();
                const dep = await env.DB.prepare('SELECT * FROM deposits WHERE id = ?').bind(deposit_id).first();
                if (!dep || dep.status !== 'pending') {
                    return new Response(JSON.stringify({ error: 'این تراکنش قبلاً بررسی شده است' }), { status: 400, headers: corsHeaders });
                }

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

            // تایید و شروع یا رد کمپین‌ها (گوگل و تلگرام)
            if (path === 'admin/campaigns/action' && method === 'POST') {
                const { campaign_type, campaign_id, action } = await request.json(); // action: 'approve' | 'reject'

                if (campaign_type === 'google') {
                    const camp = await env.DB.prepare('SELECT * FROM google_campaigns WHERE id = ?').bind(campaign_id).first();
                    if (!camp || camp.status !== 'pending') {
                        return new Response(JSON.stringify({ error: 'این کمپین قبلاً تعیین وضعیت شده است' }), { status: 400, headers: corsHeaders });
                    }
                    if (action === 'approve') {
                        await env.DB.prepare("UPDATE google_campaigns SET status = 'active' WHERE id = ?").bind(campaign_id).run();
                    } else {
                        // در صورت رد شدن توسط ادمین، بودجه به کیف پول کاربر برمی‌گردد
                        await env.DB.batch([
                            env.DB.prepare("UPDATE google_campaigns SET status = 'rejected' WHERE id = ?").bind(campaign_id),
                            env.DB.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").bind(camp.total_budget, camp.user_id)
                        ]);
                    }
                } else if (campaign_type === 'telegram') {
                    const camp = await env.DB.prepare('SELECT * FROM telegram_campaigns WHERE id = ?').bind(campaign_id).first();
                    if (!camp || camp.status !== 'pending') {
                        return new Response(JSON.stringify({ error: 'این کمپین قبلاً تعیین وضعیت شده است' }), { status: 400, headers: corsHeaders });
                    }
                    if (action === 'approve') {
                        await env.DB.prepare("UPDATE telegram_campaigns SET status = 'active' WHERE id = ?").bind(campaign_id).run();
                    } else {
                        await env.DB.batch([
                            env.DB.prepare("UPDATE telegram_campaigns SET status = 'rejected' WHERE id = ?").bind(campaign_id),
                            env.DB.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").bind(camp.budget, camp.user_id)
                        ]);
                    }
                }

                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }
        }

        return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers: corsHeaders });
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
}
