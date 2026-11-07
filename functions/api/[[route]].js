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

    // خواندن نام کاربری و رمز ادمین از Environment Variables کلودفلر
    const ADMIN_USER = env.ADMIN_USER || "admin";
    const ADMIN_PASS = env.ADMIN_PASS || "admin123456";

    try {
        // ۱. ورود مشتری در dashboard.html
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

        // ۲. دریافت اطلاعات داشبورد مشتری + آدرس کیف پول‌ها
        if (path === 'user/data' && method === 'GET') {
            const userId = url.searchParams.get('user_id');
            const user = await env.DB.prepare('SELECT id, username, balance FROM users WHERE id = ?').bind(userId).first();
            if (!user) return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { status: 404, headers: corsHeaders });

            const deposits = await env.DB.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const campaigns = await env.DB.prepare('SELECT * FROM google_campaigns WHERE user_id = ? ORDER BY id DESC').bind(userId).all();
            const settingsRows = await env.DB.prepare('SELECT * FROM settings').all();

            const wallets = { usdt: '', trx: '' };
            for (const row of settingsRows.results) {
                if (row.key === 'wallet_usdt') wallets.usdt = row.value;
                if (row.key === 'wallet_trx') wallets.trx = row.value;
            }

            return new Response(JSON.stringify({
                user,
                deposits: deposits.results,
                campaigns: campaigns.results,
                wallets
            }), { headers: corsHeaders });
        }

        // ۳. ثبت فیش واریزی کریپتو توسط مشتری
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

        // ۴. ثبت کمپین گوگل توسط مشتری و کسر بودجه
        if (path === 'user/campaign/google' && method === 'POST') {
            const { user_id, website_url, budget_search, budget_display, budget_youtube } = await request.json();
            const s = parseFloat(budget_search) || 0;
            const d = parseFloat(budget_display) || 0;
            const y = parseFloat(budget_youtube) || 0;
            const total = s + d + y;

            if (total <= 0 || !website_url) {
                return new Response(JSON.stringify({ error: 'لطفاً آدرس وب‌سایت و حداقل یکی از بودجه‌ها را وارد کنید' }), { status: 400, headers: corsHeaders });
            }

            const user = await env.DB.prepare('SELECT balance FROM users WHERE id = ?').bind(user_id).first();
            if (!user || user.balance < total) {
                return new Response(JSON.stringify({ error: 'موجودی کیف پول شما کافی نیست. لطفاً ابتدا از بخش امور مالی حساب خود را شارژ کنید.' }), { status: 400, headers: corsHeaders });
            }

            await env.DB.batch([
                env.DB.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').bind(total, user_id),
                env.DB.prepare(
                    'INSERT INTO google_campaigns (user_id, website_url, budget_search, budget_display, budget_youtube, total_budget) VALUES (?, ?, ?, ?, ?, ?)'
                ).bind(user_id, website_url.trim(), s, d, y, total)
            ]);

            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }

        // ==========================================
        // ۵. مسیرهای مدیریتی ادمین (admin.html)
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
                return new Response(JSON.stringify({ error: 'نشست شما منقضی شده یا دسترسی غیرمجاز است' }), { status: 403, headers: corsHeaders });
            }

            // دریافت کل اطلاعات در پنل ادمین
            if (path === 'admin/overview' && method === 'GET') {
                const users = await env.DB.prepare('SELECT id, username, password, balance, created_at FROM users ORDER BY id DESC').all();
                const deposits = await env.DB.prepare(`
                    SELECT deposits.*, users.username 
                    FROM deposits 
                    JOIN users ON deposits.user_id = users.id 
                    ORDER BY deposits.id DESC
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
                    wallets
                }), { headers: corsHeaders });
            }

            // بروزرسانی آدرس کیف پول‌ها توسط ادمین
            if (path === 'admin/settings/wallet' && method === 'POST') {
                const { wallet_usdt, wallet_trx } = await request.json();
                await env.DB.batch([
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_usdt', ?)").bind(wallet_usdt.trim()),
                    env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('wallet_trx', ?)").bind(wallet_trx.trim())
                ]);
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // ساخت کاربر جدید توسط ادمین
            if (path === 'admin/users' && method === 'POST') {
                const { username, password, initial_balance } = await request.json();
                await env.DB.prepare(
                    'INSERT INTO users (username, password, balance) VALUES (?, ?, ?)'
                ).bind(username.trim(), password.trim(), parseFloat(initial_balance) || 0).run();

                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // تایید یا رد واریزی و شارژ خودکار حساب کاربر
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
        }

        return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers: corsHeaders });
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
}
