// ۱. ثبت‌نام مستقیم کاربر با ایمیل و نام کاربری + بررسی امنیت رمز عبور
        if (path === 'register' && method === 'POST') {
            const { username, email, password } = await request.json();
            if (!username || !email || !password) {
                return new Response(JSON.stringify({ error: 'لطفاً نام کاربری، ایمیل و رمز عبور را کامل وارد کنید' }), { status: 400, headers: corsHeaders });
            }

            const cleanUser = username.trim();
            const cleanEmail = email.trim().toLowerCase();
            const cleanPass = password.trim();

            // بررسی سخت‌گیرانه رمز عبور: حداقل ۱۰ کاراکتر، حرف بزرگ، حرف کوچک و علامت
            const hasMinLen = cleanPass.length >= 10;
            const hasUpper = /[A-Z]/.test(cleanPass);
            const hasLower = /[a-z]/.test(cleanPass);
            const hasSymbol = /[^A-Za-z0-9]/.test(cleanPass);

            if (!hasMinLen || !hasUpper || !hasLower || !hasSymbol) {
                return new Response(JSON.stringify({ 
                    error: 'رمز عبور باید حداقل ۱۰ کاراکتر بوده و شامل حروف بزرگ، حروف کوچک انگلیسی و حداقل یک علامت (مثل @#$%) باشد.' 
                }), { status: 400, headers: corsHeaders });
            }

            const existing = await env.DB.prepare(
                'SELECT id FROM users WHERE username = ? OR email = ?'
            ).bind(cleanUser, cleanEmail).first();

            if (existing) {
                return new Response(JSON.stringify({ error: 'این نام کاربری یا ایمیل قبلاً ثبت شده است' }), { status: 400, headers: corsHeaders });
            }

            const result = await env.DB.prepare(
                'INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, 0.0)'
            ).bind(cleanUser, cleanEmail, cleanPass).run();

            const newUser = await env.DB.prepare(
                'SELECT id, username, email, balance FROM users WHERE id = ?'
            ).bind(result.meta.last_row_id).first();

            return new Response(JSON.stringify({ user: newUser }), { headers: corsHeaders });
        }
