export async function onRequest({ request }) {
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
    };

    if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }
    if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405, headers: corsHeaders
        });
    }

    // CoinGecko requires a descriptive User-Agent. Other sources are public
    // market endpoints and do not require a personal API key.
    const headers = {
        'Accept': 'application/json',
        'User-Agent': 'IranAdsNetwork/1.0 (https://iranadsnetwork.ir; TRX price widget)'
    };

    const providers = [
        {
            name: 'CoinGecko',
            url: 'https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=usd',
            read: data => data?.tron?.usd
        },
        {
            name: 'Kraken TRX/USD',
            url: 'https://api.kraken.com/0/public/Ticker?pair=TRXUSD',
            read: data => {
                const ticker = data?.result?.TRXUSD || Object.values(data?.result || {})[0];
                return ticker?.c?.[0];
            }
        },
        {
            name: 'OKX TRX/USDT',
            url: 'https://www.okx.com/api/v5/market/ticker?instId=TRX-USDT',
            read: data => data?.data?.[0]?.last
        },
        {
            name: 'Bybit TRX/USDT',
            url: 'https://api.bybit.com/v5/market/tickers?category=spot&symbol=TRXUSDT',
            read: data => data?.result?.list?.[0]?.lastPrice
        },
        {
            name: 'DefiLlama',
            url: 'https://coins.llama.fi/prices/current/coingecko:tron',
            read: data => data?.coins?.['coingecko:tron']?.price
        }
    ];

    const results = await Promise.all(providers.map(async provider => {
        try {
            const response = await fetch(provider.url, {
                headers,
                signal: AbortSignal.timeout(5000)
            });
            const body = await response.text();
            if (!response.ok) {
                return {
                    provider: provider.name,
                    ok: false,
                    status: response.status,
                    error: body.slice(0, 300) || response.statusText
                };
            }

            let data;
            try { data = JSON.parse(body); }
            catch (_) {
                return { provider: provider.name, ok: false, error: 'Invalid JSON response' };
            }

            const price = Number(provider.read(data));
            if (!Number.isFinite(price) || price <= 0) {
                return {
                    provider: provider.name,
                    ok: false,
                    error: data?.error || data?.msg || 'Price field missing or invalid'
                };
            }

            return { provider: provider.name, ok: true, price };
        } catch (error) {
            return {
                provider: provider.name,
                ok: false,
                error: error?.message || String(error),
                error_name: error?.name || 'Error'
            };
        }
    }));

    // Preserve provider priority while querying all sources concurrently.
    const winner = results.find(result => result.ok);
    if (winner) {
        const price = winner.price;
        return new Response(JSON.stringify({
            success: true,
            price_usd: price,
            usdt_per_trx: price,
            trx_per_usd: 1 / price,
            source: winner.provider,
            updated_at: new Date().toISOString()
        }), {
            headers: { ...corsHeaders, 'Cache-Control': 'public, max-age=30, s-maxage=30' }
        });
    }

    return new Response(JSON.stringify({
        success: false,
        error: 'دریافت نرخ از تمام منابع قیمت ناموفق بود.',
        diagnostics: results
    }), { status: 503, headers: corsHeaders });
}
