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

    const providers = [
        {
            name: 'CoinGecko',
            url: 'https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=usd',
            read: data => data?.tron?.usd
        },
        {
            name: 'Binance TRX/USDT',
            url: 'https://api.binance.com/api/v3/ticker/price?symbol=TRXUSDT',
            read: data => data?.price
        },
        {
            name: 'CryptoCompare',
            url: 'https://min-api.cryptocompare.com/data/price?fsym=TRX&tsyms=USD',
            read: data => data?.USD
        },
        {
            name: 'CoinCap',
            url: 'https://api.coincap.io/v2/assets/tron',
            read: data => data?.data?.priceUsd
        },
        {
            name: 'CoinPaprika',
            url: 'https://api.coinpaprika.com/v1/tickers/trx-tron',
            read: data => data?.quotes?.USD?.price
        }
    ];

    const diagnostics = [];
    for (const provider of providers) {
        try {
            const response = await fetch(provider.url, {
                headers: { 'Accept': 'application/json' },
                signal: AbortSignal.timeout(5000)
            });
            if (!response.ok) {
                let responseBody = '';
                try { responseBody = (await response.text()).slice(0, 350); } catch (_) {}
                diagnostics.push({
                    provider: provider.name,
                    status: response.status,
                    status_text: response.statusText,
                    error: responseBody || 'Provider returned a non-success HTTP status'
                });
                continue;
            }
            const data = await response.json();
            const price = Number(provider.read(data));
            if (Number.isFinite(price) && price > 0) {
                return new Response(JSON.stringify({
                    success: true,
                    price_usd: price,
                    usdt_per_trx: price,
                    trx_per_usd: 1 / price,
                    source: provider.name,
                    updated_at: new Date().toISOString()
                }), { headers: { ...corsHeaders, 'Cache-Control': 'public, max-age=30, s-maxage=30' } });
            }
            diagnostics.push({ provider: provider.name, error: 'Invalid price response' });
        } catch (error) {
            diagnostics.push({ provider: provider.name, error: error?.message || String(error), error_name: error?.name || 'Error' });
        }
    }

    return new Response(JSON.stringify({
        success: false,
        error: 'دریافت نرخ از تمام منابع قیمت ناموفق بود.',
        diagnostics
    }), { status: 503, headers: corsHeaders });
}
