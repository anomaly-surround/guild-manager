// Billing (public routes): Gumroad ping, license activation, free trial, checkout link.
// All verification logic lives in lib/gumroad.js.

import { json, safeJson } from '../lib/http.js';
import { getUser } from '../lib/auth.js';
import { bindLicense, checkoutUrl, configuredProductFromPing } from '../lib/gumroad.js';

export const routes = [
  // POST /gumroad/ping — Gumroad's sale webhook (x-www-form-urlencoded, unsigned). Fires on every
  // sale and every recurring membership charge. The license key it carries is verified with Gumroad
  // before anything is granted. url_params[uid] is the buyer's account id attached to the checkout
  // link; without it the key is matched to an account that already activated it, or left for the
  // buyer to enter in the app.
  // Gumroad gives up on a slow response (pings from its IAD path took 6–15 s here, 2026-09-23), so
  // the request is acknowledged as soon as the body is parsed and the verification runs in
  // ctx.waitUntil. Failures are covered by the daily recheck and the paste-your-key path.
  { method: 'POST', pattern: '/gumroad/ping', handler: async ({ request, env, ctx }) => {
    const t0 = Date.now(); const lap = (what) => console.log(`gumroad ping +${Date.now() - t0}ms ${what}`);
    let form;
    try { form = await request.formData(); } catch { return json({ ok: true, ignored: 'unreadable body' }); }
    lap('body read');
    const licenseKey = String(form.get('license_key') || '').trim();
    const productId = configuredProductFromPing(env, form);
    // Visible in `wrangler tail`: which product/url_params Gumroad actually sends.
    console.log('gumroad ping', JSON.stringify({ product_id: form.get('product_id'), permalink: form.get('permalink'), product_permalink: form.get('product_permalink'),
      matched: productId || null, key: licenseKey ? licenseKey.slice(0, 8) + '…' : null, test: form.get('test'), recurring: form.get('is_recurring_charge'),
      url_params: [...form.keys()].filter(k => k.startsWith('url_params')).map(k => `${k}=${form.get(k)}`) }));
    if (!licenseKey || !productId) return json({ ok: true, ignored: 'not a premium product' });

    let userId = String(form.get('url_params[uid]') || '').trim();
    if (!userId) {
      const existing = await env.DB.prepare('SELECT id FROM users WHERE gumroad_license = ?').bind(licenseKey).first();
      userId = existing ? existing.id : '';
    }
    if (!userId) return json({ ok: true, ignored: 'no account attached; buyer can enter the key in the app' });
    lap('user resolved');

    const work = bindLicense(env, userId, licenseKey, productId, lap)
      .then(r => lap(`done granted=${r.ok} ${r.plan || r.error || ''}`))
      .catch(e => console.error('gumroad ping bind error:', e));
    if (ctx?.waitUntil) { ctx.waitUntil(work); return json({ ok: true, queued: true }); }
    await work;   // local harness / tests: synchronous
    return json({ ok: true, queued: false });
  } },

  // POST /api/activate-license { licenseKey } — the buyer pastes the key Gumroad emailed them.
  { method: 'POST', pattern: '/api/activate-license', handler: async ({ request, env }) => {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const body = await safeJson(request);
    const licenseKey = String(body?.licenseKey || '').trim().toUpperCase();
    if (!/^[A-Z0-9-]{8,64}$/.test(licenseKey)) return json({ error: 'That does not look like a Gumroad license key' }, 400);

    const r = await bindLicense(env, user.userId, licenseKey);
    if (!r.ok) return json({ error: r.error }, r.transient ? 503 : 400);
    return json({ ok: true, plan: r.plan });
  } },

  // POST /api/start-trial — start 7-day free trial
  { method: 'POST', pattern: '/api/start-trial', handler: async ({ request, env }) => {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) return json({ error: 'User not found' }, 404);
    if (dbUser.auth_type === 'guest') return json({ error: 'Sign in with Discord or Google to start a trial' }, 400);
    if (dbUser.premium) return json({ error: 'Already premium' }, 400);
    if (dbUser.trial_started || dbUser.trial_used) return json({ error: 'Trial already used' }, 400);

    await env.DB.prepare('UPDATE users SET trial_started = ? WHERE id = ?')
      .bind(Math.floor(Date.now() / 1000), user.userId).run();

    return json({ ok: true, trialDaysLeft: 7 });
  } },

  // POST /api/checkout { type: 'monthly' | 'lifetime' } — Gumroad product link for this account
  { method: 'POST', pattern: '/api/checkout', handler: async ({ request, env }) => {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const body = await safeJson(request);
    if (!body) return json({ error: 'Invalid request body' }, 400);

    const plan = body.type === 'lifetime' ? 'lifetime' : 'monthly';
    const url = checkoutUrl(env, plan, user.userId);
    if (!url) return json({ error: 'Checkout is not configured yet' }, 500);
    return json({ url, plan });
  } },
];
