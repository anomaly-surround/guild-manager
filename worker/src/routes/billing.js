// Paddle webhook, free trial, checkout price lookup (public routes)

import { json, safeJson } from '../lib/http.js';
import { getUser } from '../lib/auth.js';

export const routes = [
  { method: 'POST', pattern: '/paddle/webhook', handler: async ({ request, env }) => {
    const rawBody = await request.text();
    // Verify Paddle webhook signature
    const sigHeader = request.headers.get('paddle-signature') || '';
    if (!env.PADDLE_WEBHOOK_SECRET || !sigHeader) return json({ error: 'Unauthorized' }, 403);

    // Parse ts=...;h1=... from header
    const sigParts = {};
    for (const part of sigHeader.split(';')) {
      const [k, v] = part.split('=');
      if (k && v) sigParts[k] = v;
    }
    if (!sigParts.ts || !sigParts.h1) return json({ error: 'Invalid signature format' }, 403);

    // Verify HMAC-SHA256: payload = ts:rawBody
    const payload = sigParts.ts + ':' + rawBody;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.PADDLE_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload)));
    const computed = Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    if (computed !== sigParts.h1) return json({ error: 'Invalid signature' }, 403);

    const body = JSON.parse(rawBody);
    const eventType = body.event_type;
    const data = body.data;
    const customData = data?.custom_data;
    const userId = customData?.user_id;

    if (!userId) return json({ ok: true });

    // transaction.completed — one-time purchase (lifetime)
    if (eventType === 'transaction.completed' && data?.status === 'completed') {
      const items = data.items || [];
      const isLifetime = items.some(i => String(i.price?.id) === env.PADDLE_LIFETIME_PRICE_ID);
      if (isLifetime) {
        const custId = data.customer_id || '';
        await env.DB.prepare('UPDATE users SET premium = 1, premium_type = ?, ls_customer_id = ? WHERE id = ?')
          .bind('lifetime', custId, userId).run();
      }
    }

    // subscription.created or subscription.updated with active status
    if (eventType === 'subscription.created' || (eventType === 'subscription.updated' && data?.status === 'active')) {
      const custId = data.customer_id || '';
      const nextBill = data.next_billed_at || data.current_billing_period?.ends_at;
      let until = Math.floor(Date.now() / 1000) + 35 * 86400; // default 35 days buffer
      if (nextBill) {
        until = Math.floor(new Date(nextBill).getTime() / 1000) + 3 * 86400; // next bill + 3 day buffer
      }
      await env.DB.prepare('UPDATE users SET premium = 1, premium_type = ?, premium_until = ?, ls_customer_id = ? WHERE id = ?')
        .bind('monthly', until, custId, userId).run();
    }

    // subscription.canceled, subscription.past_due, subscription.paused
    if (eventType === 'subscription.canceled' || eventType === 'subscription.paused') {
      await env.DB.prepare('UPDATE users SET premium = 0, premium_type = NULL, premium_until = NULL WHERE id = ?')
        .bind(userId).run();
    }

    return json({ ok: true });
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

  // POST /api/checkout — return Paddle price IDs for client-side checkout
  { method: 'POST', pattern: '/api/checkout', handler: async ({ request, env }) => {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);

    const priceId = body.type === 'lifetime' ? env.PADDLE_LIFETIME_PRICE_ID : env.PADDLE_MONTHLY_PRICE_ID;
    if (!priceId) return json({ error: 'Price not configured' }, 500);

    return json({ priceId, userId: user.userId });
  } },
];
