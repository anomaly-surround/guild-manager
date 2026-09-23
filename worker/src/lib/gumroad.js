// Gumroad billing: checkout URLs, license verification, granting/revoking premium, periodic recheck.
//
// Gumroad's Ping webhook is unsigned, so nothing in a ping is trusted on its own: every path
// (ping, manual activation, daily recheck) verifies the license key against Gumroad's license
// API, which needs no access token. Premium is then derived from the verified purchase.
//
// Config (wrangler.toml [vars]): GUMROAD_MONTHLY_URL, GUMROAD_LIFETIME_URL (product links),
// GUMROAD_MONTHLY_PRODUCT_ID, GUMROAD_LIFETIME_PRODUCT_ID — either the product's permalink (the
// `vbeeit` part of the link; what the editor shows) or its long product id; the license API takes
// both. GUMROAD_API overrides the API base for local tests.

const API_DEFAULT = 'https://api.gumroad.com';
export const RECHECK_AFTER_SEC = 20 * 3600;   // re-verify each stored license at most once per 20 h
const RETRY_AFTER_SEC = 3600;                 // when Gumroad is unreachable, try that license again in 1 h
const MONTHLY_GRACE_SEC = 35 * 86400;         // access granted per verified check of a monthly license

export function planForProduct(env, productId) {
  if (!productId) return null;
  if (productId === env.GUMROAD_MONTHLY_PRODUCT_ID) return 'monthly';
  if (productId === env.GUMROAD_LIFETIME_PRODUCT_ID) return 'lifetime';
  return null;
}

// A Ping names the product three ways (long id, permalink, full product link); whichever one
// matches the configured value wins, so the config may hold either form.
export function configuredProductFromPing(env, form) {
  const link = String(form.get('product_permalink') || '');
  const candidates = [form.get('product_id'), form.get('permalink'), form.get('short_product_id'), link.split('/').filter(Boolean).pop()]
    .map(v => String(v || '').trim()).filter(Boolean);
  return candidates.find(c => planForProduct(env, c)) || '';
}

// Long product ids are base64 (end in '=' and are far longer than a permalink).
function productParam(productId) {
  return /^[A-Za-z0-9+/]{16,}={0,2}$/.test(productId) && productId.length > 20 ? 'product_id' : 'product_permalink';
}

function productForPlan(env, plan) {
  return plan === 'lifetime' ? env.GUMROAD_LIFETIME_PRODUCT_ID : env.GUMROAD_MONTHLY_PRODUCT_ID;
}

// Product link with the buyer's user id attached; Gumroad forwards unknown query params
// to the Ping as url_params[uid], and ?wanted=true skips straight to checkout.
export function checkoutUrl(env, plan, userId) {
  const base = plan === 'lifetime' ? env.GUMROAD_LIFETIME_URL : env.GUMROAD_MONTHLY_URL;
  if (!base) return null;
  const u = new URL(base);
  u.searchParams.set('wanted', 'true');
  u.searchParams.set('uid', userId);
  return u.toString();
}

// -> { ok: true, purchase } | { ok: false, error, transient? }
export async function verifyLicense(env, productId, licenseKey) {
  const body = new URLSearchParams({ [productParam(productId)]: productId, license_key: licenseKey, increment_uses_count: 'false' });
  let r;
  try {
    r = await fetch(`${env.GUMROAD_API || API_DEFAULT}/v2/licenses/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
  } catch (e) {
    return { ok: false, error: 'Could not reach Gumroad, try again in a minute', transient: true };
  }
  if (r.status >= 500) return { ok: false, error: 'Gumroad is having trouble, try again in a minute', transient: true };
  const data = await r.json().catch(() => null);
  if (!data || !data.success || !data.purchase) return { ok: false, error: (data && data.message) || 'That license key was not found' };
  return { ok: true, purchase: data.purchase };
}

// Gumroad sets the three subscription_* timestamps to the membership END date (not the date the
// cancellation was requested) and clears them again when the membership renews or restarts.
export function licenseStatus(purchase) {
  if (purchase.refunded) return { active: false, reason: 'This purchase was refunded' };
  if (purchase.chargebacked) return { active: false, reason: 'This purchase was charged back' };
  if (purchase.subscription_ended_at || purchase.subscription_cancelled_at || purchase.subscription_failed_at) {
    return { active: false, reason: 'This membership has ended' };
  }
  return { active: true };
}

export async function grantLicense(env, userId, plan, licenseKey, productId) {
  const now = Math.floor(Date.now() / 1000);
  const until = plan === 'lifetime' ? null : now + MONTHLY_GRACE_SEC;
  await env.DB.prepare('UPDATE users SET premium = 1, premium_type = ?, premium_until = ?, gumroad_license = ?, gumroad_product = ?, license_checked_at = ? WHERE id = ?')
    .bind(plan, until, licenseKey, productId, now, userId).run();
}

// Premium off, license kept: a membership that restarts is picked up again by the recheck.
export async function revokeLicense(env, userId) {
  await env.DB.prepare('UPDATE users SET premium = 0, premium_type = NULL, premium_until = NULL, license_checked_at = ? WHERE id = ?')
    .bind(Math.floor(Date.now() / 1000), userId).run();
}

async function touchLicense(env, userId, checkedAt) {
  await env.DB.prepare('UPDATE users SET license_checked_at = ? WHERE id = ?').bind(checkedAt, userId).run();
}

// Verify a key and attach it to a user. productId may be omitted (manual activation): both
// products are tried. -> { ok: true, plan } | { ok: false, error, transient? }
export async function bindLicense(env, userId, licenseKey, productId) {
  const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
  if (!user) return { ok: false, error: 'Unknown account' };

  const candidates = productId ? [productId] : [productForPlan(env, 'monthly'), productForPlan(env, 'lifetime')].filter(Boolean);
  let last = { ok: false, error: 'Billing is not configured' };
  for (const pid of candidates) {
    const plan = planForProduct(env, pid);
    if (!plan) continue;
    const v = await verifyLicense(env, pid, licenseKey);
    last = v;
    if (v.transient) return v;
    if (!v.ok) continue;

    const status = licenseStatus(v.purchase);
    if (!status.active) return { ok: false, error: status.reason };

    const other = await env.DB.prepare('SELECT id FROM users WHERE gumroad_license = ? AND id != ?').bind(licenseKey, userId).first();
    if (other) return { ok: false, error: 'This license key is already in use on another account' };

    await grantLicense(env, userId, plan, licenseKey, pid);
    return { ok: true, plan };
  }
  return { ok: false, error: last.error || 'That license key was not found' };
}

// Cron: re-verify stored licenses whose last check is older than RECHECK_AFTER_SEC, a few per
// tick. Keeps monthly access rolling while the membership is live and revokes it within a day of
// Gumroad reporting an end, refund or chargeback. Self-paced, so a missed tick costs nothing.
export async function recheckLicenses(env, limit = 10) {
  const now = Math.floor(Date.now() / 1000);
  const due = await env.DB.prepare(
    'SELECT id, gumroad_license, gumroad_product FROM users WHERE gumroad_license IS NOT NULL AND (license_checked_at IS NULL OR license_checked_at < ?) LIMIT ?'
  ).bind(now - RECHECK_AFTER_SEC, limit).all();

  for (const u of due.results) {
    try {
      const plan = planForProduct(env, u.gumroad_product);
      if (!plan) { await touchLicense(env, u.id, now); continue; }   // product no longer configured: leave as is
      const v = await verifyLicense(env, u.gumroad_product, u.gumroad_license);
      if (v.transient) { await touchLicense(env, u.id, now - RECHECK_AFTER_SEC + RETRY_AFTER_SEC); continue; }
      if (v.ok && licenseStatus(v.purchase).active) await grantLicense(env, u.id, plan, u.gumroad_license, u.gumroad_product);
      else await revokeLicense(env, u.id);
    } catch (e) { console.error('License recheck error:', u.id, e); }
  }
  return due.results.length;
}
