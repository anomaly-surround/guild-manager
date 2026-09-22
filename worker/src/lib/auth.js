// Token auth: HMAC-SHA256 JWT-style tokens + request -> user

export async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)))));
  return `${data}.${sig}`;
}

export async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;
    const [header, body, sig] = parts;
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const expected = new Uint8Array(atob(sig).split('').map(c => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify('HMAC', key, expected, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  let token = auth.replace('Bearer ', '');
  // Accept token via query param ONLY for download/export routes (browser new tab)
  if (!token) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path.includes('/download') || path.includes('/export')) {
      token = url.searchParams.get('token') || '';
    }
  }
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}
