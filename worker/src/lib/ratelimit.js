// In-memory per-isolate rate limiter

const rateLimitMap = new Map();

export function rateLimit(key, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now - entry.start > windowMs) {
    rateLimitMap.set(key, { start: now, count: 1 });
    return false; // not limited
  }
  entry.count++;
  if (entry.count > maxRequests) return true; // limited
  return false;
}

// Clean up stale entries periodically
export function cleanRateLimits() {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.start > 120000) rateLimitMap.delete(key);
  }
}
