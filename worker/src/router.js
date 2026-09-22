// Request pipeline. Reproduces the original single-file worker's order exactly:
// OPTIONS -> schema init -> auth rate-limit -> public routes -> auth guard -> protected routes -> 404.
//
// A route is { method, pattern, handler }. method '*' matches any verb. pattern is an exact
// path string or a RegExp; the RegExp match array is passed to the handler as ctx.params.
import { json, corsHeaders } from './lib/http.js';
import { getUser } from './lib/auth.js';
import { rateLimit, cleanRateLimits } from './lib/ratelimit.js';
import { ensureSchema } from './db/schema.js';

import { routes as authRoutes } from './routes/auth.js';
import { routes as billingRoutes } from './routes/billing.js';
import { routes as teamRoutes } from './routes/teams.js';
import { routes as inviteRoutes } from './routes/invites.js';
import { routes as bossRoutes } from './routes/bosses.js';
import { routes as settingsRoutes } from './routes/settings.js';
import { routes as eventRoutes } from './routes/events.js';
import { routes as announcementRoutes } from './routes/announcements.js';
import { routes as memberRoutes } from './routes/members.js';
import { routes as chatRoutes } from './routes/chat.js';
import { routes as lootRoutes } from './routes/loot.js';
import { routes as dkpRoutes } from './routes/dkp.js';
import { routes as warRoutes } from './routes/wars.js';
import { routes as analyticsRoutes } from './routes/analytics.js';
import { routes as pollRoutes } from './routes/polls.js';
import { routes as rosterRoutes } from './routes/rosters.js';
import { routes as performanceRoutes } from './routes/performance.js';
import { routes as recruitmentRoutes } from './routes/recruitment.js';
import { routes as fileRoutes } from './routes/files.js';

const PUBLIC_ROUTES = [...authRoutes, ...billingRoutes];
const PROTECTED_ROUTES = [
  ...teamRoutes, ...inviteRoutes, ...bossRoutes, ...settingsRoutes, ...eventRoutes,
  ...announcementRoutes, ...memberRoutes, ...chatRoutes, ...lootRoutes, ...dkpRoutes,
  ...warRoutes, ...analyticsRoutes, ...pollRoutes, ...rosterRoutes, ...performanceRoutes,
  ...recruitmentRoutes, ...fileRoutes,
];

function matchRoute(routes, method, path) {
  for (const r of routes) {
    if (r.method !== '*' && r.method !== method) continue;
    if (typeof r.pattern === 'string') {
      if (path === r.pattern) return { route: r, params: null };
    } else {
      const m = path.match(r.pattern);
      if (m) return { route: r, params: m };
    }
  }
  return null;
}

export async function handleRequest(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  await ensureSchema(env);

  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  cleanRateLimits();
  if (path.startsWith('/auth/') && path !== '/auth/me') {
    if (rateLimit(`auth:${clientIP}`, 10, 60000)) {
      return json({ error: 'Too many requests. Try again later.' }, 429);
    }
  }

  const pub = matchRoute(PUBLIC_ROUTES, request.method, path);
  if (pub) return pub.route.handler({ request, env, url, path, user: null, params: pub.params });

  const user = await getUser(request, env);
  if (!user && path.startsWith('/api/')) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const prot = matchRoute(PROTECTED_ROUTES, request.method, path);
  if (prot) return prot.route.handler({ request, env, url, path, user, params: prot.params });

  return json({ error: 'Not found' }, 404);
}
