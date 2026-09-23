// Guild Manager - Cloudflare Worker entry point.
// Bindings: DB (D1), FILES (R2); secrets: DISCORD_*, GOOGLE_*, JWT_SECRET; vars: GUMROAD_* (wrangler.toml).
import { handleRequest } from './router.js';
import { handleScheduled } from './cron/scheduled.js';
import { corsHeaders } from './lib/http.js';

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch(e) {
      console.error('Unhandled error:', e);
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },
};
