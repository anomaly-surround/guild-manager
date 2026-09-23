# Gumroad billing — one-time setup

Decided 2026-09-23 after Paddle and Lemon Squeezy both refused seller verification. Gumroad needs no
review to start selling; identity/payout details are asked for only once a payout is due.

## How it works (so you can debug it later)

1. The upgrade modal asks the worker for a checkout link (`POST /api/checkout`). The worker returns the
   product link with `?wanted=true&uid=<user id>`. Gumroad forwards unknown query params to the Ping.
2. After a sale (and after every monthly renewal charge) Gumroad POSTs a form-encoded **Ping** to
   `/gumroad/ping`. The ping is unsigned, so the worker trusts nothing in it: it takes the `license_key`
   and `product_id` from the ping and verifies them with Gumroad's license API (no token needed).
   Only a verified, active purchase grants Premium to the account in `url_params[uid]`.
3. Meanwhile the modal polls `/auth/me` every 5 s for 3 min and flips to Premium when the ping lands.
   If the ping never arrives (bought from the Gumroad page directly, ping misconfigured), the buyer pastes
   the license key from Gumroad's email into the modal → `POST /api/activate-license` → same verification.
4. The cron re-verifies every stored license roughly once a day (`lib/gumroad.js` → `recheckLicenses`).
   Monthly access is extended 35 days per good check; an ended / failed / cancelled-and-expired
   membership, a refund or a chargeback is revoked within ~24 h. A restarted membership is re-granted.

Premium columns on `users`: `premium`, `premium_type` ('monthly' | 'lifetime'), `premium_until`,
`gumroad_license`, `gumroad_product`, `license_checked_at`.

## Steps (Gumroad's editor as of 2026-09: tabs Product / Content / Receipt / Share)

1. **Gumroad account** — done (`anomalyftw.gumroad.com`). Payouts → PayPal.
2. **Premium Monthly** (Membership, already created at `/l/vbeeit`):
   - *Product* tab: one tier, rename it from "Untitled" to **Premium**, price **$2 monthly** only (leave the other
     periods off). Under *Settings* on that same tab turn ON **Members will lose access when their memberships end**.
     Leave "Offer a free trial" OFF (the app has its own trial).
   - *Content* tab: **Insert → License key**. That block is the new form of the old "generate a unique license
     key per sale" switch: every buyer gets a key on their receipt and in their library. Above it type one line
     such as "Paste this key in Guild Manager → account menu → Upgrade to Premium → Already bought?".
   - *Share* tab → **Publish**. The preview says "not currently for sale" until you do.
3. **Premium Lifetime** — New product → type *Digital product*, price **$10**, URL e.g. `gm-lifetime`.
   Same *Content* tab → Insert → License key, same one-line text, Publish.
4. **Ping URL** — sidebar *Everything else* → *Settings* → *Advanced* → **Ping** endpoint:
   `https://guild-manager.xpropics.workers.dev/gumroad/ping`
5. **Copy four values into `worker/wrangler.toml` `[vars]`**:
   - `GUMROAD_MONTHLY_URL` = `https://anomalyftw.gumroad.com/l/vbeeit`, `GUMROAD_LIFETIME_URL` = the lifetime link.
   - `GUMROAD_MONTHLY_PRODUCT_ID` = `vbeeit`, `GUMROAD_LIFETIME_PRODUCT_ID` = the lifetime product's permalink
     (the part after `/l/`). The editor no longer shows the long product id; the worker sends the permalink
     to the license API instead, which accepts either.
6. **Deploy both halves together** (the old page expects the old Paddle route shape):
   `cd worker; npx wrangler deploy` then push the page.
7. **Test without paying**: while logged into Gumroad as the seller, buying your own product is a free *test
   purchase*. Do it from the app's upgrade modal so `uid` is attached; the modal should flip to Premium within
   ~10 s. Then paste the emailed key on a second account to see the "already in use on another account" refusal.
   Test purchases verify like real ones (`test: true`).

## Local test harness

`.dev.vars` (gitignored) may set `GUMROAD_API = "http://127.0.0.1:8799"` to point the worker at a mock;
the mock and the 26-check suite live in the session scratchpad (`mock_gumroad.py`, `m9_billing_test.py`).
Run: mock on 8799, `npx wrangler dev --local --test-scheduled --port 8788`, then the test script with the
worker folder as its argument. Wipe `.wrangler/state/v3/d1` between runs (bindings persist).

## Leftovers you can delete in the Cloudflare dashboard

Secrets `PADDLE_*` and `LS_*` are no longer read by the worker. Harmless, but they are dead.
