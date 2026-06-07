/**
 * eBay Finances API Signing Service
 * ==================================
 * Handles Ed25519 digital signatures required by eBay for UK sellers
 * accessing the Finances API. Fetches real "Order earnings" per order
 * and exposes them so your Google Sheet can retrieve them.
 *
 * SETUP (one time only):
 *   1. npm install
 *   2. Set environment variables (see ENVIRONMENT VARIABLES below)
 *   3. Run: node setup-signing-key.js   <-- creates your eBay signing key
 *   4. node server.js                   <-- starts the service
 *
 * ENVIRONMENT VARIABLES (set these before running):
 *   EBAY_CLIENT_ID       Your eBay app Client ID
 *   EBAY_CLIENT_SECRET   Your eBay app Client Secret
 *   EBAY_REFRESH_TOKEN   Your OAuth refresh token (from the sheet's REF property)
 *   API_SECRET           A secret string YOU choose — the sheet sends this to
 *                        prove it's allowed to call this service (e.g. "mySecret123")
 *   PORT                 (optional) Port to listen on, default 3000
 *
 * After running setup-signing-key.js, two more env vars are saved automatically:
 *   EBAY_JWE            The public key JWE from eBay Key Management API
 *   EBAY_PRIVATE_KEY    Your Ed25519 private key (keep this secret!)
 */

'use strict';

const express  = require('express');
const fetch    = require('node-fetch');
const crypto   = require('crypto');
const ed       = require('@noble/ed25519');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CONFIG ────────────────────────────────────────────────────────────────────
const CLIENT_ID      = process.env.EBAY_CLIENT_ID;
const CLIENT_SECRET  = process.env.EBAY_CLIENT_SECRET;
const REFRESH_TOKEN  = process.env.EBAY_REFRESH_TOKEN;
const JWE            = process.env.EBAY_JWE;           // set by setup-signing-key.js
const PRIVATE_KEY_B64= process.env.EBAY_PRIVATE_KEY;  // set by setup-signing-key.js
const API_SECRET     = process.env.API_SECRET;         // your chosen secret

// ── OAUTH: get a fresh access token ──────────────────────────────────────────
let cachedToken = null, tokenExpiry = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;

  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const resp  = await fetch('https://api.ebay.com/identity/v1/oauth2/token', {
    method : 'POST',
    headers: { 'Authorization': `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body   : `grant_type=refresh_token&refresh_token=${encodeURIComponent(REFRESH_TOKEN)}&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope%2Fsell.finances`
  });
  const data = await resp.json();
  if (!data.access_token) throw new Error('Token refresh failed: ' + JSON.stringify(data));
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in || 7200) * 1000;
  return cachedToken;
}

// ── SIGNING: build the four eBay signature headers ───────────────────────────
async function buildSignatureHeaders(method, path, authority, body) {
  const privateKeyBytes = Buffer.from(PRIVATE_KEY_B64, 'base64');
  const created         = Math.floor(Date.now() / 1000);

  // 1. Content-Digest (only needed if there's a body)
  const contentDigest = body
    ? 'sha-256=:' + crypto.createHash('sha256').update(body).digest('base64') + ':'
    : null;

  // 2. Signature-Input
  const coveredComponents = contentDigest
    ? '("x-ebay-signature-key" "@method" "@path" "@authority" "content-digest")'
    : '("x-ebay-signature-key" "@method" "@path" "@authority")';
  const sigInput = `sig1=${coveredComponents};created=${created}`;

  // 3. Signature base string
  let sigBase = `"x-ebay-signature-key": ${JWE}\n`
              + `"@method": ${method.toUpperCase()}\n`
              + `"@path": ${path}\n`
              + `"@authority": ${authority}`;
  if (contentDigest) sigBase += `\n"content-digest": ${contentDigest}`;
  sigBase += `\n"@signature-params": ${coveredComponents};created=${created}`;

  // 4. Sign with Ed25519
  const sigBytes = await ed.sign(Buffer.from(sigBase, 'utf8'), privateKeyBytes);
  const sigB64   = Buffer.from(sigBytes).toString('base64');

  const headers = {
    'x-ebay-signature-key': JWE,
    'Signature-Input'     : sigInput,
    'Signature'           : `sig1=:${sigB64}:`,
  };
  if (contentDigest) headers['Content-Digest'] = contentDigest;
  return headers;
}

// ── FINANCES API: fetch transactions for a date range ────────────────────────
async function fetchTransactions(fromDate, toDate) {
  const token     = await getAccessToken();
  const authority = 'apiz.ebay.com';
  const results   = {};
  let   offset    = 0;
  const limit     = 200;

  while (true) {
    const path = `/sell/finances/v1/transaction?limit=${limit}&offset=${offset}`
               + `&filter=transactionType%3A%7BSALE%7D`
               + `,transactionDate%3A%5B${fromDate}..${toDate}%5D`;

    const sigHeaders = await buildSignatureHeaders('GET', path, authority, null);

    const resp = await fetch(`https://${authority}${path}`, {
      method : 'GET',
      headers: {
        'Authorization'            : `Bearer ${token}`,
        'Content-Type'             : 'application/json',
        'X-EBAY-C-MARKETPLACE-ID'  : 'EBAY_GB',
        ...sigHeaders
      }
    });

    const data = await resp.json();
    if (!resp.ok) {
      console.error('Finances API error:', JSON.stringify(data));
      throw new Error(`Finances API ${resp.status}: ${data.errors?.[0]?.message || 'unknown'}`);
    }

    (data.transactions || []).forEach(tx => {
      // orderId links the transaction back to the eBay order
      const orderId = tx.orderId;
      if (!orderId) return;
      // orderEarning = totalFeeBasisAmount - totalFeeAmount (seller net)
      // or use: tx.amount.value which for SALE transactions is what eBay pays out
      const earning = tx.totalFeeBasisAmount && tx.totalFeeAmount
        ? (parseFloat(tx.totalFeeBasisAmount.value) - parseFloat(tx.totalFeeAmount.value)).toFixed(2)
        : tx.amount?.value;
      if (earning !== undefined) results[orderId] = parseFloat(earning);
    });

    if (!data.next) break; // no more pages
    offset += limit;
    if (offset > 5000) break; // safety cap
  }

  return results;
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => res.json({ status: 'ok', service: 'eBay Signing Service' }));

/**
 * GET /earnings?secret=YOUR_SECRET&from=2026-03-01&to=2026-05-31
 *
 * Returns a JSON object mapping order IDs to their real Order earnings:
 * { "11-14698-53990": 11.28, "12-14733-64534": 7.91, ... }
 *
 * The sheet calls this URL and writes the values into column F.
 */
app.get('/earnings', async (req, res) => {
  // Verify the secret so only your sheet can call this
  if (req.query.secret !== API_SECRET) {
    return res.status(401).json({ error: 'Unauthorised' });
  }

  const from = req.query.from || (() => {
    const d = new Date(); d.setDate(d.getDate() - 89);
    return d.toISOString().split('T')[0];
  })();
  const to = req.query.to || new Date().toISOString().split('T')[0];

  try {
    const earnings = await fetchTransactions(from + 'T00:00:00.000Z', to + 'T23:59:59.999Z');
    res.json({ from, to, count: Object.keys(earnings).length, earnings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`eBay Signing Service running on port ${PORT}`);
  if (!JWE || !PRIVATE_KEY_B64) {
    console.warn('WARNING: EBAY_JWE or EBAY_PRIVATE_KEY not set.');
    console.warn('Run: node setup-signing-key.js   to create your signing key first.');
  }
});
