'use strict';

const express = require('express');
const fetch   = require('node-fetch');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID      = process.env.EBAY_CLIENT_ID;
const CLIENT_SECRET  = process.env.EBAY_CLIENT_SECRET;
const REFRESH_TOKEN  = process.env.EBAY_REFRESH_TOKEN;
const JWE            = (process.env.EBAY_JWE || '').replace(/\s+/g, '');
const PRIVATE_KEY_B64= process.env.EBAY_PRIVATE_KEY;
const API_SECRET     = process.env.API_SECRET;

function toPem(input) {
  const s = (input || '').trim();
  // If eBay already returned a PEM (with BEGIN/END headers), use as-is
  if (s.includes('BEGIN PRIVATE KEY')) {
    return s.replace(/\\n/g, '\n');
  }
  // Otherwise it's base64 DER — wrap it
  const der = Buffer.from(s, 'base64');
  let pkcs8Der = der.length === 32
    ? Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), der])
    : der;
  const lines = pkcs8Der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
}

const PRIVATE_KEY_PEM = PRIVATE_KEY_B64 ? toPem(PRIVATE_KEY_B64) : null;
if (PRIVATE_KEY_PEM) {
  try {
    const k = crypto.createPrivateKey(PRIVATE_KEY_PEM);
    console.log('Key ready:', k.asymmetricKeyType);
  } catch(e) { console.error('Key error:', e.message); }
}

// Token cache - try user token first, fall back to app token
let cachedToken = null, tokenExpiry = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  // Try user refresh token with sell.finances scope
  const resp = await fetch('https://api.ebay.com/identity/v1/oauth2/token', {
    method : 'POST',
    headers: { 'Authorization': `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body   : `grant_type=refresh_token&refresh_token=${encodeURIComponent(REFRESH_TOKEN)}&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope%2Fsell.finances`
  });
  const data = await resp.json();
  console.log('Token response:', JSON.stringify(data).substring(0, 200));
  if (!data.access_token) throw new Error('Token failed: ' + JSON.stringify(data));
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in || 7200) * 1000;
  return cachedToken;
}

function buildSignatureHeaders(method, fullPath, authority) {
  const created = Math.floor(Date.now() / 1000);
  const pathOnly = fullPath.split('?')[0];
  const coveredComponents = '("x-ebay-signature-key" "@method" "@path" "@authority")';
  const sigInput = `sig1=${coveredComponents};created=${created}`;
  const sigBase = [
    `"x-ebay-signature-key": ${JWE}`,
    `"@method": ${method.toUpperCase()}`,
    `"@path": ${pathOnly}`,
    `"@authority": ${authority}`,
    `"@signature-params": ${coveredComponents};created=${created}`
  ].join('\n');
  console.log('Sig base (first 200):', sigBase.substring(0, 200));
  const privateKey = crypto.createPrivateKey(PRIVATE_KEY_PEM);
  const sig = crypto.sign(null, Buffer.from(sigBase, 'utf8'), privateKey).toString('base64');
  return {
    'x-ebay-signature-key'    : JWE,
    'x-ebay-enforce-signature': 'true',
    'Signature-Input'         : sigInput,
    'Signature'               : `sig1=:${sig}:`,
  };
}

async function fetchTransactions(fromDate, toDate) {
  const token     = await getAccessToken();
  const authority = 'apiz.ebay.com';
  const orderNet  = {};  // orderId -> net amount (credits positive, debits negative)
  let   offset    = 0;

  while (true) {
    // No transactionType filter — we want SALE credits AND fee/charge debits
    const fullPath = `/sell/finances/v1/transaction?limit=200&offset=${offset}`
               + `&filter=transactionDate%3A%5B${fromDate}..${toDate}%5D`;

    const sigHeaders = buildSignatureHeaders('GET', fullPath, authority);
    const resp = await fetch(`https://${authority}${fullPath}`, {
      method : 'GET',
      headers: {
        'Authorization'           : `Bearer ${token}`,
        'Content-Type'            : 'application/json',
        'X-EBAY-C-MARKETPLACE-ID' : 'EBAY_GB',
        ...sigHeaders
      }
    });

    const text = await resp.text();
    console.log('Finances status:', resp.status, text.substring(0, 200));
    if (!resp.ok) throw new Error(`Finances API ${resp.status}: ${text}`);
    const data = JSON.parse(text);

    (data.transactions || []).forEach(tx => {
      const orderId = tx.orderId;
      if (!orderId || !tx.amount) return;
      const val = parseFloat(tx.amount.value);
      if (isNaN(val)) return;
      // CREDIT adds to seller (the sale), DEBIT subtracts (fees, charges, refunds)
      const signed = (tx.bookingEntry === 'DEBIT') ? -val : val;
      orderNet[orderId] = (orderNet[orderId] || 0) + signed;
    });

    if (!data.next) break;
    offset += 200;
    if (offset > 10000) break;
  }

  // Round to 2 decimals
  const results = {};
  Object.keys(orderNet).forEach(id => {
    results[id] = Math.round(orderNet[id] * 100) / 100;
  });
  return results;
}

app.get('/', (req, res) => res.json({ status: 'ok', service: 'eBay Signing Service', keyReady: !!PRIVATE_KEY_PEM, jweReady: !!JWE }));

// Debug: net ALL transactions for a specific order across all pages
app.get('/debug', async (req, res) => {
  if (req.query.secret !== API_SECRET) return res.status(401).json({ error: 'Unauthorised' });
  const from = (req.query.from || '2026-03-01') + 'T00:00:00.000Z';
  const to   = (req.query.to   || '2026-03-31') + 'T23:59:59.999Z';
  const orderFilter = req.query.order;
  try {
    const token = await getAccessToken();
    const authority = 'apiz.ebay.com';
    let offset = 0, found = [], net = 0;
    while (true) {
      const fullPath = `/sell/finances/v1/transaction?limit=200&offset=${offset}`
        + `&filter=transactionDate%3A%5B${from}..${to}%5D`;
      const sigHeaders = buildSignatureHeaders('GET', fullPath, authority);
      const resp = await fetch(`https://${authority}${fullPath}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'X-EBAY-C-MARKETPLACE-ID': 'EBAY_GB',
          ...sigHeaders
        }
      });
      const data = await resp.json();
      (data.transactions || []).forEach(t => {
        if (orderFilter && t.orderId !== orderFilter) return;
        const v = t.amount ? parseFloat(t.amount.value) : 0;
        const signed = (t.bookingEntry === 'DEBIT') ? -v : v;
        net += signed;
        found.push({ type: t.transactionType, booking: t.bookingEntry, amount: t.amount && t.amount.value, feeType: t.feeType, status: t.transactionStatus });
      });
      if (!data.next) break;
      offset += 200;
      if (offset > 10000) break;
    }
    res.json({ order: orderFilter, netEarning: Math.round(net*100)/100, entries: found });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/earnings', async (req, res) => {
  if (req.query.secret !== API_SECRET) return res.status(401).json({ error: 'Unauthorised' });
  const from = req.query.from || (() => { const d = new Date(); d.setDate(d.getDate()-89); return d.toISOString().split('T')[0]; })();
  const to   = req.query.to   || new Date().toISOString().split('T')[0];
  try {
    const earnings = await fetchTransactions(from + 'T00:00:00.000Z', to + 'T23:59:59.999Z');
    res.json({ from, to, count: Object.keys(earnings).length, earnings });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`eBay Signing Service running on port ${PORT}`));
