'use strict';

const express = require('express');
const fetch   = require('node-fetch');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID      = process.env.EBAY_CLIENT_ID;
const CLIENT_SECRET  = process.env.EBAY_CLIENT_SECRET;
const REFRESH_TOKEN  = process.env.EBAY_REFRESH_TOKEN;
const JWE            = process.env.EBAY_JWE;
const PRIVATE_KEY_B64= process.env.EBAY_PRIVATE_KEY;
const API_SECRET     = process.env.API_SECRET;

let privateKeyObj = null;
if (PRIVATE_KEY_B64) {
  try {
    const der = Buffer.from(PRIVATE_KEY_B64, 'base64');
    if (der.length === 32) {
      const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
      const pkcs8 = Buffer.concat([pkcs8Header, der]);
      privateKeyObj = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    } else {
      privateKeyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    }
    console.log('Private key loaded OK, type:', privateKeyObj.asymmetricKeyType, 'length:', der.length);
  } catch(e) {
    console.error('Failed to load private key:', e.message);
  }
}

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

function buildSignatureHeaders(method, pathWithQuery, authority) {
  const created = Math.floor(Date.now() / 1000);

  // Split path from query for @path component (only the path, not query string)
  const pathOnly = pathWithQuery.split('?')[0];

  const coveredComponents = '("x-ebay-signature-key" "@method" "@path" "@authority")';
  const sigInput = `sig1=${coveredComponents};created=${created}`;

  // Signature base per RFC 9421 - each line is: "<component-name>": <value>
  const sigBase = [
    `"x-ebay-signature-key": ${JWE}`,
    `"@method": ${method.toUpperCase()}`,
    `"@path": ${pathOnly}`,
    `"@authority": ${authority}`,
    `"@signature-params": ${coveredComponents};created=${created}`
  ].join('\n');

  console.log('--- Signature Base ---\n' + sigBase + '\n---');

  const sigBuffer = crypto.sign(null, Buffer.from(sigBase, 'utf8'), privateKeyObj);
  const sig = sigBuffer.toString('base64');

  return {
    'x-ebay-signature-key': JWE,
    'Signature-Input'     : sigInput,
    'Signature'           : `sig1=:${sig}:`,
  };
}

async function fetchTransactions(fromDate, toDate) {
  const token     = await getAccessToken();
  const authority = 'apiz.ebay.com';
  const results   = {};
  let   offset    = 0;

  while (true) {
    const pathWithQuery = `/sell/finances/v1/transaction?limit=200&offset=${offset}`
               + `&filter=transactionType%3A%7BSALE%7D`
               + `,transactionDate%3A%5B${fromDate}..${toDate}%5D`;

    const sigHeaders = buildSignatureHeaders('GET', pathWithQuery, authority);
    const resp = await fetch(`https://${authority}${pathWithQuery}`, {
      method : 'GET',
      headers: {
        'Authorization'           : `Bearer ${token}`,
        'Content-Type'            : 'application/json',
        'X-EBAY-C-MARKETPLACE-ID' : 'EBAY_GB',
        ...sigHeaders
      }
    });

    const data = await resp.json();
    console.log('Finances API status:', resp.status);
    if (!resp.ok) throw new Error(`Finances API ${resp.status}: ${JSON.stringify(data)}`);

    (data.transactions || []).forEach(tx => {
      const orderId = tx.orderId;
      if (!orderId) return;
      const earning = tx.totalFeeBasisAmount && tx.totalFeeAmount
        ? (parseFloat(tx.totalFeeBasisAmount.value) - parseFloat(tx.totalFeeAmount.value)).toFixed(2)
        : tx.amount?.value;
      if (earning !== undefined) results[orderId] = parseFloat(earning);
    });

    if (!data.next) break;
    offset += 200;
    if (offset > 5000) break;
  }
  return results;
}

app.get('/', (req, res) => res.json({
  status: 'ok',
  service: 'eBay Signing Service',
  keyLoaded: !!privateKeyObj,
  keyEnvSet: !!PRIVATE_KEY_B64,
  jweSet: !!JWE
}));

app.get('/earnings', async (req, res) => {
  if (req.query.secret !== API_SECRET) return res.status(401).json({ error: 'Unauthorised' });
  const from = req.query.from || (() => { const d = new Date(); d.setDate(d.getDate()-89); return d.toISOString().split('T')[0]; })();
  const to   = req.query.to   || new Date().toISOString().split('T')[0];
  try {
    const earnings = await fetchTransactions(from + 'T00:00:00.000Z', to + 'T23:59:59.999Z');
    res.json({ from, to, count: Object.keys(earnings).length, earnings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`eBay Signing Service running on port ${PORT}`);
  if (!privateKeyObj) console.warn('WARNING: Private key not loaded!');
});
