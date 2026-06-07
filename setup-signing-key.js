/**
 * setup-signing-key.js
 * =====================
 * Run this ONCE before starting the server.
 * It creates an Ed25519 keypair, registers the public key with eBay's
 * Key Management API, and prints the two environment variables you need
 * to set (EBAY_JWE and EBAY_PRIVATE_KEY).
 *
 * Usage:
 *   EBAY_CLIENT_ID=xxx EBAY_CLIENT_SECRET=xxx node setup-signing-key.js
 */

'use strict';

const fetch = require('node-fetch');
const ed    = require('@noble/ed25519');
const crypto= require('crypto');

const CLIENT_ID     = process.env.EBAY_CLIENT_ID;
const CLIENT_SECRET = process.env.EBAY_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('ERROR: Set EBAY_CLIENT_ID and EBAY_CLIENT_SECRET before running.');
  process.exit(1);
}

async function main() {
  console.log('Step 1: Getting eBay access token (application scope)...');

  // Application token (not user token) is used for Key Management API
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const tokenResp = await fetch('https://api.ebay.com/identity/v1/oauth2/token', {
    method : 'POST',
    headers: { 'Authorization': `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body   : 'grant_type=client_credentials&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope'
  });
  const tokenData = await tokenResp.json();
  if (!tokenData.access_token) {
    console.error('Token failed:', JSON.stringify(tokenData));
    process.exit(1);
  }
  const appToken = tokenData.access_token;
  console.log('Got application token OK.');

  console.log('\nStep 2: Generating Ed25519 keypair...');
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey  = await ed.getPublicKey(privateKey);
  const privateKeyB64 = Buffer.from(privateKey).toString('base64');
  const publicKeyB64  = Buffer.from(publicKey).toString('base64');
  console.log('Keypair generated.');

  console.log('\nStep 3: Registering public key with eBay Key Management API...');
  const keyResp = await fetch('https://apiz.ebay.com/developer/key_management/v1/signing_key', {
    method : 'POST',
    headers: {
      'Authorization': `Bearer ${appToken}`,
      'Content-Type' : 'application/json'
    },
    body: JSON.stringify({ signingKeyCipher: 'ED25519' })
  });
  const keyData = await keyResp.json();
  if (!keyResp.ok || !keyData.jwe) {
    console.error('Key Management API failed:', JSON.stringify(keyData));
    process.exit(1);
  }
  const jwe = keyData.jwe;
  console.log('Signing key registered with eBay. Key ID:', keyData.signingKeyId);

  console.log('\n========================================================');
  console.log('SUCCESS! Set these environment variables on your server:');
  console.log('========================================================\n');
  console.log(`EBAY_JWE="${jwe}"`);
  console.log(`EBAY_PRIVATE_KEY="${privateKeyB64}"`);
  console.log('\nKeep EBAY_PRIVATE_KEY secret — do not share or commit it.');
  console.log('eBay does not store it; if you lose it, run this script again.');
}

main().catch(err => { console.error(err); process.exit(1); });
