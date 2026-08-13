var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var ZERO_IV = new Uint8Array(16);
var CONST_RB = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135]);
var SKU_MAP = {
  "WMK": "piece_wmk",
  "FRM": "piece_frm",
  "BLK": "piece_blk",
  "UNM": "piece_unm"
};
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
__name(hexToBytes, "hexToBytes");
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
function xorBytes(a, b) {
  const r = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i] ^ b[i];
  return r;
}
__name(xorBytes, "xorBytes");
function shiftLeft(data) {
  const r = new Uint8Array(data.length);
  let carry = 0;
  for (let i = data.length - 1; i >= 0; i--) {
    r[i] = (data[i] << 1 | carry) & 255;
    carry = data[i] & 128 ? 1 : 0;
  }
  return r;
}
__name(shiftLeft, "shiftLeft");
function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(generateToken, "generateToken");
async function aesEncryptBlock(key, data) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ZERO_IV }, cryptoKey, data);
  return new Uint8Array(encrypted).slice(0, 16);
}
__name(aesEncryptBlock, "aesEncryptBlock");
async function generateSubkeys(key) {
  const L = await aesEncryptBlock(key, new Uint8Array(16));
  let K1 = shiftLeft(L);
  if (L[0] & 128) K1 = xorBytes(K1, CONST_RB);
  let K2 = shiftLeft(K1);
  if (K1[0] & 128) K2 = xorBytes(K2, CONST_RB);
  return { K1, K2 };
}
__name(generateSubkeys, "generateSubkeys");
async function aesCmac(key, message) {
  const { K1, K2 } = await generateSubkeys(key);
  const n = Math.ceil(message.length / 16) || 1;
  const lastBlockComplete = message.length > 0 && message.length % 16 === 0;
  let lastBlock;
  if (lastBlockComplete) {
    lastBlock = xorBytes(message.slice((n - 1) * 16), K1);
  } else {
    const padded = new Uint8Array(16);
    const lastStart = (n - 1) * 16;
    const remaining = message.length - lastStart;
    if (remaining > 0) padded.set(message.slice(lastStart, lastStart + remaining));
    padded[remaining] = 128;
    lastBlock = xorBytes(padded, K2);
  }
  let X = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) {
    X = await aesEncryptBlock(key, xorBytes(X, message.slice(i * 16, (i + 1) * 16)));
  }
  return await aesEncryptBlock(key, xorBytes(X, lastBlock));
}
__name(aesCmac, "aesCmac");
// ExtraÃ­da de /api/validate como helper reutilizable (Bloque B parte 2, secciÃ³n 1).
// v6.6.4: rollback de la rotaciÃ³n Key0 (v6.6.3). DecisiÃ³n consciente
// (Camino 3) tras anÃ¡lisis de modelo de amenaza â€” Key0 vuelve a zeros
// hardcoded, factory default. Ver README.md de potisse-ntag424 para el
// razonamiento completo. Camino 2a (rotaciÃ³n Key1) queda documentado
// como opciÃ³n futura si aparece caso de uso concreto.
async function verifyNfcCmac(uidHex, ctrHex, cmacHex, env) {
  const uid = hexToBytes(uidHex);
  const ctrValue = parseInt(ctrHex, 16);
  const ctrLSB = new Uint8Array([ctrValue & 255, ctrValue >> 8 & 255, ctrValue >> 16 & 255]);
  const sdmKey = new Uint8Array(16);
  const sv2 = new Uint8Array(16);
  sv2[0] = 60;
  sv2[1] = 195;
  sv2[2] = 0;
  sv2[3] = 1;
  sv2[4] = 0;
  sv2[5] = 128;
  sv2.set(uid.slice(0, 7), 6);
  sv2.set(ctrLSB, 13);
  const sesSDMFileReadMAC = await aesCmac(sdmKey, sv2);
  const calculatedCmac = await aesCmac(sesSDMFileReadMAC, new Uint8Array(0));
  const truncated = new Uint8Array(8);
  for (let i = 0; i < 8; i++) truncated[i] = calculatedCmac[i * 2 + 1];
  return {
    valid: bytesToHex(truncated).toLowerCase() === cmacHex.toLowerCase(),
    uid: uidHex,
    counter: ctrValue
  };
}
__name(verifyNfcCmac, "verifyNfcCmac");
async function getScanData(env, uidHex) {
  try {
    const data = await env.POTISSE_NFC.get("nfc_" + uidHex);
    if (data) return JSON.parse(data);
  } catch (e) {
  }
  return { scans: 0, firstScan: null, lastScan: null, lastCounter: -1 };
}
__name(getScanData, "getScanData");
async function saveScanData(env, uidHex, scanData) {
  await env.POTISSE_NFC.put("nfc_" + uidHex, JSON.stringify(scanData));
}
__name(saveScanData, "saveScanData");
function verifyWashToken(request, env) {
  const token = request.headers.get("X-Auth-Token");
  return env.WASH_TOKEN ? token === env.WASH_TOKEN : true;
}
__name(verifyWashToken, "verifyWashToken");
async function getWashData(env, customerId, pieceCode) {
  const raw = await env.POTISSE_NFC.get(`wash:${customerId}:${pieceCode}`);
  return raw ? JSON.parse(raw) : { count: 0, last: null };
}
__name(getWashData, "getWashData");
async function incrementWash(env, customerId, pieceCode) {
  const current = await getWashData(env, customerId, pieceCode);
  const updated = { count: current.count + 1, last: (/* @__PURE__ */ new Date()).toISOString() };
  await env.POTISSE_NFC.put(`wash:${customerId}:${pieceCode}`, JSON.stringify(updated));
  return updated;
}
__name(incrementWash, "incrementWash");
async function sendMagicLinkEmail(env, email, magicUrl) {
  const payload = {
    from: "POTISSE 50430 <50430@potisse.com>",
    to: [email],
    subject: "Your key to The Club",
    html: `
      <div style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 48px 24px; color: #3A322E;">
        <div style="text-align: center; margin-bottom: 48px;">
          <span style="font-size: 11px; letter-spacing: 4px; text-transform: uppercase; color: #C4B5A4;">Potisse</span>
        </div>
        <p style="font-size: 15px; line-height: 1.7; margin-bottom: 24px;">The key is already there.</p>
        <p style="font-size: 15px; line-height: 1.7; margin-bottom: 36px;">This link will open for 15 minutes. After that, it disappears.</p>
        <div style="text-align: center; margin-bottom: 48px;">
          <a href="${magicUrl}" style="display: inline-block; padding: 14px 36px; background-color: #3A322E; color: #F2F1ED; text-decoration: none; font-size: 13px; letter-spacing: 2px; text-transform: uppercase;">Step Inside</a>
        </div>
        <div style="border-top: 1px solid #E8E6E1; padding-top: 24px; text-align: center;">
          <span style="font-size: 11px; color: #C4B5A4; letter-spacing: 1px;">Potisse &middot; Zaragoza 50430</span>
        </div>
      </div>
    `
  };

  console.log(`[MAGIC LINK] Sending to ${email} from 50430@potisse.com`);

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  let bodyText = "";
  try { bodyText = await response.text(); } catch (e) { bodyText = "(no body)"; }

  console.log(`[MAGIC LINK] Resend status: ${response.status}, body: ${bodyText}`);

  if (!response.ok) {
    console.error(`[MAGIC LINK] Resend rejected: ${response.status} â€” ${bodyText}`);
    return { ok: false, error: `Resend ${response.status}: ${bodyText}` };
  }

  let bodyJson = null;
  try { bodyJson = JSON.parse(bodyText); } catch (e) {}

  return { ok: true, id: bodyJson?.id || null };
}
__name(sendMagicLinkEmail, "sendMagicLinkEmail");
async function sendVerifyEmail(env, email, verifyUrl) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "POTISSE 50430 <50430@potisse.com>",
      to: [email],
      subject: "Sequence 01. The wait.",
      html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="background-color:#F2F1ED;color:#3A322E;padding:48px 24px;margin:0;font-family:'SF Mono','Menlo','Monaco','Consolas','Courier New',monospace;font-size:14px;line-height:1.7;"><div style="max-width:560px;margin:0 auto;"><p style="margin:0 0 24px 0;">&#9472;&#9472;&#9472;&#9472;&#9472;</p><p style="margin:0 0 32px 0;">LOCATION: 50430 &middot; STATUS: Added, quietly.</p><p style="margin:0 0 8px 0;">An outfit for the shadow.</p><p style="margin:0 0 32px 0;">A uniform for the light.</p><p style="margin:0 0 8px 0;">Your address has been recorded in our log.</p><p style="margin:0 0 24px 0;">To secure your place in the silence, confirm the link below:</p><p style="margin:0 0 32px 0;word-break:break-all;"><a href="${verifyUrl}" style="color:#3A322E;">${verifyUrl}</a></p><p style="margin:0 0 32px 0;">The door remains ajar for 7 days. Then, the silence closes.</p><p style="margin:0 0 32px 0;">If this wasn't you, let this transmission dissolve in the dark.</p><p style="margin:0;">&#9472;&#9472;&#9472; POTISSE 2026</p></div></body></html>`,
      text: `-----

LOCATION: 50430 - STATUS: Added, quietly.

An outfit for the shadow.
A uniform for the light.

Your address has been recorded in our log.
To secure your place in the silence, confirm the link below:

${verifyUrl}

The door remains ajar for 7 days. Then, the silence closes.

If this wasn't you, let this transmission dissolve in the dark.

--- POTISSE 2026`
    })
  });
  if (!response.ok) throw new Error(`Resend ${response.status}: ${await response.text()}`);
  return true;
}
__name(sendVerifyEmail, "sendVerifyEmail");
async function verifyShopifyHmac(rawBody, secret, hmacHeader) {
  if (!hmacHeader) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, rawBody);
  return btoa(String.fromCharCode(...new Uint8Array(signature))) === hmacHeader;
}
__name(verifyShopifyHmac, "verifyShopifyHmac");
async function countOrdersWithSkuPrefix(env, skuPrefix) {
  const store = env.SHOPIFY_STORE_DOMAIN;
  const token = env.SHOPIFY_ACCESS_TOKEN;
  let count = 0;
  let nextUrl = `https://${store}/admin/api/2024-01/orders.json?status=any&limit=250&fields=id,line_items`;
  while (nextUrl) {
    const res = await fetch(nextUrl, { headers: { "X-Shopify-Access-Token": token } });
    if (!res.ok) break;
    const data = await res.json();
    for (const order of data.orders || []) {
      if ((order.line_items || []).some((item) => item.sku && item.sku.toUpperCase().startsWith(skuPrefix + "."))) count++;
    }
    const link = res.headers.get("Link") || "";
    const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
    nextUrl = nextMatch ? nextMatch[1] : null;
  }
  return count;
}
__name(countOrdersWithSkuPrefix, "countOrdersWithSkuPrefix");
async function upsertCustomerMetafield(env, customerId, namespace, key, value) {
  const store = env.SHOPIFY_STORE_DOMAIN;
  const token = env.SHOPIFY_ACCESS_TOKEN;
  const listRes = await fetch(
    `https://${store}/admin/api/2024-01/customers/${customerId}/metafields.json?namespace=${namespace}&key=${key}`,
    { headers: { "X-Shopify-Access-Token": token } }
  );
  if (listRes.ok) {
    const listData = await listRes.json();
    const existing = (listData.metafields || [])[0];
    if (existing) {
      await fetch(`https://${store}/admin/api/2024-01/metafields/${existing.id}.json`, {
        method: "PUT",
        headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" },
        body: JSON.stringify({ metafield: { id: existing.id, value, type: "number_integer" } })
      });
      return;
    }
  }
  await fetch(`https://${store}/admin/api/2024-01/customers/${customerId}/metafields.json`, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" },
    body: JSON.stringify({ metafield: { namespace, key, value, type: "number_integer" } })
  });
}
__name(upsertCustomerMetafield, "upsertCustomerMetafield");
async function registerShopifyWebhook(env, workerUrl) {
  const store = env.SHOPIFY_STORE_DOMAIN;
  const token = env.SHOPIFY_ACCESS_TOKEN;
  const res = await fetch(`https://${store}/admin/api/2024-01/webhooks.json`, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" },
    body: JSON.stringify({ webhook: { topic: "orders/create", address: `${workerUrl}/api/webhook/orders-create`, format: "json" } })
  });
  return { ok: res.ok, status: res.status, body: await res.json() };
}
__name(registerShopifyWebhook, "registerShopifyWebhook");
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// POTISSE ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â /api/customer-update endpoint
// Identity edit from /pages/you (HMAC-signed).
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â

const NONCE_WINDOW_SECONDS = 900;

async function handleCustomerUpdate(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (err) {
    return jsonResponse({ ok: false, error: "Invalid request" }, 400);
  }

  const { customer_id, nonce, signature, first_name, last_name, email } = body;

  if (!customer_id || !nonce || !signature || !first_name || !last_name || !email) {
    return jsonResponse({ ok: false, error: "Missing fields" }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const nonceInt = parseInt(nonce, 10);
  if (!Number.isFinite(nonceInt) || Math.abs(now - nonceInt) > NONCE_WINDOW_SECONDS) {
    return jsonResponse({ ok: false, error: "Session expired. Refresh and try again." }, 401);
  }

  const payload = `${customer_id}.${nonce}`;
  let expectedSignature;
  try {
    expectedSignature = await hmacSha256Hex(env.HMAC_SECRET_YOU, payload);
  } catch (err) {
    return jsonResponse({ ok: false, error: "Signature verification failed" }, 500);
  }

  if (!timingSafeEqualHex(signature, expectedSignature)) {
    return jsonResponse({ ok: false, error: "Invalid signature" }, 401);
  }

  const trimmedFirst = String(first_name).trim();
  const trimmedLast = String(last_name).trim();
  const trimmedEmail = String(email).trim().toLowerCase();

  if (!trimmedFirst || !trimmedLast) {
    return jsonResponse({ ok: false, error: "Required fields missing" }, 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
    return jsonResponse({ ok: false, error: "Not a valid email" }, 400);
  }

  const shopifyUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/${customer_id}.json`;

  let shopifyRes;
  try {
    shopifyRes = await fetch(shopifyUrl, {
      method: "PUT",
      headers: {
        "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        customer: {
          id: parseInt(customer_id, 10),
          first_name: trimmedFirst,
          last_name: trimmedLast,
          email: trimmedEmail
        }
      })
    });
  } catch (err) {
    return jsonResponse({ ok: false, error: "Connection to Shopify failed" }, 502);
  }

  if (!shopifyRes.ok) {
    const errorBody = await shopifyRes.text();
    console.error("[customer-update] Shopify error", shopifyRes.status, errorBody);

    let userMessage = "Update failed. Try again.";
    try {
      const errData = JSON.parse(errorBody);
      if (errData.errors) {
        if (errData.errors.email) {
          userMessage = "That email is already in use.";
        } else if (typeof errData.errors === "string") {
          userMessage = errData.errors;
        }
      }
    } catch (_) {}

    return jsonResponse({ ok: false, error: userMessage }, 400);
  }

  return jsonResponse({ ok: true });
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// v6.9.2: timing-safe string comparison using SHA-256 double-hash + XOR loop
async function timingSafeStringEqual(a, b) {
  const aEnc = new TextEncoder().encode(a || "");
  const bEnc = new TextEncoder().encode(b || "");
  if (aEnc.length !== bEnc.length) return false;
  const aHash = await crypto.subtle.digest("SHA-256", aEnc);
  const bHash = await crypto.subtle.digest("SHA-256", bEnc);
  const aArr = new Uint8Array(aHash);
  const bArr = new Uint8Array(bHash);
  let match = true;
  for (let i = 0; i < aArr.length; i++) {
    if (aArr[i] !== bArr[i]) match = false;
  }
  return match;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Auth-Token"
    }
  });
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Crear/actualizar objeto customer:{id} en KV
// Llamada desde handler orders/create. No interrumpe flujo principal.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
async function updateCustomerKvForSilencio1(env, order) {
  // Diagnostic log ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â visible cuando falta customer_id
  const rawCustomerId = order.customer?.id;
  const rawEmail = order.customer?.email || order.email || null;
  const orderId = String(order.id || "");

  console.log(`Silencio1 incoming: order=${orderId} customer=${rawCustomerId} email=${rawEmail || "none"}`);

  // Guard clause: sin customer_id no hay nada que hacer
  if (!rawCustomerId) {
    console.warn(`Silencio1: skipping order ${orderId} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no customer_id in payload (likely test webhook or guest checkout)`);
    return;
  }

  const customerId = String(rawCustomerId);
  const email = rawEmail || "";
  const createdAt = order.created_at || new Date().toISOString();

  console.log(`Silencio1 step 1: variables extracted ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â customerId=${customerId} createdAt=${createdAt}`);

  // Detectar zona por country_code del shipping address.
  // Iberian: EspaÃƒÆ’Ã‚Â±a + Portugal peninsular.
  // Europe: resto de UE + Baleares (Baleares es ES pero se factura
  // como Europe segÃƒÆ’Ã‚Âºn decisiÃƒÆ’Ã‚Â³n POTISSE).
  const shippingCountry = (order.shipping_address?.country_code || "").toUpperCase();
  const shippingProvinceCode = (order.shipping_address?.province_code || "").toUpperCase();
  const shippingZipCode = (order.shipping_address?.zip || "").trim();

  const EUROPE_COUNTRIES = [
    "FR", "DE", "IT", "NL", "BE", "LU", "AT", "IE",
    "DK", "SE", "FI", "GR", "CY", "MT",
    "EE", "LV", "LT", "PL", "CZ", "SK", "SI",
    "HU", "HR", "RO", "BG"
  ];

  // Excepciones peninsulares: Baleares (ES-IB) va a Europe, no Iberian
  const BALEARES_PROVINCE = "IB";
  // Canarias, Ceuta, Melilla no se sirven (fuera Fase 1)
  const EXCLUDED_ES_PROVINCES = ["CN", "TF", "GC", "CE", "ML"];
  // Portugal excluye Azores y Madeira (todos los 9xxxx en PT)

  let shippingZone;

  if (shippingCountry === "ES") {
    if (EXCLUDED_ES_PROVINCES.includes(shippingProvinceCode)) {
      shippingZone = "excluded";
      console.warn(`Silencio1: excluded ES province ${shippingProvinceCode} for order ${String(order.id)}`);
    } else if (shippingProvinceCode === BALEARES_PROVINCE) {
      shippingZone = "europe";
    } else {
      shippingZone = "iberian";
    }
  } else if (shippingCountry === "PT") {
    if (shippingZipCode.startsWith("9")) {
      shippingZone = "excluded";
      console.warn(`Silencio1: excluded PT zip ${shippingZipCode} for order ${String(order.id)}`);
    } else {
      shippingZone = "iberian";
    }
  } else if (EUROPE_COUNTRIES.includes(shippingCountry)) {
    shippingZone = "europe";
  } else if (!shippingCountry) {
    shippingZone = "unknown";
    console.warn(`Silencio1: no shipping_address in order ${String(order.id)} (likely test payload)`);
  } else {
    shippingZone = "unknown";
    console.warn(`Silencio1: unrecognized shipping country "${shippingCountry}" for order ${String(order.id)}`);
  }

  console.log(`Silencio1 step 2: shipping zone resolved = ${shippingZone} (country=${shippingCountry}, province=${shippingProvinceCode}, zip=${shippingZipCode})`);

  const kvKey = `customer:${customerId}`;
  console.log(`Silencio1 step 3: computed kvKey = "${kvKey}"`);

  let existingRaw;
  try {
    existingRaw = await env.POTISSE_NFC.get(kvKey);
    console.log(`Silencio1 step 4: KV read done. existingRaw is ${existingRaw ? "present" : "null"}`);
  } catch (err) {
    console.error(`Silencio1 step 4 FAILED: KV.get threw: ${err.message}`);
    throw err;
  }

  const now = new Date().toISOString();
  const newOrder = {
    order_id: String(order.id || ""),
    created_at: createdAt,
    fulfilled_at: null,
    delivered_approx_at: null,
    shipping_zone: shippingZone,
    refunded: false,
    refunded_at: null,
    refund_id: null
  };

  console.log(`Silencio1 step 5: newOrder built for order_id=${newOrder.order_id}`);

  let customerObj;

  const orderTotal = parseFloat(order.total_price || 0);

  if (!existingRaw) {
    customerObj = {
      id: customerId,
      email,
      orders: [newOrder],
      total_spent: orderTotal,
      aov: orderTotal,
      silencio_1: {
        is_candidate: false,
        candidate_since: null,
        tag_applied: false,
        tag_applied_at: null,
        tag_removed_at: null,
        last_purchase_at: createdAt
      },
      schema_version: 1,
      created_at: now,
      updated_at: now
    };
    console.log(`Silencio1 step 6a: new customer object built`);
  } else {
    try {
      customerObj = JSON.parse(existingRaw);
    } catch (err) {
      console.error(`Silencio1 step 6b FAILED: JSON.parse threw: ${err.message}`);
      throw err;
    }
    const alreadyExists = (customerObj.orders || []).some(o => o.order_id === newOrder.order_id);
    if (!alreadyExists) {
      customerObj.orders = customerObj.orders || [];
      customerObj.orders.push(newOrder);
      customerObj.total_spent = (customerObj.total_spent || 0) + orderTotal;
      customerObj.aov = customerObj.orders.length > 0 ? customerObj.total_spent / customerObj.orders.length : 0;
      customerObj.silencio_1 = customerObj.silencio_1 || {};
      customerObj.silencio_1.last_purchase_at = createdAt;
      customerObj.updated_at = now;
      console.log(`Silencio1 step 6b: existing customer updated with new order (total_spent=${customerObj.total_spent}, aov=${customerObj.aov})`);
    } else {
      console.log(`Silencio1 step 6b: order already exists in customer.orders, skipping duplicate`);
    }
  }

  const serialized = JSON.stringify(customerObj);
  console.log(`Silencio1 step 7: serialized JSON length = ${serialized.length}`);

  try {
    await env.POTISSE_NFC.put(kvKey, serialized);
    console.log(`Silencio1 step 8: KV.put success for key "${kvKey}"`);
  } catch (err) {
    console.error(`Silencio1 step 8 FAILED: KV.put threw: ${err.message}`);
    throw err;
  }

  // Push 4b: mergear datos en customer_{id}_profile si existe
  try {
    const profileKey = `customer_${customerId}_profile`;
    const profileRaw = await env.POTISSE_NFC.get(profileKey);
    if (profileRaw) {
      const profile = JSON.parse(profileRaw);
      const orderEmail = order.customer?.email || order.email || "";
      let changed = false;
      if (orderEmail && orderEmail !== profile.email) {
        profile.email = orderEmail;
        changed = true;
      }
      const orderFirstName = order.customer?.first_name || "";
      const orderLastName = order.customer?.last_name || "";
      if (orderFirstName && orderFirstName !== profile.first_name) {
        profile.first_name = orderFirstName;
        changed = true;
      }
      if (orderLastName && orderLastName !== profile.last_name) {
        profile.last_name = orderLastName;
        changed = true;
      }
      if (changed) {
        profile.updated_at = new Date().toISOString();
        await env.POTISSE_NFC.put(profileKey, JSON.stringify(profile));

  ctx.waitUntil(writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "customer",
    customer_id: customerId,
    type: "customer_data_updated_from_shopify",
    title: "Customer data updated from Shopify",
    details: "PII refreshed via webhook customers/update"
  }));
        console.log(`Silencio1: merged customer data into existing profile for ${customerId}`);
      }
    }
  } catch (err) {
    console.error(`Silencio1: profile merge failed for ${customerId}: ${err.message}`);
  }
}
__name(updateCustomerKvForSilencio1, "updateCustomerKvForSilencio1");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Helper: computar HMAC-SHA256 base64 de un string
// Para nuevos webhook handlers que leen request.text()
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
async function computeHmacBase64(secret, bodyInput) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const data = bodyInput instanceof Uint8Array ? bodyInput : encoder.encode(bodyInput);
  const signature = await crypto.subtle.sign("HMAC", key, data);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}
__name(computeHmacBase64, "computeHmacBase64");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Helper: buscar index de una orden dentro del array
// orders del objeto customer:{id}. Devuelve -1 si no encuentra.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
function findOrderIndexByOrderId(customerObj, orderId) {
  if (!customerObj || !Array.isArray(customerObj.orders)) return -1;
  const targetId = String(orderId);
  return customerObj.orders.findIndex(o => o.order_id === targetId);
}
__name(findOrderIndexByOrderId, "findOrderIndexByOrderId");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Helper: calcular delivered_approx_at desde fulfilled_at
// segÃƒÆ’Ã‚Âºn shipping_zone (iberian +3d, europe +7d, excluded/unknown null)
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
function calculateDeliveredApproxAt(fulfilledAtIso, shippingZone) {
  if (!fulfilledAtIso) return null;
  const daysToAdd = shippingZone === "iberian" ? 3
                  : shippingZone === "europe" ? 7
                  : null;
  if (daysToAdd === null) return null;
  const fulfilledDate = new Date(fulfilledAtIso);
  const deliveredDate = new Date(fulfilledDate.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
  return deliveredDate.toISOString();
}
__name(calculateDeliveredApproxAt, "calculateDeliveredApproxAt");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Webhook orders/fulfilled handler
// Actualiza fulfilled_at y delivered_approx_at de la orden
// correspondiente en el objeto customer:{id}.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
async function handleOrdersFulfilledForSilencio1(env, order) {
  const rawCustomerId = order.customer?.id;
  const orderId = String(order.id || "");

  console.log(`Silencio1 fulfilled incoming: order=${orderId} customer=${rawCustomerId}`);

  if (!rawCustomerId) {
    console.warn(`Silencio1 fulfilled: skipping order ${orderId} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no customer_id`);
    return;
  }

  const customerId = String(rawCustomerId);
  const kvKey = `customer:${customerId}`;

  const existingRaw = await env.POTISSE_NFC.get(kvKey);
  if (!existingRaw) {
    console.warn(`Silencio1 fulfilled: customer ${customerId} not in KV yet (orders/create webhook may be pending)`);
    return;
  }

  let customerObj;
  try {
    customerObj = JSON.parse(existingRaw);
  } catch (err) {
    console.error(`Silencio1 fulfilled: JSON.parse failed for ${kvKey}: ${err.message}`);
    return;
  }

  const orderIndex = findOrderIndexByOrderId(customerObj, orderId);
  if (orderIndex === -1) {
    console.warn(`Silencio1 fulfilled: order ${orderId} not found in customer.orders (orders/create webhook may be pending)`);
    return;
  }

  const targetOrder = customerObj.orders[orderIndex];

  // Idempotencia: si ya tiene fulfilled_at con este mismo timestamp, skip
  const fulfilledAt = order.fulfillments?.[0]?.created_at
                   || order.updated_at
                   || new Date().toISOString();

  if (targetOrder.fulfilled_at === fulfilledAt) {
    console.log(`Silencio1 fulfilled: order ${orderId} already has this fulfilled_at, skipping duplicate`);
    return;
  }

  targetOrder.fulfilled_at = fulfilledAt;
  targetOrder.delivered_approx_at = calculateDeliveredApproxAt(fulfilledAt, targetOrder.shipping_zone);

  customerObj.updated_at = new Date().toISOString();

  await env.POTISSE_NFC.put(kvKey, JSON.stringify(customerObj));

  console.log(`Silencio1 fulfilled: updated order ${orderId} in customer ${customerId} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â fulfilled_at=${fulfilledAt}, delivered_approx_at=${targetOrder.delivered_approx_at}`);
}
__name(handleOrdersFulfilledForSilencio1, "handleOrdersFulfilledForSilencio1");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Webhook refunds/create handler
// Marca la orden refundada, invalida silencio_1.is_candidate si aplica.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
async function handleRefundsCreateForSilencio1(env, refund) {
  const orderId = String(refund.order_id || "");
  const refundId = String(refund.id || "");

  console.log(`Silencio1 refund incoming: refund=${refundId} order=${orderId}`);

  if (!orderId) {
    console.warn(`Silencio1 refund: skipping refund ${refundId} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no order_id`);
    return;
  }

  // El payload de refunds/create NO trae customer_id directamente.
  // Hay que buscar el customer que tiene esta orden en su array orders.
  const list = await env.POTISSE_NFC.list({ prefix: "customer:" });

  let matchedCustomerKey = null;
  let matchedCustomerObj = null;
  let matchedOrderIndex = -1;

  for (const keyEntry of list.keys) {
    const raw = await env.POTISSE_NFC.get(keyEntry.name);
    if (!raw) continue;

    let obj;
    try {
      obj = JSON.parse(raw);
    } catch {
      continue;
    }

    const idx = findOrderIndexByOrderId(obj, orderId);
    if (idx !== -1) {
      matchedCustomerKey = keyEntry.name;
      matchedCustomerObj = obj;
      matchedOrderIndex = idx;
      break;
    }
  }

  if (!matchedCustomerKey) {
    console.warn(`Silencio1 refund: no customer in KV contains order ${orderId} (orders/create may be pending)`);
    return;
  }

  const targetOrder = matchedCustomerObj.orders[matchedOrderIndex];

  // Idempotencia: si ya tiene este refund_id, skip
  if (targetOrder.refund_id === refundId) {
    console.log(`Silencio1 refund: refund ${refundId} already processed for order ${orderId}, skipping`);
    return;
  }

  targetOrder.refunded = true;
  targetOrder.refunded_at = refund.created_at || new Date().toISOString();
  targetOrder.refund_id = refundId;

  // Invalidar candidatura si estaba activa
  if (matchedCustomerObj.silencio_1?.is_candidate) {
    matchedCustomerObj.silencio_1.is_candidate = false;
    matchedCustomerObj.silencio_1.candidate_since = null;
    console.log(`Silencio1 refund: invalidated candidacy for customer ${matchedCustomerObj.id}`);
  }

  matchedCustomerObj.updated_at = new Date().toISOString();

  await env.POTISSE_NFC.put(matchedCustomerKey, JSON.stringify(matchedCustomerObj));

  console.log(`Silencio1 refund: order ${orderId} marked as refunded in customer ${matchedCustomerObj.id}`);
}
__name(handleRefundsCreateForSilencio1, "handleRefundsCreateForSilencio1");

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
// SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Cron nightly evaluation
// Escanea TODOS los customers de KV y evalÃƒÆ’Ã‚Âºa si cumplen criterios
// para pasar a is_candidate: true.
//
// Regla: ÃƒÂ¢Ã¢â‚¬Â°Ã‚Â¥2 orders con delivered_approx_at + 20 dÃƒÆ’Ã‚Â­as ya cumplidos,
// ninguna refunded, y is_candidate actualmente false.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
async function evaluateSilencio1Candidates(env) {
  console.log("Silencio1 cron: starting nightly evaluation");

  const now = new Date();
  const TWENTY_DAYS_MS = 20 * 24 * 60 * 60 * 1000;

  let scanned = 0;
  let newCandidates = 0;
  let cursor = undefined;

  do {
    const listOptions = { prefix: "customer:" };
    if (cursor) listOptions.cursor = cursor;

    const list = await env.POTISSE_NFC.list(listOptions);

    for (const keyEntry of list.keys) {
      scanned++;

      const raw = await env.POTISSE_NFC.get(keyEntry.name);
      if (!raw) continue;

      let obj;
      try {
        obj = JSON.parse(raw);
      } catch {
        console.warn(`Silencio1 cron: failed to parse ${keyEntry.name}`);
        continue;
      }

      // Skip si ya es candidato
      if (obj.silencio_1?.is_candidate === true) continue;

      // Filtrar orders vÃƒÆ’Ã‚Â¡lidas: delivered_approx_at existe, no refunded
      const validOrders = (obj.orders || []).filter(o =>
        o.delivered_approx_at && !o.refunded
      );

      // Necesita al menos 2 orders vÃƒÆ’Ã‚Â¡lidas
      if (validOrders.length < 2) continue;

      // La 2Ãƒâ€šÃ‚Âª orden (por fecha de entrega) debe tener delivered_approx_at + 20d cumplido
      const sortedValid = [...validOrders].sort((a, b) =>
        new Date(a.delivered_approx_at) - new Date(b.delivered_approx_at)
      );

      const secondOrder = sortedValid[1];
      const deliveredPlus20 = new Date(secondOrder.delivered_approx_at).getTime() + TWENTY_DAYS_MS;

      if (now.getTime() < deliveredPlus20) continue;

      // ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Cumple criterios: marcar candidato
      obj.silencio_1 = obj.silencio_1 || {};
      obj.silencio_1.is_candidate = true;
      obj.silencio_1.candidate_since = now.toISOString();
      obj.updated_at = now.toISOString();

      await env.POTISSE_NFC.put(keyEntry.name, JSON.stringify(obj));
      newCandidates++;

      console.log(`Silencio1 cron: new candidate ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â customer ${obj.id}`);
    }

    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  console.log(`Silencio1 cron: evaluation complete. Scanned=${scanned}, newCandidates=${newCandidates}`);

  return { scanned, newCandidates };
}
__name(evaluateSilencio1Candidates, "evaluateSilencio1Candidates");

// â”€â”€ Bloque B parte 3B, Fase 6: cron Access alerts (08:00 UTC) â”€â”€â”€â”€â”€â”€â”€â”€
async function runAccessAlerts(env) {
  const pendingRaw = await env.POTISSE_NFC.get("orders_pending_first_tap");
  const pending = pendingRaw ? JSON.parse(pendingRaw) : { order_ids: [] };

  // 1) Leer alertas activas existentes (persisten entre cron runs)
  const existingRaw = await env.POTISSE_NFC.get("access_alerts_active");
  const existing = existingRaw ? JSON.parse(existingRaw) : { iberian: [], european: [] };

  // 2) Leer alertas resueltas para no recrearlas
  const resolvedRaw = await env.POTISSE_NFC.get("access_alerts_resolved");
  const resolved = resolvedRaw ? JSON.parse(resolvedRaw) : [];
  const resolvedKey = new Set(resolved.map(r => String(r.order_id) + "_" + String(r.piece_id)));

  // 3) Construir mapas de alertas existentes por zona
  const iberianMap = new Map();
  const europeanMap = new Map();
  for (const a of (existing.iberian || [])) {
    iberianMap.set(String(a.order_id) + "_" + String(a.piece_id), a);
  }
  for (const a of (existing.european || [])) {
    europeanMap.set(String(a.order_id) + "_" + String(a.piece_id), a);
  }

  // 4) Evaluar pedidos pendientes: añadir nuevas, limpiar activadas
  for (const orderId of pending.order_ids) {
    const orderIndexRaw = await env.POTISSE_NFC.get(`order_${orderId}_pieces_index`);
    if (!orderIndexRaw) continue;
    const orderIndex = JSON.parse(orderIndexRaw);
    const firstPieceId = orderIndex.piece_ids?.[0];
    if (!firstPieceId) continue;

    const pieceRaw = await env.POTISSE_NFC.get(`piece_${firstPieceId}`);
    if (!pieceRaw) continue;
    const piece = JSON.parse(pieceRaw);

    const mapKey = String(orderId) + "_" + String(firstPieceId);

    // Si la pieza ya fue activada, quitar de alertas activas (si estaba)
    if (piece.origin_date) {
      iberianMap.delete(mapKey);
      europeanMap.delete(mapKey);
      continue;
    }

    // Si no tiene fulfillment_date, no puede alertar
    if (!piece.fulfillment_date) continue;

    // Si fue resuelta manualmente, no recrear
    if (resolvedKey.has(mapKey)) continue;

    const daysSince = Math.floor((Date.now() - new Date(piece.fulfillment_date).getTime()) / 86400000);
    const alertEntry = {
      order_id: orderId,
      piece_id: firstPieceId,
      customer_id: piece.customer_id,
      fulfillment_date: piece.fulfillment_date,
      shipping_zone: piece.shipping_zone,
      days_since_fulfillment: daysSince
    };

    if (piece.shipping_zone === "iberian" && daysSince >= 7) {
      if (!iberianMap.has(mapKey)) {
        iberianMap.set(mapKey, alertEntry);
      }
    } else if (piece.shipping_zone === "european" && daysSince >= 14) {
      if (!europeanMap.has(mapKey)) {
        europeanMap.set(mapKey, alertEntry);
      }
    }
  }

  // 5) También limpiar alertas existentes cuya pieza se haya activado
  // (por si el cliente activó entre cron runs)
  for (const [key, alert] of [...iberianMap]) {
    const pieceRaw = await env.POTISSE_NFC.get(`piece_${alert.piece_id}`);
    if (pieceRaw) {
      const piece = JSON.parse(pieceRaw);
      if (piece.origin_date) {
        iberianMap.delete(key);
      }
    }
  }
  for (const [key, alert] of [...europeanMap]) {
    const pieceRaw = await env.POTISSE_NFC.get(`piece_${alert.piece_id}`);
    if (pieceRaw) {
      const piece = JSON.parse(pieceRaw);
      if (piece.origin_date) {
        europeanMap.delete(key);
      }
    }
  }

  const iberian = Array.from(iberianMap.values());
  const european = Array.from(europeanMap.values());

  await env.POTISSE_NFC.put("access_alerts_active", JSON.stringify({
    iberian,
    european,
    last_run: new Date().toISOString(),
    total_count: iberian.length + european.length
  }));

  console.log(`Access alerts: ${iberian.length} iberian, ${european.length} european, ${pending.order_ids.length} orders checked`);
  return { iberian: iberian.length, european: european.length, checked: pending.order_ids.length };
}
__name(runAccessAlerts, "runAccessAlerts");
async function runPurgeRetracts(env) {
  // v6.6.2: timestamp "el cron corriÃ³" incondicional, primera lÃ­nea â€”
  // antes quedaba detrÃ¡s de los early returns de abajo y nunca se escribÃ­a
  // en producciÃ³n (retracted_posts no existe todavÃ­a, pre-launch).
  await env.POTISSE_NFC.put("system:last_purge_retracts_run", new Date().toISOString());

  const indexRaw = await env.POTISSE_NFC.get("retracted_posts");
  if (!indexRaw) {
    console.log("Purge retracts: no retracted_posts index, nothing to do");
    return { purged: 0, remaining: 0 };
  }

  let index;
  try {
    index = JSON.parse(indexRaw);
  } catch {
    console.error("Purge retracts: retracted_posts index corrupted, skipping");
    return { purged: 0, remaining: 0 };
  }

  const remainingPending = [];
  let purgedCount = 0;

  for (const postId of index.pending || []) {
    const postRaw = await env.POTISSE_NFC.get(`post_${postId}`);
    if (!postRaw) continue; // ya purgado o borrado, se cae del Ã­ndice

    let post;
    try {
      post = JSON.parse(postRaw);
    } catch {
      continue;
    }

    if (post.status !== "retracted" || !post.retracted_at) continue; // ya no aplica, se cae del Ã­ndice

    const hoursSinceRetract = (Date.now() - new Date(post.retracted_at).getTime()) / (60 * 60 * 1000);
    if (hoursSinceRetract >= 24) {
      if (post.r2_key) {
        await env.POTISSE_POSTS.delete(post.r2_key);
      }
      await env.POTISSE_NFC.delete(`post_${postId}`);
      purgedCount++;
      console.log(`Purged retracted post ${postId} after 24h`);
    } else {
      remainingPending.push(postId);
    }
  }

  await env.POTISSE_NFC.put("retracted_posts", JSON.stringify({ pending: remainingPending }));
  console.log(`Purge retracts: ${purgedCount} purged, ${remainingPending.length} still pending`);
  return { purged: purgedCount, remaining: remainingPending.length };
}
__name(runPurgeRetracts, "runPurgeRetracts");

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// BLOQUE B parte 1 â€” Piezas, washes, sesiÃ³n Club (cookie potisse_session)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const EU_SHIPPING_COUNTRIES = [
  "FR", "DE", "IT", "NL", "BE", "LU", "AT", "IE",
  "DK", "SE", "FI", "GR", "CY", "MT",
  "EE", "LV", "LT", "PL", "CZ", "SK", "SI",
  "HU", "HR", "RO", "BG"
];
const BALEARES_PROVINCE_PIECES = "IB";
const EXCLUDED_ES_PROVINCES_PIECES = ["CN", "TF", "GC", "CE", "ML"];

function resolvePieceShippingZone(shippingAddress, orderId) {
  const country = (shippingAddress?.country_code || "").toUpperCase();
  const province = (shippingAddress?.province_code || "").toUpperCase();
  const zip = (shippingAddress?.zip || "").trim();

  if (country === "ES") {
    if (EXCLUDED_ES_PROVINCES_PIECES.includes(province)) {
      console.warn(`Pieces: excluded ES province ${province} for order ${orderId}, defaulting shipping_zone to european`);
      return "european";
    }
    if (province === BALEARES_PROVINCE_PIECES) return "european";
    return "iberian";
  }
  if (country === "PT") {
    if (zip.startsWith("9")) {
      console.warn(`Pieces: excluded PT zip ${zip} for order ${orderId}, defaulting shipping_zone to european`);
      return "european";
    }
    return "iberian";
  }
  if (!country) {
    console.warn(`Pieces: no shipping_address in order ${orderId}, defaulting shipping_zone to european`);
  } else if (!EU_SHIPPING_COUNTRIES.includes(country)) {
    console.warn(`Pieces: unrecognized shipping country "${country}" for order ${orderId}, defaulting shipping_zone to european`);
  }
  return "european";
}
__name(resolvePieceShippingZone, "resolvePieceShippingZone");

async function listAllKeysWithPrefix(env, prefix) {
  let keys = [];
  let cursor;
  do {
    const opts = { prefix };
    if (cursor) opts.cursor = cursor;
    const list = await env.POTISSE_NFC.list(opts);
    keys = keys.concat(list.keys);
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  return keys;
}
__name(listAllKeysWithPrefix, "listAllKeysWithPrefix");

// â”€â”€ Bloque B parte 2: Â¿el customer ya es miembro? (tiene alguna pieza tapeada) â”€â”€
async function customerIsMember(env, customerId) {
  const indexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
  if (!indexRaw) return false;
  const index = JSON.parse(indexRaw);
  for (const pieceId of index.piece_ids) {
    const pieceRaw = await env.POTISSE_NFC.get(`piece_${pieceId}`);
    if (!pieceRaw) continue;
    const piece = JSON.parse(pieceRaw);
    if (piece.first_tap_at) return true;
  }
  return false;
}
__name(customerIsMember, "customerIsMember");

// â”€â”€ Pieces: creaciÃ³n al recibir orders/create â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Devuelve { created, isMember }: created=false en cualquier salida temprana
// (sin customer_id, webhook duplicado, o 0 piezas) para que el llamador no
// dispare notifyFranPendingNfc en reintentos de Shopify.
async function createPiecesForOrder(env, order) {
  const orderId = order.id;
  const customerId = order.customer?.id;

  if (!customerId) {
    console.warn(`Pieces: skipping order ${orderId} â€” no customer_id`);
    return { created: false, isMember: false };
  }

  const orderIndexKey = `order_${orderId}_pieces_index`;

  // Idempotencia: Shopify puede reenviar el webhook duplicado
  const existingOrderIndex = await env.POTISSE_NFC.get(orderIndexKey);
  if (existingOrderIndex) {
    console.log(`Pieces: order ${orderId} already has pieces index, skipping duplicate`);
    return { created: false, isMember: false };
  }

  const isMember = await customerIsMember(env, customerId);

  const shippingZone = resolvePieceShippingZone(order.shipping_address, orderId);
  const orderCreatedAt = order.created_at || new Date().toISOString();

  const allPieceIds = [];

  for (const item of order.line_items || []) {
    const quantity = item.quantity || 1;
    const lineItemId = item.id;

    for (let unitIndex = 0; unitIndex < quantity; unitIndex++) {
      const pieceId = `${orderId}_${lineItemId}_${unitIndex}`;
      const piece = {
        piece_id: pieceId,
        order_id: orderId,
        line_item_id: lineItemId,
        unit_index: unitIndex,
        customer_id: customerId,
        product_name: item.name || item.title || "",
        sku: item.sku || "",
        shopify_variant_id: item.variant_id || null,
        order_created_at: orderCreatedAt,
        fulfillment_date: null,
        shipping_zone: shippingZone,
        first_tap_at: null,
        origin_date: null,
        fallback_applied_at: null,
        arriving: isMember
      };
      await env.POTISSE_NFC.put(`piece_${pieceId}`, JSON.stringify(piece));
      allPieceIds.push(pieceId);
    }
  }

  if (allPieceIds.length === 0) {
    console.warn(`Pieces: order ${orderId} produced 0 pieces (no line_items?)`);
    return { created: false, isMember };
  }

  const customerIndexKey = `customer_${customerId}_pieces_index`;
  const existingCustomerIndexRaw = await env.POTISSE_NFC.get(customerIndexKey);
  const customerIndex = existingCustomerIndexRaw ? JSON.parse(existingCustomerIndexRaw) : { piece_ids: [] };
  customerIndex.piece_ids.push(...allPieceIds);
  await env.POTISSE_NFC.put(customerIndexKey, JSON.stringify(customerIndex));

  await env.POTISSE_NFC.put(orderIndexKey, JSON.stringify({ piece_ids: allPieceIds }));

  console.log(`Pieces: created ${allPieceIds.length} pieces for order ${orderId}, customer ${customerId}, isMember=${isMember}`);

  return { created: true, isMember };
}
__name(createPiecesForOrder, "createPiecesForOrder");

// â”€â”€ Pieces: fulfillment_date + orders_pending_first_tap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function updatePiecesForFulfillment(env, order) {
  const orderId = order.id;
  const orderIndexKey = `order_${orderId}_pieces_index`;
  const orderIndexRaw = await env.POTISSE_NFC.get(orderIndexKey);

  if (!orderIndexRaw) {
    console.warn(`Pieces: fulfillment for order ${orderId} but no pieces index found (orders/create may be pending)`);
    return;
  }

  const orderIndex = JSON.parse(orderIndexRaw);
  const fulfillmentDate = order.fulfillments?.[0]?.created_at || order.updated_at || new Date().toISOString();

  for (const pieceId of orderIndex.piece_ids) {
    const pieceKey = `piece_${pieceId}`;
    const pieceRaw = await env.POTISSE_NFC.get(pieceKey);
    if (!pieceRaw) continue;

    const piece = JSON.parse(pieceRaw);
    if (piece.fulfillment_date) continue; // idempotencia

    piece.fulfillment_date = fulfillmentDate;

    // Bloque B parte 2: piezas ARRIVING (cliente ya miembro) se activan
    // completas en el fulfillment, sin esperar tap de la tarjeta nueva.
    if (piece.arriving === true) {
      piece.origin_date = piece.fulfillment_date;
      piece.arriving = false;
      // first_tap_at queda null a propÃ³sito: se rellenarÃ¡ cuando llegue
      // el tap real de la nueva tarjeta, como dato histÃ³rico.
    }

    await env.POTISSE_NFC.put(pieceKey, JSON.stringify(piece));
  }

  const pendingKey = "orders_pending_first_tap";
  const pendingRaw = await env.POTISSE_NFC.get(pendingKey);
  const pending = pendingRaw ? JSON.parse(pendingRaw) : { order_ids: [] };
  if (!pending.order_ids.includes(orderId)) {
    pending.order_ids.push(orderId);
    await env.POTISSE_NFC.put(pendingKey, JSON.stringify(pending));
  }

  console.log(`Pieces: fulfillment_date=${fulfillmentDate} set for order ${orderId}, added to orders_pending_first_tap`);
}
__name(updatePiecesForFulfillment, "updatePiecesForFulfillment");

// â”€â”€ Washes: helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function listWashesForPiece(env, pieceId) {
  const keys = await listAllKeysWithPrefix(env, `wash_${pieceId}_`);
  const washes = [];
  for (const key of keys) {
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    try {
      washes.push(JSON.parse(raw));
    } catch {
      console.warn(`Washes: failed to parse ${key.name}`);
    }
  }
  return washes;
}
__name(listWashesForPiece, "listWashesForPiece");

// â”€â”€ Rhythm â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const RHYTHM_TIERS = [
  { maxCount: 2, phase: "pre", visible: false, phrase: "The Rhythm appears after her third wash." },
  { maxCount: 3, phase: "early", visible: true, phrase: "She is still finding her shape." },
  { maxCount: 15, phase: "settling", visible: true, phrase: "She is settling into you now." },
  { maxCount: 40, phase: "settled", visible: true, phrase: "She is yours now, unmistakably." },
  { maxCount: Infinity, phase: "heritage", visible: true, phrase: "A companion, now. Not many make it here." }
];

function computeRhythm(washCount) {
  const tier = RHYTHM_TIERS.find(t => washCount <= t.maxCount);
  return { phase: tier.phase, phrase: tier.phrase, visible: tier.visible };
}
__name(computeRhythm, "computeRhythm");

function monthsSince(originDateIso) {
  if (!originDateIso) return null;
  const origin = new Date(originDateIso);
  const now = new Date();
  let months = (now.getFullYear() - origin.getFullYear()) * 12 + (now.getMonth() - origin.getMonth());
  if (now.getDate() < origin.getDate()) months--;
  return Math.max(0, months);
}
__name(monthsSince, "monthsSince");

// â”€â”€ SesiÃ³n Club: cookie potisse_session â†’ session_<token> en KV â”€â”€â”€â”€
// NOTA: el endpoint que EMITE esta cookie (start-session) se construye
// en push 2, junto al handler NFC tap. Este bloque solo LEE la sesiÃ³n.
function parseDevice(userAgent) {
  if (!userAgent) return "Unknown";
  const ua = userAgent.toLowerCase();
  if (ua.includes("iphone")) return "iPhone";
  if (ua.includes("android")) return "Android";
  if (ua.includes("ipad")) return "iPad";
  if (ua.includes("macintosh") || ua.includes("mac os")) return "Mac";
  if (ua.includes("windows")) return "Windows";
  return "Desktop";
}
__name(parseDevice, "parseDevice");

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) cookies[key] = decodeURIComponent(val);
  });
  return cookies;
}
__name(parseCookies, "parseCookies");

// â”€â”€ Bloque B parte 3A, secciÃ³n 1.2: rate limit soft 100 req/min por customer_id â”€â”€
const clubRateLimitMap = new Map();
const CLUB_RATE_LIMIT_MAX = 100;
const CLUB_RATE_LIMIT_WINDOW_MS = 60 * 1000;

function checkClubRateLimit(customerId) {
  const key = String(customerId);
  const now = Date.now();
  const entry = clubRateLimitMap.get(key);
  if (!entry || (now - entry.windowStart) > CLUB_RATE_LIMIT_WINDOW_MS) {
    clubRateLimitMap.set(key, { count: 1, windowStart: now });
    return { limited: false };
  }
  entry.count++;
  if (entry.count > CLUB_RATE_LIMIT_MAX) {
    return { limited: true };
  }
  return { limited: false };
}
__name(checkClubRateLimit, "checkClubRateLimit");

async function resolveClubSession(request, env) {
  const cookies = parseCookies(request);
  const token = cookies["potisse_session"];
  if (!token) return { error: "no_session", status: 401 };

  const raw = await env.POTISSE_NFC.get(`session_${token}`);
  if (!raw) return { error: "invalid_session", status: 401 };

  let session;
  try {
    session = JSON.parse(raw);
  } catch {
    return { error: "invalid_session", status: 401 };
  }

  if (new Date(session.expires_at).getTime() < Date.now()) {
    await env.POTISSE_NFC.delete(`session_${token}`);
    return { error: "session_expired", status: 401 };
  }

  // Rate limit ANTES del rolling refresh, per spec secciÃ³n 1.2.
  const rl = checkClubRateLimit(session.customer_id);
  if (rl.limited) {
    return { error: "rate_limited", status: 429 };
  }

  // Bloque B parte 2, secciÃ³n 6: refresh rolling â€” cada request autenticado
  // vÃ¡lido extiende la sesiÃ³n 30min mÃ¡s, tanto en KV como (mÃ¡s abajo, en la
  // respuesta) en la cookie del navegador.
  session.expires_at = new Date(Date.now() + 1800 * 1000).toISOString();
  await env.POTISSE_NFC.put(`session_${token}`, JSON.stringify(session), { expirationTtl: 1800 });

  return { session, token };
}
__name(resolveClubSession, "resolveClubSession");

function clubRateLimitResponse(request) {
  return new Response(JSON.stringify({ error: "too_many_requests", retry_after_seconds: 60 }), {
    status: 429,
    headers: { ...clubCorsHeaders(request), "Content-Type": "application/json", "Retry-After": "60" }
  });
}
__name(clubRateLimitResponse, "clubRateLimitResponse");

function buildSessionCookieHeader(token) {
  return `potisse_session=${token}; Domain=.potisse.com; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Lax`;
}
__name(buildSessionCookieHeader, "buildSessionCookieHeader");

function clubCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "https://www.potisse.com";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}
__name(clubCorsHeaders, "clubCorsHeaders");

function clubJsonResponse(request, data, status = 200, sessionToken = null) {
  const headers = { ...clubCorsHeaders(request), "Content-Type": "application/json" };
  // Rolling cookie: solo en respuestas autenticadas exitosas (200), nunca en errores.
  if (sessionToken && status === 200) {
    headers["Set-Cookie"] = buildSessionCookieHeader(sessionToken);
  }
  return new Response(JSON.stringify(data), { status, headers });
}
__name(clubJsonResponse, "clubJsonResponse");

// â”€â”€ In-memory cache /api/club/me (30 min, por customer_id) â”€â”€â”€â”€â”€â”€â”€â”€â”€
const clubMeCache = new Map();
const CLUB_ME_CACHE_TTL_MS = 30 * 60 * 1000;

function invalidateClubMeCache(customerId) {
  clubMeCache.delete(String(customerId));
}
__name(invalidateClubMeCache, "invalidateClubMeCache");

// â”€â”€ Bloque B parte 3A cierre: product_image por pieza, cacheado 24h en KV â”€â”€
// NOTA: el encargo original pedÃ­a env.SHOPIFY_ADMIN_TOKEN, un secret que no
// existe en producciÃ³n (verificado con `wrangler secret list` â€” solo existe
// SHOPIFY_ACCESS_TOKEN, que es el que ya usan getShopifyCustomerBasic,
// upsertCustomerMetafield, etc.). Reutilizo ese en vez de pedir un secret
// nuevo redundante para lo mismo.
async function getPieceProductImage(env, piece) {
  if (!piece.shopify_variant_id) return null;

  const cacheKey = `variant_image_${piece.shopify_variant_id}`;
  const cachedRaw = await env.POTISSE_NFC.get(cacheKey);
  if (cachedRaw) {
    try {
      const cached = JSON.parse(cachedRaw);
      return cached.image_url || null;
    } catch {}
  }

  try {
    const shopifyDomain = env.SHOPIFY_STORE_DOMAIN;
    const token = env.SHOPIFY_ACCESS_TOKEN;
    if (!token) {
      console.warn("SHOPIFY_ACCESS_TOKEN missing, skipping product image fetch");
      return null;
    }

    const variantRes = await fetch(
      `https://${shopifyDomain}/admin/api/2024-07/variants/${piece.shopify_variant_id}.json`,
      { headers: { "X-Shopify-Access-Token": token } }
    );

    if (!variantRes.ok) {
      console.warn(`Shopify variant fetch failed ${piece.shopify_variant_id}: ${variantRes.status}`);
      return null;
    }

    const variantData = await variantRes.json();
    const variant = variantData.variant;
    if (!variant || !variant.product_id) return null;

    let imageUrl = null;
    if (variant.image_id) {
      const imageRes = await fetch(
        `https://${shopifyDomain}/admin/api/2024-07/products/${variant.product_id}/images/${variant.image_id}.json`,
        { headers: { "X-Shopify-Access-Token": token } }
      );
      if (imageRes.ok) {
        const imgData = await imageRes.json();
        imageUrl = imgData.image?.src || null;
      }
    }

    if (!imageUrl) {
      const productRes = await fetch(
        `https://${shopifyDomain}/admin/api/2024-07/products/${variant.product_id}.json?fields=image`,
        { headers: { "X-Shopify-Access-Token": token } }
      );
      if (productRes.ok) {
        const productData = await productRes.json();
        imageUrl = productData.product?.image?.src || null;
      }
    }

    await env.POTISSE_NFC.put(
      cacheKey,
      JSON.stringify({ image_url: imageUrl, cached_at: new Date().toISOString() }),
      { expirationTtl: 86400 }
    );

    return imageUrl;
  } catch (err) {
    console.error(`getPieceProductImage failed for variant ${piece.shopify_variant_id}: ${err.message}`);
    return null;
  }
}
__name(getPieceProductImage, "getPieceProductImage");

async function getShopifyCustomerBasic(env, customerId, fallbackEmail) {
  try {
    const res = await fetch(
      `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/${customerId}.json`,
      { headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN } }
    );
    if (!res.ok) return { name: "", email: fallbackEmail || "", tags: "", ok: false };
    const data = await res.json();
    const c = data.customer || {};
    const name = [c.first_name, c.last_name].filter(Boolean).join(" ");
    return { name, email: c.email || fallbackEmail || "", tags: c.tags || "", ok: true };
  } catch (err) {
    console.error(`Club: getShopifyCustomerBasic failed for ${customerId}: ${err.message}`);
    return { name: "", email: fallbackEmail || "", tags: "", ok: false };
  }
}
__name(getShopifyCustomerBasic, "getShopifyCustomerBasic");

// â”€â”€ Fase 9.2, CorrecciÃ³n 2: cache 24h de tags Shopify para el listado â”€â”€
const TAGS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

async function getCachedShopifyTags(env, customerId, fallbackEmail) {
  const cacheKey = `customer_${customerId}_tags_cache`;
  const cachedRaw = await env.POTISSE_NFC.get(cacheKey);
  let cached = null;
  if (cachedRaw) {
    try {
      cached = JSON.parse(cachedRaw);
    } catch {}
  }

  const isFresh = cached && (Date.now() - new Date(cached.cached_at).getTime()) < TAGS_CACHE_TTL_MS;
  if (isFresh) {
    return cached.tags;
  }

  const shopifyInfo = await getShopifyCustomerBasic(env, customerId, fallbackEmail);
  if (shopifyInfo.ok) {
    const fresh = { tags: shopifyInfo.tags || "", cached_at: new Date().toISOString() };
    await env.POTISSE_NFC.put(cacheKey, JSON.stringify(fresh));
    return fresh.tags;
  }

  // Shopify fallÃ³ de verdad (ok:false) â€” si hay cache vieja, mejor stale que null en la UI
  if (cached) return cached.tags;
  return "";
}
__name(getCachedShopifyTags, "getCachedShopifyTags");

// â”€â”€ Bloque B parte 3B, Fase 5: anniversaries + journey + post_reply â”€â”€
const ANNIVERSARY_PURCHASE_YEARS = [1, 3, 5, 10];
const ANNIVERSARY_PIECE_MONTHS = [6];
const ANNIVERSARY_PIECE_YEARS = [1, 3, 5, 10];
const ANNIVERSARY_WASH_MILESTONES = [10, 25, 50, 100, 200];
const ANNIVERSARY_DUAL_MILESTONES = {
  purchase_years: [5, 10],
  piece_years: [5, 10],
  washes: [100, 200]
};

// Placeholder fijo pendiente de fÃ³rmula real de Fran (ver reporte Fase 5).
const JOURNEY_KM_FIXED = 10300;

function anniversaryIsNew(exactDateIso) {
  const diffDays = (Date.now() - new Date(exactDateIso).getTime()) / 86400000;
  return diffDays >= 0 && diffDays < 7;
}
__name(anniversaryIsNew, "anniversaryIsNew");

function anniversarySignature(type, value) {
  const dualList = ANNIVERSARY_DUAL_MILESTONES[type] || [];
  return dualList.includes(value) ? "dual" : "potisse";
}
__name(anniversarySignature, "anniversarySignature");

function computePurchaseYearAnniversaries(memberSince) {
  if (!memberSince) return [];
  const results = [];
  for (const years of ANNIVERSARY_PURCHASE_YEARS) {
    const milestoneDate = new Date(memberSince);
    milestoneDate.setUTCFullYear(milestoneDate.getUTCFullYear() + years);
    if (milestoneDate.getTime() > Date.now()) continue;
    results.push({
      type: "purchase_years",
      subject: "customer",
      milestone: `${years} year${years > 1 ? "s" : ""}`,
      date: milestoneDate.toISOString(),
      is_new: anniversaryIsNew(milestoneDate.toISOString()),
      signature: anniversarySignature("purchase_years", years)
    });
  }
  return results;
}
__name(computePurchaseYearAnniversaries, "computePurchaseYearAnniversaries");

// ascendingActiveWashes: washes activos de la pieza, ordenados wash_date ASC
function computePieceAnniversaries(piece, ascendingActiveWashes) {
  const results = [];

  if (piece.origin_date) {
    for (const months of ANNIVERSARY_PIECE_MONTHS) {
      const milestoneDate = new Date(piece.origin_date);
      milestoneDate.setUTCMonth(milestoneDate.getUTCMonth() + months);
      if (milestoneDate.getTime() > Date.now()) continue;
      results.push({
        type: "piece_months",
        subject: "piece",
        subject_id: piece.piece_id,
        product_name: piece.product_name,
        milestone: `${months} months`,
        date: milestoneDate.toISOString(),
        is_new: anniversaryIsNew(milestoneDate.toISOString()),
        signature: "potisse"
      });
    }

    for (const years of ANNIVERSARY_PIECE_YEARS) {
      const milestoneDate = new Date(piece.origin_date);
      milestoneDate.setUTCFullYear(milestoneDate.getUTCFullYear() + years);
      if (milestoneDate.getTime() > Date.now()) continue;
      results.push({
        type: "piece_years",
        subject: "piece",
        subject_id: piece.piece_id,
        product_name: piece.product_name,
        milestone: `${years} year${years > 1 ? "s" : ""}`,
        date: milestoneDate.toISOString(),
        is_new: anniversaryIsNew(milestoneDate.toISOString()),
        signature: anniversarySignature("piece_years", years)
      });
    }
  }

  for (const n of ANNIVERSARY_WASH_MILESTONES) {
    if (ascendingActiveWashes.length < n) continue;
    const milestoneWash = ascendingActiveWashes[n - 1];
    const dateIso = milestoneWash.wash_date_utc || new Date(milestoneWash.wash_date).toISOString();
    results.push({
      type: "washes",
      subject: "piece",
      subject_id: piece.piece_id,
      product_name: piece.product_name,
      milestone: `${n} washes`,
      date: dateIso,
      is_new: anniversaryIsNew(dateIso),
      signature: anniversarySignature("washes", n)
    });
  }

  return results;
}
__name(computePieceAnniversaries, "computePieceAnniversaries");

function computeJourney(renderedPieces) {
  let oldest = null;
  for (const p of renderedPieces) {
    if (!p.origin_date) continue;
    if (!oldest || new Date(p.origin_date) < new Date(oldest.origin_date)) {
      oldest = p;
    }
  }
  if (!oldest) return null;
  return {
    piece_id: oldest.piece_id,
    product_name: oldest.product_name,
    origin_date: oldest.origin_date,
    km: JOURNEY_KM_FIXED
  };
}
__name(computeJourney, "computeJourney");

function nextMonthFirstDayIso() {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0)).toISOString();
}
__name(nextMonthFirstDayIso, "nextMonthFirstDayIso");

// Un solo paso sobre los posts del customer: resuelve latest_reply y
// post_state (pending) a la vez, evitando doble lectura de KV.
async function computeClubPostsSnapshot(env, customerId) {
  const postIds = await getCustomerPostIds(env, customerId);
  let latestReply = null;
  let pending = null;

  for (const pid of postIds) {
    const raw = await env.POTISSE_NFC.get(`post_${pid}`);
    if (!raw) continue;
    let p;
    try {
      p = JSON.parse(raw);
    } catch {
      continue;
    }
    if (p.status === "pending") {
      pending = p;
    } else if (p.status === "kept" || p.status === "published_ig") {
      if (!latestReply || new Date(p.reviewed_at) > new Date(latestReply.reviewed_at)) {
        latestReply = p;
      }
    }
  }

  const quota = await getPostQuota(env, customerId);

  return {
    latest_reply: latestReply
      ? {
          post_id: latestReply.post_id,
          status: latestReply.status,
          reply_message: latestReply.reply_message,
          ig_post_url: latestReply.ig_post_url ?? null,
          reviewed_at: latestReply.reviewed_at,
          caption: latestReply.caption
        }
      : null,
    post_state: {
      has_pending: !!pending,
      pending_post_id: pending ? pending.post_id : undefined,
      pending_submitted_at: pending ? pending.submitted_at : undefined,
      quota: { month: quota.month, used: quota.used, remaining: 2 - quota.used },
      quota_reset: nextMonthFirstDayIso()
    }
  };
}
__name(computeClubPostsSnapshot, "computeClubPostsSnapshot");

// â”€â”€ GET /api/club/me â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleClubMe(request, env) {
  const authResult = await resolveClubSession(request, env);
  if (authResult.error === "rate_limited") return clubRateLimitResponse(request);
  if (authResult.error) return clubJsonResponse(request, { error: authResult.error }, authResult.status);

  const { session, token } = authResult;
  const customerId = session.customer_id;

  const cached = clubMeCache.get(String(customerId));
  if (cached && cached.expires > Date.now()) {
    return clubJsonResponse(request, cached.data, 200, token);
  }

  const customerIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
  const pieceIds = customerIndexRaw ? JSON.parse(customerIndexRaw).piece_ids : [];

  // Paralelizado: cada pieza resuelve washes + product_image (variantâ†’imagen,
  // cacheado 24h en KV) a la vez en vez de en serie.
  const piecesData = await Promise.all(pieceIds.map(async (pieceId) => {
    const pieceRaw = await env.POTISSE_NFC.get(`piece_${pieceId}`);
    if (!pieceRaw) return null;
    const piece = JSON.parse(pieceRaw);

    const [allWashes, productImage] = await Promise.all([
      listWashesForPiece(env, pieceId),
      getPieceProductImage(env, piece)
    ]);

    const activeWashes = allWashes.filter((w) => !w.deleted_at);
    const washCount = activeWashes.length;
    const ascendingActiveWashes = [...activeWashes].sort((a, b) => new Date(a.wash_date) - new Date(b.wash_date));
    activeWashes.sort((a, b) => new Date(b.wash_date) - new Date(a.wash_date));

    return {
      piece,
      anniversaries: computePieceAnniversaries(piece, ascendingActiveWashes),
      rendered: {
        piece_id: piece.piece_id,
        product_name: piece.product_name,
        product_image: productImage,
        sku: piece.sku,
        origin_date: piece.origin_date,
        months_together: monthsSince(piece.origin_date),
        wash_count: washCount,
        rhythm: computeRhythm(washCount),
        washes: activeWashes.map((w) => ({
          wash_id: w.wash_id,
          wash_date: w.wash_date,
          note: w.note
        }))
      }
    };
  }));

  const pieces = [];
  let memberSince = null;
  let anniversaries = [];

  for (const entry of piecesData) {
    if (!entry) continue;
    if (entry.piece.fulfillment_date) {
      if (!memberSince || new Date(entry.piece.fulfillment_date) < new Date(memberSince)) {
        memberSince = entry.piece.fulfillment_date;
      }
    }
    pieces.push(entry.rendered);
    anniversaries = anniversaries.concat(entry.anniversaries);
  }

  anniversaries = anniversaries.concat(computePurchaseYearAnniversaries(memberSince));
  anniversaries.sort((a, b) => new Date(b.date) - new Date(a.date));

  const journey = computeJourney(pieces);

  const postsSnapshot = await computeClubPostsSnapshot(env, customerId);

  const customer = await getShopifyCustomerBasic(env, customerId, session.email);

  const responseData = {
    customer: {
      id: customerId,
      name: customer.name,
      email: customer.email,
      member_since: memberSince
    },
    collection: { pieces },
    journey,
    anniversaries,
    latest_reply: postsSnapshot.latest_reply,
    post_state: postsSnapshot.post_state,
    hours: {},
    did_you_know: {},
    silence: {}
  };

  clubMeCache.set(String(customerId), { data: responseData, expires: Date.now() + CLUB_ME_CACHE_TTL_MS });

  return clubJsonResponse(request, responseData, 200, token);
}
__name(handleClubMe, "handleClubMe");

// â”€â”€ POST /api/club/wash â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleClubWashAdd(request, env) {
  const authResult = await resolveClubSession(request, env);
  if (authResult.error === "rate_limited") return clubRateLimitResponse(request);
  if (authResult.error) return clubJsonResponse(request, { error: authResult.error }, authResult.status);

  const { session, token } = authResult;
  const customerId = session.customer_id;

  let body;
  try {
    body = await request.json();
  } catch {
    return clubJsonResponse(request, { error: "invalid_body" }, 400);
  }

  const { piece_id, wash_date, note } = body || {};
  if (!piece_id || !wash_date) {
    return clubJsonResponse(request, { error: "missing_fields" }, 400);
  }

  const washDateObj = new Date(wash_date);
  if (isNaN(washDateObj.getTime())) {
    return clubJsonResponse(request, { error: "invalid_wash_date" }, 400);
  }

  const pieceRaw = await env.POTISSE_NFC.get(`piece_${piece_id}`);
  if (!pieceRaw) {
    return clubJsonResponse(request, { error: "forbidden" }, 403);
  }
  const piece = JSON.parse(pieceRaw);

  if (String(piece.customer_id) !== String(customerId)) {
    return clubJsonResponse(request, { error: "forbidden" }, 403);
  }

  if (!piece.origin_date) {
    return clubJsonResponse(request, { error: "Piece not yet activated" }, 403);
  }

  if (piece.fulfillment_date && washDateObj < new Date(piece.fulfillment_date)) {
    return clubJsonResponse(request, { error: "Wash date before fulfillment" }, 400);
  }

  if (washDateObj.getTime() > Date.now()) {
    return clubJsonResponse(request, { error: "Wash date in the future" }, 400);
  }

  const existingWashes = await listWashesForPiece(env, piece_id);
  const newDayKey = String(wash_date).slice(0, 10);
  const duplicate = existingWashes.some((w) => !w.deleted_at && String(w.wash_date).slice(0, 10) === newDayKey);
  if (duplicate) {
    return clubJsonResponse(request, { error: "This piece has been washed today already." }, 409);
  }

  if (note != null && String(note).length > 500) {
    return clubJsonResponse(request, { error: "note_too_long" }, 400);
  }

  const washId = crypto.randomUUID();
  const wash = {
    wash_id: washId,
    piece_id,
    customer_id: customerId,
    wash_date,
    wash_date_utc: washDateObj.toISOString(),
    note: note || null,
    created_at: new Date().toISOString(),
    deleted_at: null
  };

  await env.POTISSE_NFC.put(`wash_${piece_id}_${washId}`, JSON.stringify(wash));
  // Ãndice auxiliar para resolver DELETE /api/club/wash/:wash_id sin escanear todo el namespace
  await env.POTISSE_NFC.put(`washindex_${washId}`, piece_id);

  invalidateClubMeCache(customerId);

  const washCountNew = existingWashes.filter((w) => !w.deleted_at).length + 1;

  return clubJsonResponse(request, { wash_id: washId, wash_count_new: washCountNew }, 200, token);
}
__name(handleClubWashAdd, "handleClubWashAdd");

// â”€â”€ DELETE /api/club/wash/:wash_id â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleClubWashDelete(request, env, washId) {
  const authResult = await resolveClubSession(request, env);
  if (authResult.error === "rate_limited") return clubRateLimitResponse(request);
  if (authResult.error) return clubJsonResponse(request, { error: authResult.error }, authResult.status);

  const { session, token } = authResult;
  const customerId = session.customer_id;

  const pieceId = await env.POTISSE_NFC.get(`washindex_${washId}`);
  if (!pieceId) return clubJsonResponse(request, { error: "wash_not_found" }, 404);

  const washKey = `wash_${pieceId}_${washId}`;
  const washRaw = await env.POTISSE_NFC.get(washKey);
  if (!washRaw) return clubJsonResponse(request, { error: "wash_not_found" }, 404);

  const wash = JSON.parse(washRaw);

  if (String(wash.customer_id) !== String(customerId)) {
    return clubJsonResponse(request, { error: "forbidden" }, 403);
  }

  if (wash.deleted_at) {
    return clubJsonResponse(request, { error: "already_deleted" }, 410);
  }

  wash.deleted_at = new Date().toISOString();
  await env.POTISSE_NFC.put(washKey, JSON.stringify(wash));

  invalidateClubMeCache(customerId);

  const remainingWashes = await listWashesForPiece(env, pieceId);
  const washCountNew = remainingWashes.filter((w) => !w.deleted_at).length;

  return clubJsonResponse(request, { wash_count_new: washCountNew }, 200, token);
}
__name(handleClubWashDelete, "handleClubWashDelete");

// â”€â”€ Bloque B parte 3B, Fase 2: POST /api/club/post â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function validateImageMagicBytes(bytes, declaredType) {
  let actualType = null;
  if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    actualType = "image/jpeg";
  } else if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
    bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A
  ) {
    actualType = "image/png";
  }
  return { valid: actualType === declaredType, actualType };
}
__name(validateImageMagicBytes, "validateImageMagicBytes");

const clubPostUploadRateLimitMap = new Map();
const CLUB_POST_UPLOAD_RATE_LIMIT_MAX = 5;
const CLUB_POST_UPLOAD_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;

function checkClubPostUploadRateLimit(customerId) {
  const key = String(customerId);
  const now = Date.now();
  const entry = clubPostUploadRateLimitMap.get(key);
  if (!entry || (now - entry.windowStart) > CLUB_POST_UPLOAD_RATE_LIMIT_WINDOW_MS) {
    clubPostUploadRateLimitMap.set(key, { count: 1, windowStart: now });
    return { limited: false };
  }
  entry.count++;
  if (entry.count > CLUB_POST_UPLOAD_RATE_LIMIT_MAX) {
    return { limited: true };
  }
  return { limited: false };
}
__name(checkClubPostUploadRateLimit, "checkClubPostUploadRateLimit");

function currentMonthKey() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}
__name(currentMonthKey, "currentMonthKey");

async function getPostQuota(env, customerId) {
  const month = currentMonthKey();
  const raw = await env.POTISSE_NFC.get(`customer_${customerId}_post_quota`);
  if (!raw) return { month, used: 0 };
  let quota;
  try {
    quota = JSON.parse(raw);
  } catch {
    return { month, used: 0 };
  }
  if (quota.month !== month) return { month, used: 0 };
  return quota;
}
__name(getPostQuota, "getPostQuota");

// Ãndice de posts por customer, anÃ¡logo a customer_<id>_pieces_index.
// No estaba explÃ­cito en el encargo pero es necesario para el pending
// check (Fase 2, validaciÃ³n 3) y para latest_reply (Fase 5.1) sin
// escanear todo el namespace post_.
async function getCustomerPostIds(env, customerId) {
  const raw = await env.POTISSE_NFC.get(`customer_${customerId}_posts_index`);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
__name(getCustomerPostIds, "getCustomerPostIds");

// â”€â”€ Fase 9.1: Ã­ndice global posts_pending_all = { pending: [post_ids] } â”€â”€
// Permite a los endpoints admin listar pending sin escanear todo el
// namespace post_. Mantenido por handleClubPost (add), handleAdminPostCurate
// y handleClubPostRetract (remove) â€” cero cambio de comportamiento externo.
async function addToPostsPendingAllIndex(env, postId) {
  const raw = await env.POTISSE_NFC.get("posts_pending_all");
  let index = { pending: [] };
  if (raw) {
    try {
      index = JSON.parse(raw);
    } catch {}
  }
  if (!index.pending.includes(postId)) {
    index.pending.push(postId);
  }
  await env.POTISSE_NFC.put("posts_pending_all", JSON.stringify(index));
}
__name(addToPostsPendingAllIndex, "addToPostsPendingAllIndex");

async function removeFromPostsPendingAllIndex(env, postId) {
  const raw = await env.POTISSE_NFC.get("posts_pending_all");
  if (!raw) return;
  let index;
  try {
    index = JSON.parse(raw);
  } catch {
    return;
  }
  index.pending = (index.pending || []).filter((id) => id !== postId);
  await env.POTISSE_NFC.put("posts_pending_all", JSON.stringify(index));
}
__name(removeFromPostsPendingAllIndex, "removeFromPostsPendingAllIndex");

async function handleClubPost(request, env) {
  const authResult = await resolveClubSession(request, env);
  if (authResult.error === "rate_limited") return clubRateLimitResponse(request);
  if (authResult.error) return clubJsonResponse(request, { error: authResult.error }, authResult.status);

  const { session, token } = authResult;
  const customerId = session.customer_id;

  // 1. Rate limit 5 uploads/hora
  if (checkClubPostUploadRateLimit(customerId).limited) {
    return clubJsonResponse(request, { error: "too_many_uploads", retry_after_seconds: 3600 }, 429);
  }

  // 2. Quota mensual
  const quota = await getPostQuota(env, customerId);
  if (quota.used >= 2) {
    return clubJsonResponse(request, { error: "monthly_quota_exceeded" }, 400);
  }

  // 3. Pending check
  const postIds = await getCustomerPostIds(env, customerId);
  for (const pid of postIds) {
    const raw = await env.POTISSE_NFC.get(`post_${pid}`);
    if (!raw) continue;
    let p;
    try {
      p = JSON.parse(raw);
    } catch {
      continue;
    }
    if (p.status === "pending") {
      return clubJsonResponse(request, { error: "pending_post_exists" }, 400);
    }
  }

  // 4. Parse multipart/form-data
  let formData;
  try {
    formData = await request.formData();
  } catch {
    return clubJsonResponse(request, { error: "invalid_body" }, 400);
  }

  const file = formData.get("imagen");
  const captionRaw = formData.get("caption");
  const caption = captionRaw != null && captionRaw !== "" ? String(captionRaw) : null;

  if (caption != null && caption.length > 140) {
    return clubJsonResponse(request, { error: "caption_too_long" }, 400);
  }

  if (!file || typeof file === "string" || !file.type) {
    return clubJsonResponse(request, { error: "invalid_mime" }, 400);
  }

  // 5. Content-Type
  if (file.type !== "image/jpeg" && file.type !== "image/png") {
    return clubJsonResponse(request, { error: "invalid_mime" }, 400);
  }

  // 6. TamaÃ±o <= 10MB
  if (file.size > 10 * 1024 * 1024) {
    return clubJsonResponse(request, { error: "file_too_large" }, 400);
  }

  // 7. Magic bytes
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const magicCheck = validateImageMagicBytes(bytes, file.type);
  if (!magicCheck.valid) {
    return clubJsonResponse(request, { error: "invalid_image_content" }, 400);
  }

  // 8. post_id + extensiÃ³n
  const postId = crypto.randomUUID();
  const extension = file.type === "image/jpeg" ? "jpg" : "png";

  // 9. R2
  const r2Key = `posts/${customerId}/${postId}.${extension}`;
  await env.POTISSE_POSTS.put(r2Key, bytes, {
    httpMetadata: { contentType: file.type }
  });

  // 10. KV post_<id>
  const submittedAt = new Date().toISOString();
  const post = {
    post_id: postId,
    customer_id: customerId,
    submitted_at: submittedAt,
    r2_key: r2Key,
    caption,
    status: "pending",
    reply_message: null,
    ig_post_url: null,
    reviewed_at: null,
    reviewed_by: null
  };
  await env.POTISSE_NFC.put(`post_${postId}`, JSON.stringify(post));

  postIds.push(postId);
  await env.POTISSE_NFC.put(`customer_${customerId}_posts_index`, JSON.stringify(postIds));

  // Fase 9.1: Ã­ndice global para queries admin O(1), sin tocar comportamiento externo
  await addToPostsPendingAllIndex(env, postId);

  // 11. Incrementar quota
  const newQuota = { month: quota.month, used: quota.used + 1 };
  await env.POTISSE_NFC.put(`customer_${customerId}_post_quota`, JSON.stringify(newQuota));

  // 12. NotificaciÃ³n Resend a thepost@potisse.com (best-effort, no falla el request)
  try {
    const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
    const profile = profileRaw ? JSON.parse(profileRaw) : {};
    const captionPreview = caption ? caption.slice(0, 60) : "";
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "club@potisse.com",
        to: "thepost@potisse.com",
        subject: `New moment awaiting. Customer ${profile.first_name || customerId}.`,
        text: `${captionPreview}\n\nView: https://${env.SHOPIFY_STORE_DOMAIN}/admin/workshop-tools#post-curation\n\nâ€” POTISSE system`
      })
    });
    if (!res.ok) {
      const err = await res.text();
      console.error(`Resend notify post upload failed: ${res.status} ${err}`);
    }
  } catch (err) {
    console.error(`Resend notify post upload threw: ${err.message}`);
  }

  // 14. Invalidar cache /api/club/me
  invalidateClubMeCache(customerId);

  // 13. Response
  return clubJsonResponse(request, {
    ok: true,
    post_id: postId,
    quota_remaining: 2 - newQuota.used
  }, 200, token);
}
__name(handleClubPost, "handleClubPost");

// â”€â”€ Bloque B parte 3B, Fase 3: POST /api/club/post/retract â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const clubPostRetractRateLimitMap = new Map();
const CLUB_POST_RETRACT_RATE_LIMIT_MAX = 3;
const CLUB_POST_RETRACT_RATE_LIMIT_WINDOW_MS = 24 * 60 * 60 * 1000;

function checkClubPostRetractRateLimit(customerId) {
  const key = String(customerId);
  const now = Date.now();
  const entry = clubPostRetractRateLimitMap.get(key);
  if (!entry || (now - entry.windowStart) > CLUB_POST_RETRACT_RATE_LIMIT_WINDOW_MS) {
    clubPostRetractRateLimitMap.set(key, { count: 1, windowStart: now });
    return { limited: false };
  }
  entry.count++;
  if (entry.count > CLUB_POST_RETRACT_RATE_LIMIT_MAX) {
    return { limited: true };
  }
  return { limited: false };
}
__name(checkClubPostRetractRateLimit, "checkClubPostRetractRateLimit");

async function handleClubPostRetract(request, env) {
  const authResult = await resolveClubSession(request, env);
  if (authResult.error === "rate_limited") return clubRateLimitResponse(request);
  if (authResult.error) return clubJsonResponse(request, { error: authResult.error }, authResult.status);

  const { session, token } = authResult;
  const customerId = session.customer_id;

  // 1. Rate limit 3 retracts/24h â€” al superarlo, flag para alerta Workshop Tools
  if (checkClubPostRetractRateLimit(customerId).limited) {
    const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
    if (profileRaw) {
      try {
        const profile = JSON.parse(profileRaw);
        profile.excessive_retract_flagged_at = new Date().toISOString();
        await env.POTISSE_NFC.put(`customer_${customerId}_profile`, JSON.stringify(profile));
      } catch (err) {
        console.error(`Failed to flag excessive_retract_flagged_at for customer ${customerId}: ${err.message}`);
      }
    }
    return clubJsonResponse(request, { error: "excessive_retracts", message: "This piece is settled." }, 403);
  }

  // 2. Body
  let body;
  try {
    body = await request.json();
  } catch {
    return clubJsonResponse(request, { error: "invalid_body" }, 400);
  }
  const { post_id } = body || {};
  if (!post_id) {
    return clubJsonResponse(request, { error: "missing_fields" }, 400);
  }

  // 3. post existe
  const postRaw = await env.POTISSE_NFC.get(`post_${post_id}`);
  if (!postRaw) {
    return clubJsonResponse(request, { error: "post_not_found" }, 404);
  }
  const post = JSON.parse(postRaw);

  // 4. ownership
  if (String(post.customer_id) !== String(customerId)) {
    return clubJsonResponse(request, { error: "forbidden" }, 403);
  }

  // 5. debe estar pending
  if (post.status !== "pending") {
    return clubJsonResponse(request, { error: "not_pending" }, 400);
  }

  // 6. soft delete
  const retractedAt = new Date().toISOString();
  post.status = "retracted";
  post.retracted_at = retractedAt;
  await env.POTISSE_NFC.put(`post_${post_id}`, JSON.stringify(post));

  // Fase 9.1: sale del Ã­ndice global de pending
  await removeFromPostsPendingAllIndex(env, post_id);

  // 7. contador histÃ³rico â€” nunca se resetea
  const retractCountRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
  let retractCount = { total: 0, last_retract: null };
  if (retractCountRaw) {
    try {
      retractCount = JSON.parse(retractCountRaw);
    } catch {}
  }
  retractCount.total = (retractCount.total || 0) + 1;
  retractCount.last_retract = retractedAt;
  await env.POTISSE_NFC.put(`customer_${customerId}_retract_count`, JSON.stringify(retractCount));

  // 8. liberar slot de quota, solo si el mes de submitted_at coincide con el mes actual
  const submittedMonth = post.submitted_at ? post.submitted_at.slice(0, 7) : null;
  if (submittedMonth === currentMonthKey()) {
    const quota = await getPostQuota(env, customerId);
    if (quota.used > 0) {
      await env.POTISSE_NFC.put(`customer_${customerId}_post_quota`, JSON.stringify({ month: quota.month, used: quota.used - 1 }));
    }
  }

  // 9. NO se borra R2 todavÃ­a â€” se indexa para el purge cron (Fase 6), que lo
  // borrarÃ¡ 24h despuÃ©s. Ãndice segÃºn spec Fase 6: retracted_posts = { pending: [post_ids] }.
  const retractedIndexRaw = await env.POTISSE_NFC.get("retracted_posts");
  let retractedIndex = { pending: [] };
  if (retractedIndexRaw) {
    try {
      retractedIndex = JSON.parse(retractedIndexRaw);
    } catch {}
  }
  if (!retractedIndex.pending.includes(post_id)) {
    retractedIndex.pending.push(post_id);
  }
  await env.POTISSE_NFC.put("retracted_posts", JSON.stringify(retractedIndex));

  // 10. invalidar cache /api/club/me
  invalidateClubMeCache(customerId);

  // 11. response
  return clubJsonResponse(request, { ok: true }, 200, token);
}
__name(handleClubPostRetract, "handleClubPostRetract");

// â”€â”€ Bloque B parte 2, secciÃ³n 7: aviso a Fran de orden pendiente de programar NFC â”€â”€
async function notifyFranPendingNfc(env, order) {
  const orderId = order.id;
  const customerId = order.customer?.id;
  const orderName = order.name || `#${order.order_number || orderId}`;
  const totalItems = (order.line_items || []).reduce((s, li) => s + (li.quantity || 1), 0);
  const productSummary = (order.line_items || [])
    .map((li) => `${li.quantity}Ã— ${li.name || li.title || li.sku}`)
    .join(", ");

  const body = {
    from: "club@potisse.com",
    to: "backend@potisse.com",
    subject: `Pending NFC â€” order ${orderName}`,
    text: `New order awaiting NFC programming.\n\n` +
          `Order: ${orderName} (${orderId})\n` +
          `Customer ID: ${customerId}\n` +
          `Items: ${totalItems} â€” ${productSummary}\n\n` +
          `Program the card and register the client in Workshop Tools when ready.\n\n` +
          `â€” POTISSE system`
  };

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const err = await res.text();
    console.error(`Resend notifyFranPendingNfc failed: ${res.status} ${err}`);
    return false;
  }
  return true;
}
__name(notifyFranPendingNfc, "notifyFranPendingNfc");

// â”€â”€ Bloque B parte 2, secciÃ³n 3: POST /api/admin/nfc-card â”€â”€
function isValidNfcUidHex(uid) {
  return typeof uid === "string" && /^[0-9A-Fa-f]{14}$/.test(uid);
}
__name(isValidNfcUidHex, "isValidNfcUidHex");

// ── C.3 NFC Cards Push A ──
async function handleAdminNfcCardsList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const statusFilter = url.searchParams.get("status") || "all";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 250);
  const cursor = url.searchParams.get("cursor") || null;

  try {
    // List all uid_* keys from KV
    const listResult = await env.POTISSE_NFC.list({ prefix: "uid_", limit: 1000, cursor });
    const cards = [];

    for (const key of listResult.keys || []) {
      if (!key.name.startsWith("uid_")) continue;
      // Skip tap_history keys
      if (key.name.includes("_tap_history")) continue;

      const uid = key.name.replace("uid_", "");
      const raw = await env.POTISSE_NFC.get(key.name);
      if (!raw) continue;

      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        continue;
      }

      // Infer status
      let status = "unassigned";
      if (data.customer_id) {
        status = "assigned";
        // Check if lost flag exists
        if (data.lost === true) status = "lost";
        // Check if disabled
        if (data.disabled === true) status = "disabled";
      }

      // Apply status filter
      if (statusFilter !== "all" && status !== statusFilter) continue;

      // Get tap history count
      let tapsCount = 0;
      let lastTapAt = null;
      const tapHistoryRaw = await env.POTISSE_NFC.get(`uid_${uid}_tap_history`);
      if (tapHistoryRaw) {
        try {
          const tapData = JSON.parse(tapHistoryRaw);
          tapsCount = tapData.history?.length || 0;
          if (tapData.history?.length > 0) {
            lastTapAt = tapData.history[tapData.history.length - 1].timestamp || null;
          }
        } catch {}
      }

      // Get customer name from uid record or profile
      let customerName = data.name || null;
      if (data.customer_id && !customerName) {
        const profileRaw = await env.POTISSE_NFC.get(`customer_${data.customer_id}_profile`);
        if (profileRaw) {
          try {
            const profile = JSON.parse(profileRaw);
            customerName = profile.first_name + " " + profile.last_name;
          } catch {}
        }
      }

      cards.push({
        uid,
        status,
        customer_id: data.customer_id || null,
        customer_name: customerName,
        key_version: data.key_version || null,
        taps_count: tapsCount,
        last_tap_at: lastTapAt,
        created_at: data.registered_at || null
      });
    }

    return jsonResponse({
      ok: true,
      cards,
      count: cards.length,
      next_cursor: listResult.list_complete ? null : listResult.cursor
    });
  } catch (err) {
    console.error("[nfc-cards/list] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminNfcCardsList, "handleAdminNfcCardsList");

async function handleAdminNfcCardGet(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const match = url.pathname.match(/^\/api\/admin\/nfc-cards\/([0-9A-Fa-f]{14})$/);
  const uid = match ? match[1] : null;
  if (!uid) {
    return jsonResponse({ error: "invalid_uid_format" }, 400);
  }

  try {
    const raw = await env.POTISSE_NFC.get(`uid_${uid}`);
    if (!raw) {
      return jsonResponse({ error: "card_not_found" }, 404);
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return jsonResponse({ error: "corrupted_data" }, 500);
    }

    // Infer status
    let status = "unassigned";
    if (data.customer_id) {
      status = "assigned";
      if (data.lost === true) status = "lost";
      if (data.disabled === true) status = "disabled";
    }

    // Get customer PII
    let customer = null;
    if (data.customer_id) {
      const profileRaw = await env.POTISSE_NFC.get(`customer_${data.customer_id}_profile`);
      if (profileRaw) {
        try {
          const profile = JSON.parse(profileRaw);
          customer = {
            first_name: profile.first_name || null,
            last_name: profile.last_name || null,
            email: profile.email || null
          };
        } catch {}
      }
    }

    // Get tap history
    let tapHistory = [];
    const tapHistoryRaw = await env.POTISSE_NFC.get(`uid_${uid}_tap_history`);
    if (tapHistoryRaw) {
      try {
        const tapData = JSON.parse(tapHistoryRaw);
        tapHistory = (tapData.history || []).slice(-20).reverse(); // Last 20, newest first
      } catch {}
    }

    const card = {
      uid,
      status,
      customer_id: data.customer_id || null,
      order: data.order || null,
      email: data.email || null,
      name: data.name || null,
      registered_at: data.registered_at || null,
      key_version: data.key_version || null,
      lost: data.lost || false,
      disabled: data.disabled || false,
      lost_reason: data.lost_reason || null
    };

    return jsonResponse({ ok: true, card, customer, tap_history: tapHistory });
  } catch (err) {
    console.error(`[nfc-card/get] error: ${err.message}`);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminNfcCardGet, "handleAdminNfcCardGet");

async function handleAdminNfcCardAssign(request, env, url, ctx) {
  const match = url.pathname.match(/^\/api\/admin\/nfc-cards\/([0-9A-Fa-f]{14})\/assign$/);
  const uid = match ? match[1] : null;
  if (!uid) {
    return jsonResponse({ error: "invalid_uid_format" }, 400);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const { customer_id } = body || {};
  if (!customer_id || typeof customer_id !== "number") {
    return jsonResponse({ error: "missing_or_invalid_customer_id" }, 400);
  }

  try {
    // Read card
    const raw = await env.POTISSE_NFC.get(`uid_${uid}`);
    if (!raw) {
      return jsonResponse({ error: "card_not_found" }, 404);
    }
    const data = JSON.parse(raw);

    // Check if already assigned to another customer
    if (data.customer_id && data.customer_id !== customer_id) {
      return jsonResponse({
        error: "already_assigned",
        message: `Card is already assigned to customer ${data.customer_id}. Unassign first.`
      }, 400);
    }

    // Verify customer exists
    const profileRaw = await env.POTISSE_NFC.get(`customer_${customer_id}_profile`);
    if (!profileRaw) {
      return jsonResponse({ error: "customer_not_found" }, 404);
    }
    const profile = JSON.parse(profileRaw);

    // Update card
    data.customer_id = customer_id;
    data.name = profile.first_name + " " + profile.last_name;
    data.email = profile.email;
    await env.POTISSE_NFC.put(`uid_${uid}`, JSON.stringify(data));

    // Update customer profile with card reference (backfill lazy)
    if (!profile.cards_owned) profile.cards_owned = [];
    if (!profile.cards_owned.includes(uid)) {
      profile.cards_owned.push(uid);
      await env.POTISSE_NFC.put(`customer_${customer_id}_profile`, JSON.stringify(profile));
    }

    // Timeline event
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil((async () => {
        try {
          await logTimelineEvent(env, {
            severity: "info",
            category: "nfc_cards",
            message: `Card ${uid} assigned to customer ${customer_id}`,
            customer_id,
            uid
          });
        } catch (e) {
          console.error("[nfc-card/assign] timeline error:", e.message);
        }
      })());
    }

    return jsonResponse({ ok: true, uid, customer_id, action: "assigned" });
  } catch (err) {
    console.error(`[nfc-card/assign] error: ${err.message}`);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminNfcCardAssign, "handleAdminNfcCardAssign");

async function handleAdminNfcCardUnassign(request, env, url, ctx) {
  const match = url.pathname.match(/^\/api\/admin\/nfc-cards\/([0-9A-Fa-f]{14})\/unassign$/);
  const uid = match ? match[1] : null;
  if (!uid) {
    return jsonResponse({ error: "invalid_uid_format" }, 400);
  }

  try {
    const raw = await env.POTISSE_NFC.get(`uid_${uid}`);
    if (!raw) {
      return jsonResponse({ error: "card_not_found" }, 404);
    }
    const data = JSON.parse(raw);

    const prevCustomerId = data.customer_id;
    if (!prevCustomerId) {
      return jsonResponse({ error: "not_assigned" }, 400);
    }

    // Remove reference from customer profile
    const profileRaw = await env.POTISSE_NFC.get(`customer_${prevCustomerId}_profile`);
    if (profileRaw) {
      try {
        const profile = JSON.parse(profileRaw);
        if (profile.cards_owned) {
          profile.cards_owned = profile.cards_owned.filter(id => id !== uid);
          await env.POTISSE_NFC.put(`customer_${prevCustomerId}_profile`, JSON.stringify(profile));
        }
      } catch {}
    }

    // Update card
    data.customer_id = null;
    data.name = null;
    data.email = null;
    await env.POTISSE_NFC.put(`uid_${uid}`, JSON.stringify(data));

    // Timeline event
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil((async () => {
        try {
          await logTimelineEvent(env, {
            severity: "info",
            category: "nfc_cards",
            message: `Card ${uid} unassigned from customer ${prevCustomerId}`,
            customer_id: prevCustomerId,
            uid
          });
        } catch (e) {
          console.error("[nfc-card/unassign] timeline error:", e.message);
        }
      })());
    }

    return jsonResponse({ ok: true, uid, prev_customer_id: prevCustomerId, action: "unassigned" });
  } catch (err) {
    console.error(`[nfc-card/unassign] error: ${err.message}`);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminNfcCardUnassign, "handleAdminNfcCardUnassign");

async function handleAdminNfcCardMarkLost(request, env, url, ctx) {
  const match = url.pathname.match(/^\/api\/admin\/nfc-cards\/([0-9A-Fa-f]{14})\/mark-lost$/);
  const uid = match ? match[1] : null;
  if (!uid) {
    return jsonResponse({ error: "invalid_uid_format" }, 400);
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    // body can be empty
  }
  const reason = body.reason || "";

  try {
    const raw = await env.POTISSE_NFC.get(`uid_${uid}`);
    if (!raw) {
      return jsonResponse({ error: "card_not_found" }, 404);
    }
    const data = JSON.parse(raw);

    data.lost = true;
    data.lost_reason = reason;
    data.lost_at = new Date().toISOString();
    await env.POTISSE_NFC.put(`uid_${uid}`, JSON.stringify(data));

    // Timeline event
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil((async () => {
        try {
          await logTimelineEvent(env, {
            severity: "warning",
            category: "nfc_cards",
            message: `Card marked as lost. Reason: ${reason || "not specified"}`,
            uid,
            customer_id: data.customer_id || null
          });
        } catch (e) {
          console.error("[nfc-card/mark-lost] timeline error:", e.message);
        }
      })());
    }

    return jsonResponse({ ok: true, uid, status: "lost", reason });
  } catch (err) {
    console.error(`[nfc-card/mark-lost] error: ${err.message}`);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminNfcCardMarkLost, "handleAdminNfcCardMarkLost");

async function handleAdminNfcCard(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const { uid, order_id, customer_id, email, first_name, last_name, phone, address, notes } = body || {};

  const requiredChecks = [
    ["uid", uid],
    ["order_id", order_id],
    ["customer_id", customer_id],
    ["email", email],
    ["first_name", first_name],
    ["last_name", last_name]
  ];
  for (const [field, value] of requiredChecks) {
    if (value === undefined || value === null || value === "") {
      return new Response(JSON.stringify({ error: "missing_field", missing_field: field }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
  }

  if (typeof order_id !== "number" || order_id <= 0) {
    return new Response(JSON.stringify({ error: "invalid_order_id" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  if (typeof customer_id !== "number" || customer_id <= 0) {
    return new Response(JSON.stringify({ error: "invalid_customer_id" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  if (!isValidNfcUidHex(uid)) {
    return new Response(JSON.stringify({ error: "invalid_uid_format" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const orderIndexKey = `order_${order_id}_pieces_index`;
  const orderIndexRaw = await env.POTISSE_NFC.get(orderIndexKey);
  if (!orderIndexRaw) {
    return new Response(JSON.stringify({ error: "order_not_found_in_worker", hint: "webhook may not have arrived yet" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  const orderIndex = JSON.parse(orderIndexRaw);

  const nowIso = new Date().toISOString();

  try {
    await env.POTISSE_NFC.put(`uid_${uid}`, JSON.stringify({
      email,
      name: `${first_name} ${last_name}`,
      order: order_id,
      customer_id,
      registered_at: nowIso
    }));
  } catch (err) {
    console.error(`admin/nfc-card: uid_ put failed: ${err.message}`);
    return new Response(JSON.stringify({ error: "kv_write_failed", step: "uid" }), { status: 500, headers: { "Content-Type": "application/json" } });
  }

  try {
    await env.POTISSE_NFC.put(`customer_${customer_id}_profile`, JSON.stringify({
      customer_id,
      email,
      first_name,
      last_name,
      phone: phone || null,
      address: address || null,
      notes: notes || null,
      registered_at: nowIso
    }));
  } catch (err) {
    console.error(`admin/nfc-card: customer_profile put failed: ${err.message}`);
    return new Response(JSON.stringify({ error: "kv_write_failed", step: "customer_profile" }), { status: 500, headers: { "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({
    ok: true,
    uid,
    order_id,
    customer_id,
    pieces_linked: orderIndex.piece_ids.length
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminNfcCard, "handleAdminNfcCard");

// â”€â”€ Bloque B parte 3A, secciÃ³n 1.1: GET /api/admin/emergency-session â”€â”€
// Backdoor de acceso Club para Fran, sin depender de un tap NFC fÃ­sico.
// v6.7: hotfix seguridad â€” este endpoint emitÃ­a sesiones sin comprobar
// ADMIN_KEY (agujero preexistente, no regresiÃ³n de este push). Cualquiera
// con un customer_id numÃ©rico podÃ­a generar una sesiÃ³n de Club vÃ¡lida.
async function handleAdminEmergencySession(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const customerIdParam = url.searchParams.get("customer_id");
  const customerId = Number(customerIdParam);
  if (!customerIdParam || !Number.isFinite(customerId) || customerId <= 0) {
    return new Response(JSON.stringify({ error: "invalid_customer_id" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
  }
  const profile = JSON.parse(profileRaw);

  const sessionToken = crypto.randomUUID();
  const sessionObj = {
    token: sessionToken,
    customer_id: customerId,
    email: profile.email || "",
    uid: "ADMIN_BACKDOOR",
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 1800 * 1000).toISOString()
  };
  await env.POTISSE_NFC.put(`session_${sessionToken}`, JSON.stringify(sessionObj), { expirationTtl: 1800 });

  console.log(`Emergency session for customer ${customerId} issued by admin (${profile.first_name || ""} ${profile.last_name || ""} <${profile.email || ""}>)`);

  return new Response(null, {
    status: 302,
    headers: {
      Location: "https://www.potisse.com/pages/club",
      "Set-Cookie": buildSessionCookieHeader(sessionToken)
    }
  });
}
__name(handleAdminEmergencySession, "handleAdminEmergencySession");

// â”€â”€ Bloque B parte 3B, Fase 4: POST /api/admin/post/curate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const CLUB_POST_CURATE_STATUS_MAP = {
  keep: "kept",
  publish_ig: "published_ig",
  discard: "discarded"
};

const CLUB_POST_REPLY_TEMPLATES = {
  keep: "We kept it. Thank you.",
  publish_ig: (igPostUrl) => `Your moment appeared. Here's where: ${igPostUrl}`,
  discard: null
};

async function handleAdminMagicLink(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const { customer_id } = body || {};
  if (!customer_id) {
    return new Response(JSON.stringify({ error: "missing_customer_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customer_id}_profile`);
  let email = null;
  let firstName = "Customer";
  if (profileRaw) {
    const profile = JSON.parse(profileRaw);
    email = profile.email;
    firstName = profile.first_name || firstName;
  }

  if (!email) {
    const shopifyInfo = await getShopifyCustomerBasic(env, customer_id, null);
    if (shopifyInfo.ok && shopifyInfo.email) {
      email = shopifyInfo.email;
    }
  }

  if (!email) {
    return new Response(JSON.stringify({ error: "customer_email_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }

  const token = generateToken();
  const tokenData = {
    customer_id: Number(customer_id),
    email,
    created: new Date().toISOString(),
    expires: Date.now() + 15 * 60 * 1000,
    used: false
  };
  await env.POTISSE_NFC.put("magic_" + token, JSON.stringify(tokenData), { expirationTtl: 900 });

  const magicUrl = `${url.protocol}//${url.host}/api/validate?token=${token}`;

  let sendResult = { ok: false };
  try {
    sendResult = await sendMagicLinkEmail(env, email, magicUrl);
  } catch (err) {
    console.error(`Magic link email failed: ${err.message}`);
  }

  if (!sendResult.ok) {
    return new Response(JSON.stringify({ sent: false, error: "send_failed", detail: sendResult.error || "unknown" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "admin",
    customer_id: Number(customer_id),
    type: "magic_link_sent",
    title: `Magic link sent to ${email}`,
    metadata: { email }
  });

  return new Response(JSON.stringify({ ok: true, sent: true, email, email_id: sendResult.id }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMagicLink, "handleAdminMagicLink");

async function handleAdminPostCurate(request, env, url) {
  // 1. Auth
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const { post_id, action, ig_post_url, custom_message } = body || {};

  // 2. post existe
  if (!post_id) {
    return new Response(JSON.stringify({ error: "missing_fields" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const postRaw = await env.POTISSE_NFC.get(`post_${post_id}`);
  if (!postRaw) {
    return new Response(JSON.stringify({ error: "post_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  const post = JSON.parse(postRaw);

  // 3. action vÃ¡lida
  if (!Object.prototype.hasOwnProperty.call(CLUB_POST_CURATE_STATUS_MAP, action)) {
    return new Response(JSON.stringify({ error: "invalid_action" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 4. publish_ig requiere ig_post_url vÃ¡lida
  if (action === "publish_ig") {
    if (!ig_post_url || !isValidUrl(ig_post_url)) {
      return new Response(JSON.stringify({ error: "invalid_ig_post_url" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  // 5-9. actualizar post
  post.status = CLUB_POST_CURATE_STATUS_MAP[action];
  post.reviewed_at = new Date().toISOString();
  post.reviewed_by = "admin";

  let replyMessage;
  if (custom_message) {
    replyMessage = custom_message;
  } else if (action === "publish_ig") {
    replyMessage = CLUB_POST_REPLY_TEMPLATES.publish_ig(ig_post_url);
  } else {
    replyMessage = CLUB_POST_REPLY_TEMPLATES[action];
  }
  post.reply_message = replyMessage;

  if (action === "publish_ig") {
    post.ig_post_url = ig_post_url;
  }

  // 10. persistir (11: R2 nunca se toca aquÃ­)
  await env.POTISSE_NFC.put(`post_${post_id}`, JSON.stringify(post));

  // Fase 9.1: sale del Ã­ndice global de pending
  await removeFromPostsPendingAllIndex(env, post_id);

  // 12. invalidar cache del customer dueÃ±o del post
  invalidateClubMeCache(post.customer_id);

  // 13. response
  return new Response(JSON.stringify({
    ok: true,
    post_id,
    new_status: post.status,
    reply_sent: post.reply_message !== null
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminPostCurate, "handleAdminPostCurate");

function isValidUrl(value) {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
__name(isValidUrl, "isValidUrl");

// â”€â”€ Bloque B parte 3B, Fase 9.1: GET /api/admin/posts/pending â”€â”€â”€â”€â”€â”€
async function handleAdminPostsPending(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const indexRaw = await env.POTISSE_NFC.get("posts_pending_all");
  const index = indexRaw ? JSON.parse(indexRaw) : { pending: [] };

  const posts = [];
  for (const postId of index.pending || []) {
    const raw = await env.POTISSE_NFC.get(`post_${postId}`);
    if (!raw) continue;
    let post;
    try {
      post = JSON.parse(raw);
    } catch {
      continue;
    }
    if (post.status !== "pending") continue; // Ã­ndice podrÃ­a estar stale, defensivo

    const profileRaw = await env.POTISSE_NFC.get(`customer_${post.customer_id}_profile`);
    let profile = {};
    if (profileRaw) {
      try {
        profile = JSON.parse(profileRaw);
      } catch {}
    }

    posts.push({
      post_id: post.post_id,
      customer_id: post.customer_id,
      first_name: profile.first_name || null,
      caption: post.caption,
      submitted_at: post.submitted_at,
      r2_key: post.r2_key
    });
  }

  posts.sort((a, b) => new Date(a.submitted_at) - new Date(b.submitted_at));

  return new Response(JSON.stringify({ ok: true, count: posts.length, posts }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminPostsPending, "handleAdminPostsPending");

// â”€â”€ Bloque B parte 3B, Fase 9.1: GET /api/admin/posts/retracted â”€â”€â”€â”€
// NOTA: el encargo original nombra el Ã­ndice "retracted_posts_pending_purge",
// pero el Ã­ndice real creado en Fase 3/6 es "retracted_posts" â€” verificado
// en el propio cÃ³digo (handleClubPostRetract + runPurgeRetracts). Uso el
// nombre real.
async function handleAdminPostsRetracted(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const indexRaw = await env.POTISSE_NFC.get("retracted_posts");
  const index = indexRaw ? JSON.parse(indexRaw) : { pending: [] };

  const posts = [];
  for (const postId of index.pending || []) {
    const raw = await env.POTISSE_NFC.get(`post_${postId}`);
    if (!raw) continue;
    let post;
    try {
      post = JSON.parse(raw);
    } catch {
      continue;
    }
    if (post.status !== "retracted" || !post.retracted_at) continue;

    const hoursSince = (Date.now() - new Date(post.retracted_at).getTime()) / (60 * 60 * 1000);
    if (hoursSince >= 24) continue; // ya deberÃ­a haber sido purgado por el cron

    const profileRaw = await env.POTISSE_NFC.get(`customer_${post.customer_id}_profile`);
    let profile = {};
    if (profileRaw) {
      try {
        profile = JSON.parse(profileRaw);
      } catch {}
    }

    posts.push({
      post_id: post.post_id,
      customer_id: post.customer_id,
      first_name: profile.first_name || null,
      caption: post.caption,
      retracted_at: post.retracted_at,
      hours_since_retract: Math.floor(hoursSince),
      r2_key: post.r2_key
    });
  }

  return new Response(JSON.stringify({ ok: true, count: posts.length, posts }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminPostsRetracted, "handleAdminPostsRetracted");

// â”€â”€ Bloque B parte 3B, Fase 9.1: GET /api/admin/access-alerts â”€â”€â”€â”€â”€â”€
async function handleAdminAccessAlertsGet(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const raw = await env.POTISSE_NFC.get("access_alerts_active");
  const alerts = raw ? JSON.parse(raw) : { iberian: [], european: [], last_run: null, total_count: 0 };

  // Mergear notas en cada alerta
  const mergeNotes = async (list) => {
    const enriched = [];
    for (const a of (list || [])) {
      const noteKey = `alert_notes_${String(a.order_id)}_${String(a.piece_id)}`;
      const notesRaw = await env.POTISSE_NFC.get(noteKey);
      const notes = notesRaw ? JSON.parse(notesRaw) : [];
      const allTags = new Set();
      notes.forEach(n => (n.tags || []).forEach(t => allTags.add(t)));
      enriched.push({
        ...a,
        has_notes: notes.length > 0,
        notes_count: notes.length,
        tags: Array.from(allTags)
      });
    }
    return enriched;
  };

  const [iberian, european] = await Promise.all([
    mergeNotes(alerts.iberian),
    mergeNotes(alerts.european)
  ]);

  return new Response(JSON.stringify({
    ok: true,
    iberian,
    european,
    total_count: alerts.total_count != null
      ? alerts.total_count
      : (alerts.iberian || []).length + (alerts.european || []).length,
    last_run: alerts.last_run || null
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminAccessAlertsGet, "handleAdminAccessAlertsGet");

// ── Bloque B parte 3B, Fase C.4: POST /api/admin/access-alerts/resolve ──
// Backend atómico: issue_detected crea incidencia + elimina alerta
const ACCESS_ALERT_RESOLVE_ACTIONS = ["verbal_confirmation", "issue_detected", "magic_link_sent", "contact_attempted", "note_added"];

async function handleAdminAccessAlertResolve(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const { order_id, piece_id, action, note } = body || {};
  if (!order_id || !piece_id || !action || !ACCESS_ALERT_RESOLVE_ACTIONS.includes(action)) {
    return new Response(JSON.stringify({ error: "invalid_fields" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const alertsRaw = await env.POTISSE_NFC.get("access_alerts_active");
  const alerts = alertsRaw
    ? JSON.parse(alertsRaw)
    : { iberian: [], european: [], last_run: null, total_count: 0 };

  let matchedEntry = null;

  // Buscar la alerta (sin eliminar todavía)
  for (const zone of ["iberian", "european"]) {
    for (const entry of (alerts[zone] || [])) {
      if (String(entry.order_id) === String(order_id) && String(entry.piece_id) === String(piece_id)) {
        matchedEntry = entry;
        break;
      }
    }
    if (matchedEntry) break;
  }

  const customerId = matchedEntry ? matchedEntry.customer_id : null;
  let createdIncidence = null;
  let removed = false;

  // Extraer tags de la nota
  const tags = [];
  if (note) {
    const tagMatches = note.match(/#([\w-]+)/g);
    if (tagMatches) {
      tagMatches.forEach(t => tags.push(t.slice(1)));
    }
  }

  if (action === "issue_detected" && matchedEntry) {
    // ÚNICA acción que elimina la alerta
    const days = matchedEntry.days_since_fulfillment || 0;
    const title = `Piece not activated after ${days} days`;
    const description = note || `Order ${order_id} — piece ${piece_id} fulfilled on ${matchedEntry.fulfillment_date} but never activated. Zone: ${matchedEntry.shipping_zone}.`;
    createdIncidence = await createIncidenceFromAlert(env, matchedEntry, title, description, "access_alert", "medium");

    for (const zone of ["iberian", "european"]) {
      const beforeLen = alerts[zone].length;
      alerts[zone] = alerts[zone].filter(entry => {
        return !(String(entry.order_id) === String(order_id) && String(entry.piece_id) === String(piece_id));
      });
      if (alerts[zone].length < beforeLen) removed = true;
    }
  } else if (action === "note_added") {
    // Guardar nota en KV separada por alerta
    const noteKey = `alert_notes_${String(order_id)}_${String(piece_id)}`;
    const notesRaw = await env.POTISSE_NFC.get(noteKey);
    let notes = [];
    if (notesRaw) { try { notes = JSON.parse(notesRaw); } catch {} }
    notes.unshift({
      timestamp: new Date().toISOString(),
      text: note || "",
      tags,
      admin: "admin"
    });
    if (notes.length > 20) notes = notes.slice(0, 20);
    await env.POTISSE_NFC.put(noteKey, JSON.stringify(notes));
  }

  if (removed) {
    alerts.total_count = alerts.iberian.length + alerts.european.length;
    await env.POTISSE_NFC.put("access_alerts_active", JSON.stringify(alerts));
  }

  // Guardar en log del cliente (siempre, para trazabilidad)
  if (customerId) {
    const logKey = `customer_${customerId}_access_alert_actions`;
    const logRaw = await env.POTISSE_NFC.get(logKey);
    let log = [];
    if (logRaw) { try { log = JSON.parse(logRaw); } catch {} }
    log.unshift({
      action,
      order_id,
      piece_id,
      note: note || null,
      tags: tags.length ? tags : null,
      created_incidence_id: createdIncidence ? createdIncidence.incidence_id : null,
      timestamp: new Date().toISOString()
    });
    if (log.length > 50) log = log.slice(0, 50);
    await env.POTISSE_NFC.put(logKey, JSON.stringify(log));
  }

  return new Response(JSON.stringify({
    ok: true,
    action,
    removed,
    created_incidence: createdIncidence ? {
      incidence_id: createdIncidence.incidence_id,
      title: createdIncidence.title
    } : null
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminAccessAlertResolve, "handleAdminAccessAlertResolve");

// ── Bloque C.4 v3: GET /api/admin/members/:id/access-alert-history ──
async function handleAdminMemberAccessAlertHistory(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const match = url.pathname.match(/^\/api\/admin\/members\/(\d+)\/access-alert-history$/);
  if (!match) {
    return new Response(JSON.stringify({ error: "invalid_path" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = match[1];
  const logKey = `customer_${customerId}_access_alert_actions`;
  const logRaw = await env.POTISSE_NFC.get(logKey);
  let history = [];
  if (logRaw) {
    try { history = JSON.parse(logRaw); } catch {}
  }
  return new Response(JSON.stringify({ ok: true, history }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMemberAccessAlertHistory, "handleAdminMemberAccessAlertHistory");

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Bloque B parte 3B, Fase 9.2 â€” Workshop Tools backend ampliado
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// â”€â”€ 9.2.1: GET /api/admin/posts/image/:post_id (R2 proxy) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleAdminPostsImage(request, env, url, postId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }
  const postRaw = await env.POTISSE_NFC.get(`post_${postId}`);
  if (!postRaw) {
    return new Response("Not found", { status: 404 });
  }
  const post = JSON.parse(postRaw);
  const object = await env.POTISSE_POSTS.get(post.r2_key);
  if (!object) {
    return new Response("Not found", { status: 404 });
  }
  const ext = (post.r2_key.split(".").pop() || "").toLowerCase();
  const contentType = ext === "png" ? "image/png" : "image/jpeg";
  return new Response(object.body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "private, max-age=3600"
    }
  });
}
__name(handleAdminPostsImage, "handleAdminPostsImage");

// â”€â”€ Fase 9.2: log de tap history NFC (uid_<uid>_tap_history) â”€â”€â”€â”€â”€â”€â”€
async function logNfcTapHistory(env, uid, entry) {
  const key = `uid_${uid}_tap_history`;
  const raw = await env.POTISSE_NFC.get(key);
  let data = { history: [] };
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {}
  }
  data.history.push(entry);
  if (data.history.length > 100) {
    data.history = data.history.slice(data.history.length - 100);
  }
  await env.POTISSE_NFC.put(key, JSON.stringify(data));
}
__name(logNfcTapHistory, "logNfcTapHistory");

// â”€â”€ 9.2.2: GET /api/admin/uid-info?uid=X (test tarjeta) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleAdminUidInfo(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const uid = url.searchParams.get("uid");
  if (!uid) {
    return new Response(JSON.stringify({ error: "missing_uid" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const tapHistoryRaw = await env.POTISSE_NFC.get(`uid_${uid}_tap_history`);
  const tapHistory = tapHistoryRaw ? (JSON.parse(tapHistoryRaw).history || []) : [];

  const uidDataRaw = await env.POTISSE_NFC.get(`uid_${uid}`);
  if (!uidDataRaw) {
    return new Response(JSON.stringify({ uid, registered: false, tap_history: tapHistory }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  const uidData = JSON.parse(uidDataRaw);
  const orderId = uidData.order;
  const customerId = uidData.customer_id;

  let firstName;
  if (customerId) {
    const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
    if (profileRaw) {
      try {
        firstName = JSON.parse(profileRaw).first_name;
      } catch {}
    }
  }

  let pieces = [];
  if (orderId) {
    const orderIndexRaw = await env.POTISSE_NFC.get(`order_${orderId}_pieces_index`);
    if (orderIndexRaw) {
      const orderIndex = JSON.parse(orderIndexRaw);
      for (const pid of orderIndex.piece_ids) {
        const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
        if (!pRaw) continue;
        const p = JSON.parse(pRaw);
        pieces.push({
          piece_id: p.piece_id,
          first_tap_at: p.first_tap_at || null,
          origin_date: p.origin_date || null,
          product_name: p.product_name
        });
      }
    }
  }

  // Sin Ã­ndice uidâ†’sesiÃ³n; escaneamos session_ activas (volumen bajo, TTL 30min)
  let lastSession = null;
  const sessionKeys = await listAllKeysWithPrefix(env, "session_");
  for (const key of sessionKeys) {
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    let s;
    try {
      s = JSON.parse(raw);
    } catch {
      continue;
    }
    if (s.uid === uid && (!lastSession || new Date(s.created_at) > new Date(lastSession.created_at))) {
      lastSession = { token: s.token, created_at: s.created_at, expires_at: s.expires_at };
    }
  }

  return new Response(JSON.stringify({
    uid,
    registered: true,
    customer_id: customerId,
    first_name: firstName,
    email: uidData.email,
    order_id: orderId,
    pieces,
    last_session: lastSession,
    tap_history: tapHistory,
    registered_at: uidData.registered_at
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminUidInfo, "handleAdminUidInfo");

// â”€â”€ 9.2.3: POST /api/admin/email-customer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// EMAIL TEMPLATES â€” 15 templates, 2 variantes editoriales (Push 4a Mejora 6)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const EMAIL_TEMPLATES_REGISTRY = {
  size_color: {
    category: "Preventa / InformaciÃ³n",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "A quiet question about your size.",
    title: "About the fit.",
    body: [
      "Hello {first_name},",
      "",
      "We received your question about {product_name}.",
      "",
      "{custom_body}",
      "",
      "Take your time. There is no rush from us."
    ],
    cta: { label: "Reply here", url: null },
    signature: "â€” POTISSE",
    requires: ["first_name", "product_name"]
  },
  product_availability: {
    category: "Preventa / InformaciÃ³n",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "About what you were looking for.",
    title: "On the piece you asked about.",
    body: [
      "Hello {first_name},",
      "",
      "The piece you asked about â€” {product_name} â€” is not always with us. We work in small, permanent batches, and we prefer to make less, well.",
      "",
      "{status_line}",
      "",
      "If you would like us to remember you when it returns, reply to this message and we will hold your name in our list."
    ],
    cta: { label: "View the piece", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "product_name", "status_line"]
  },
  production_timing: {
    category: "Preventa / InformaciÃ³n",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "On the next batch.",
    title: "Slow work takes its time.",
    body: [
      "Hello {first_name},",
      "",
      "Thank you for waiting. {product_name} is being prepared in MarÃ­a de Huerva, and will return to us around {estimated_date}.",
      "",
      "We do not push the makers. Nor the fabric. It arrives when it is ready.",
      "",
      "If anything changes, we will write again."
    ],
    cta: { label: "View the piece", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "product_name", "estimated_date"]
  },
  address_check: {
    category: "Pedido en curso",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "A moment before we send it.",
    title: "Before it leaves.",
    body: [
      "Hello {first_name},",
      "",
      "Before we prepare your order for shipping, we would like to confirm your address:",
      "",
      "{shipping_address_block}",
      "",
      "If everything is correct, no reply is needed. We will proceed within the day.",
      "",
      "If anything should change, reply to this message and we will hold the order until you tell us."
    ],
    cta: { label: "View your order", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "shipping_address_block"]
  },
  nfc_quantity: {
    category: "Pedido en curso",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "A note on your order.",
    title: "On what will arrive with you.",
    body: [
      "Hello {first_name},",
      "",
      "Your order includes {pieces_count} {pieces_word}. Each one will arrive with its own card â€” small, discreet, holding its own history.",
      "",
      "If this does not match what you expected, reply to this message before {cutoff_date} and we will pause the order."
    ],
    cta: { label: "View your order", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "pieces_count", "pieces_word", "cutoff_date"]
  },
  delivery_availability_check: {
    category: "Pedido en curso",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "Just to be sure it arrives well.",
    title: "On your delivery.",
    body: [
      "Hello {first_name},",
      "",
      "Your piece will be with GLS in the coming days, arriving to:",
      "",
      "{shipping_address_short}",
      "",
      "Will you be there in the next five days to receive it? If not, or if you prefer we hold it until you return, reply to this message and we will pause.",
      "",
      "Otherwise, no reply is needed â€” we will proceed."
    ],
    cta: { label: "Reply here", url: null },
    signature: "â€” POTISSE",
    requires: ["first_name", "shipping_address_short"]
  },
  delivery_confirmation: {
    category: "Entrega",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "Did it arrive well?",
    title: "A quiet check.",
    body: [
      "Hello {first_name},",
      "",
      "We saw that your piece was marked as delivered on {delivered_date}. We wanted to make sure it reached you â€” not just the door.",
      "",
      "If it did, no reply is needed.",
      "",
      "If something is not as it should be â€” the packaging, the piece, anything â€” reply to this message. We will listen without hurry."
    ],
    cta: { label: "Reply if needed", url: null },
    signature: "â€” POTISSE",
    requires: ["first_name", "delivered_date"]
  },
  delivery_delayed: {
    category: "Entrega",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "A small delay on the way.",
    title: "On the wait.",
    body: [
      "Hello {first_name},",
      "",
      "GLS has reported a delay on your shipment. It has not been lost â€” only paused somewhere between us and you.",
      "",
      "{reason_line}",
      "",
      "We will keep watching, and will write again once it moves. If you prefer to hold or change anything, reply to this message.",
      "",
      "Thank you for your patience. It is not a light word for us."
    ],
    cta: { label: "Follow its journey", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "reason_line"]
  },
  defect_apology: {
    category: "Incidencias",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "We noticed something on your piece.",
    title: "Before it leaves us.",
    body: [
      "Hello {first_name},",
      "",
      "During inspection, we found a detail on your {product_name} that does not meet what we expect from a POTISSE piece: {defect_description}.",
      "",
      "We would rather tell you now than hope you would not notice.",
      "",
      "Your options:",
      "",
      "â€” Wait for a replacement from the next batch. Estimated arrival: {estimated_date}.",
      "â€” Refund in full, no return needed.",
      "",
      "Reply to this message and let us know how you would like to proceed. There is no wrong choice."
    ],
    cta: { label: "Reply here", url: null },
    signature: "â€” POTISSE",
    requires: ["first_name", "product_name", "defect_description", "estimated_date"]
  },
  return_confirmation: {
    category: "Incidencias",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "Your return has arrived.",
    title: "We have received it.",
    body: [
      "Hello {first_name},",
      "",
      "Your {product_name} arrived back with us on {return_date}. We will inspect it in the coming days and process the refund of {refund_amount} to your original method of payment.",
      "",
      "You should see it in your account within {refund_days_estimate}, depending on your bank.",
      "",
      "If you would like the piece to return to you in a different size, reply to this message and we will arrange it."
    ],
    cta: { label: "View return details", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: ["first_name", "product_name", "return_date", "refund_amount", "refund_days_estimate"]
  },
  first_wear_check: {
    category: "Post-venta emocional",
    variant: "B",
    reply_to: "hola@potisse.com",
    subject: "A quiet check-in.",
    body: [
      "â”€â”€â”€â”€â”€",
      "",
      "LOCATION: 50430 Â· STATUS: {days_since_delivery} days with you.",
      "",
      "A piece takes time to become yours.",
      "The first days are still ceremony.",
      "",
      "How does it wear?",
      "",
      "If it has already found its place in your rhythm, no reply is needed.",
      "If not â€” reply. We will listen."
    ],
    signature: "â€” POTISSE",
    requires: ["days_since_delivery"]
  },
  wash_reminder: {
    category: "Post-venta emocional",
    variant: "B",
    reply_to: "hola@potisse.com",
    subject: "A gentle reminder.",
    body: [
      "â”€â”€â”€â”€â”€",
      "",
      "LOCATION: 50430 Â· STATUS: {washes} washes registered.",
      "",
      "Your piece is settling.",
      "",
      "If you have washed it recently and forgotten to register it, the door is open â€” no rush.",
      "",
      "Each wash is part of how it becomes yours.",
      "",
      "https://potisse.com/pages/side-b"
    ],
    signature: "â€” POTISSE",
    requires: ["washes"]
  },
  silencio_1_courtesy: {
    category: "Silencios",
    variant: "B",
    reply_to: "50430@potisse.com",
    subject: "A quiet gesture.",
    body: [
      "â”€â”€â”€â”€â”€",
      "",
      "LOCATION: 50430 Â· STATUS: Courtesy shipping, activated.",
      "",
      "From today, your orders arrive with us covering the transit.",
      "",
      "It is a quiet gesture. Nothing to announce, nothing to reciprocate.",
      "",
      "Just a way of saying: we notice you."
    ],
    signature: "â€” POTISSE",
    requires: []
  },
  silencio_3_response: {
    category: "Silencios",
    variant: "B",
    reply_to: "50430@potisse.com",
    subject: "On your piece.",
    body: [
      "â”€â”€â”€â”€â”€",
      "",
      "LOCATION: 50430 Â· STATUS: Silencio 3, received.",
      "",
      "We received your message about {incident_summary}.",
      "",
      "It is not necessary to return the affected piece.",
      "",
      "We will resolve this from our side, quietly.",
      "",
      "If you wish to write again, the door remains ajar."
    ],
    signature: "â€” POTISSE",
    dual_signature: "â€” POT Â· Fran",
    requires: ["incident_summary"]
  },
  custom: {
    category: "GenÃ©rico",
    variant: "A",
    reply_to: "hola@potisse.com",
    subject: "{custom_subject}",
    title: "{custom_title}",
    body: ["{custom_body}"],
    cta: { label: "{cta_label}", url: "{cta_url}" },
    signature: "â€” POTISSE",
    requires: []
  }
};

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
__name(escapeHtml, "escapeHtml");

function interpolateVars(templateStr, vars) {
  return templateStr.replace(/\{(\w+)\}/g, (m, key) => {
    return vars[key] !== undefined ? vars[key] : m;
  });
}
__name(interpolateVars, "interpolateVars");

function nl2br(str) {
  return str.replace(/\n/g, "<br>");
}
__name(nl2br, "nl2br");

function buildTextBody(lines, signature, dualSig) {
  const body = lines.join("\n");
  let sig = signature;
  if (dualSig) sig = dualSig + "\n" + signature;
  return body + "\n\n" + sig;
}
__name(buildTextBody, "buildTextBody");

function renderVariantA(subject, title, bodyLines, cta, signature, logoUrl) {
  const greeting = bodyLines[0] || "";
  const restLines = bodyLines.slice(1);
  const bodyHtml = restLines.map((line) => {
    if (!line.trim()) return '<p style="margin: 0 0 8px 0; line-height: 1.6;">&nbsp;</p>';
    return `<p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 300; color: #3A322E; opacity: 0.85; line-height: 1.6;">${escapeHtml(line)}</p>`;
  }).join("\n");

  const ctaHtml = cta && cta.label && cta.url
    ? `<div style="margin-top: 32px; text-align: center;">
        <a href="${escapeHtml(cta.url)}" style="display: inline-block; height: 32px; line-height: 32px; padding: 0 32px; background-color: #3A322E; color: #F2F1ED !important; text-decoration: none; font-size: 11px; font-weight: 400; letter-spacing: 0.1em; text-transform: uppercase;">${escapeHtml(cta.label)}</a>
      </div>`
    : "";

  const year = new Date().getFullYear();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(subject)}</title>
  <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
</head>
<body style="margin: 0 !important; padding: 0 !important; width: 100% !important; font-family: 'IBM Plex Sans Condensed', 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F2F1ED; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%;">
  <div style="width: 100%; background-color: #F2F1ED; padding: 40px 0;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
      <tr>
        <td align="center">
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="max-width: 480px; margin: 0 auto; background-color: #F2F1ED;">
            <tr>
              <td style="padding: 0 45px;">
                <div style="padding-bottom: 50px;">
                  ${logoUrl ? `<a href="https://potisse.com"><img src="${escapeHtml(logoUrl)}" alt="POTISSE" style="height: 15px; width: auto; display: block; border: 0; outline: none; text-decoration: none;"></a>` : `<a href="https://potisse.com" style="font-family: 'IBM Plex Sans Condensed', 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; letter-spacing: 0.18em; color: #3A322E; text-decoration: none; text-transform: uppercase;">POTISSE</a>`}
                </div>
                <div style="border-left: 1px solid rgba(58, 50, 46, 0.15); padding-left: 20px; margin-bottom: 35px;">
                  <p style="font-size: 13px; font-weight: 300; letter-spacing: 0.02em; color: #3A322E; opacity: 0.55; margin: 0 0 8px 0;">${escapeHtml(greeting)}</p>
                  <h1 style="font-size: 20px; font-weight: 400; letter-spacing: 0.01em; color: #3A322E; line-height: 1.3; margin: 0 0 14px 0;">${escapeHtml(title)}</h1>
                </div>
                <div style="padding-left: 21px;">
                  ${bodyHtml}
                  ${ctaHtml}
                </div>
                <div style="margin-top: 55px; padding-top: 28px; border-top: 1px solid rgba(58, 50, 46, 0.08);">
                  <p style="font-size: 11px; letter-spacing: 0.12em; color: #3A322E; opacity: 0.4; margin: 0 0 20px 0;">Silencio, Calma</p>
                  <p style="font-size: 13px; color: #3A322E; opacity: 0.7; margin: 0;">We're here â€” <a href="mailto:hola@potisse.com" style="color: #3A322E; text-decoration: none;">hola@potisse.com</a></p>
                  <p style="font-size: 11px; color: #3A322E; opacity: 0.35; margin: 16px 0 0 0;">${escapeHtml(signature)} Â· ${year}</p>
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>`;
}
__name(renderVariantA, "renderVariantA");

function renderVariantB(bodyLines, signature, dualSig, year) {
  const poemBody = bodyLines.join("\n");
  const sigBlock = dualSig
    ? `${dualSig}\n${signature} ${year}`
    : `${signature} ${year}`;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Potisse</title>
</head>
<body style="background-color:#F2F1ED;color:#3A322E;padding:48px 24px;margin:0;font-family:'SF Mono','Menlo','Monaco','Consolas','Courier New',monospace;font-size:14px;line-height:1.7;">
  <div style="max-width:560px;margin:0 auto;">
    <p style="margin:0 0 24px 0;">â”€â”€â”€â”€â”€</p>
    <p style="margin:0 0 32px 0;white-space:pre-wrap;">${escapeHtml(poemBody).replace(/\n/g, "<br>")}</p>
    <p style="margin:0 0 32px 0;white-space:pre-wrap;">${escapeHtml(sigBlock).replace(/\n/g, "<br>")}</p>
  </div>
</body>
</html>`;
}
__name(renderVariantB, "renderVariantB");

function buildEmailPayload(templateId, vars) {
  const def = EMAIL_TEMPLATES_REGISTRY[templateId];
  if (!def) return null;

  const interpolatedVars = {};
  for (const key of Object.keys(vars)) {
    interpolatedVars[key] = vars[key];
  }
  // Defaults
  if (interpolatedVars.year == null) interpolatedVars.year = new Date().getFullYear();
  if (interpolatedVars.first_name == null) interpolatedVars.first_name = "Customer";

  const subject = interpolatedVars.custom_subject || interpolateVars(def.subject, interpolatedVars);
  const title = interpolatedVars.custom_title || (def.title ? interpolateVars(def.title, interpolatedVars) : "");
  let bodyLines;
  if (interpolatedVars.custom_body) {
    bodyLines = interpolatedVars.custom_body.split('\n');
  } else {
    bodyLines = def.body.map((line) => interpolateVars(line, interpolatedVars));
  }
  const cta = def.cta ? {
    label: interpolateVars(def.cta.label, interpolatedVars),
    url: def.cta.url ? interpolateVars(def.cta.url, interpolatedVars) : null
  } : null;

  let html, text;
  if (def.variant === "B") {
    html = renderVariantB(bodyLines, def.signature, def.dual_signature && vars.use_dual_signature ? def.dual_signature : null, interpolatedVars.year);
    text = buildTextBody(bodyLines, def.signature, def.dual_signature && vars.use_dual_signature ? def.dual_signature : null);
  } else {
    const logoUrl = vars.editorial_style === true ? (vars.logo_url || null) : null;
    html = renderVariantA(subject, title, bodyLines, cta, def.signature, logoUrl);
    text = buildTextBody(bodyLines, def.signature, null);
  }

  return {
    subject,
    html,
    text,
    reply_to: def.reply_to || "hola@potisse.com"
  };
}
__name(buildEmailPayload, "buildEmailPayload");

// Backward compatibility: los 3 templates antiguos como funciones directas
const EMAIL_CUSTOMER_TEMPLATES = {
  address_check: (detail) => `*We're preparing your order and wanted to confirm the address you gave us. Could you check ${detail || "it"}? Thank you.*`,
  nfc_quantity: () => `*Before we send your piece, one small question about the number of NFC cards. Reply when you can.*`,
  size_color: (detail) => `*Quick question about your order â€” ${detail || "a detail"}. Reply when you can.*`
};

async function handleAdminEmailCustomer(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const {
    customer_id,
    order_id,
    template_id,
    custom_message,
    custom_subject,
    custom_title,
    custom_body,
    subject: legacySubject,
    detail,
    cta_url,
    cta_label,
    use_dual_signature,
    ...templateVars
  } = body || {};

  if (!customer_id) {
    return new Response(JSON.stringify({ error: "missing_customer_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customer_id}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  const profile = JSON.parse(profileRaw);
  if (!profile.email) {
    return new Response(JSON.stringify({ error: "customer_email_missing" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  let finalSubject;
  let finalHtml = null;
  let finalText;
  let replyTo = "hola@potisse.com";

  // â”€â”€ Nuevo sistema de templates (15 templates) â”€â”€
  if (template_id && EMAIL_TEMPLATES_REGISTRY[template_id]) {
    const vars = {
      first_name: profile.first_name || "Customer",
      ...templateVars
    };
    // Legacy custom_message mapea a custom_body si aplica
    if (custom_body) {
      vars.custom_body = custom_body;
    }
    if (custom_message && template_id === "custom") {
      vars.custom_body = custom_message;
    }
    if (custom_subject) vars.custom_subject = custom_subject;
    if (custom_title) vars.custom_title = custom_title;
    if (custom_body) vars.custom_body = custom_body;
    if (cta_url) vars.cta_url = cta_url;
    if (cta_label) vars.cta_label = cta_label;
    if (use_dual_signature != null) vars.use_dual_signature = use_dual_signature;

    const payload = buildEmailPayload(template_id, vars);
    if (!payload) {
      return new Response(JSON.stringify({ error: "template_render_failed" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
    finalSubject = payload.subject;
    finalHtml = payload.html;
    finalText = payload.text;
    replyTo = payload.reply_to;
  }
  // â”€â”€ Backward compatibility: 3 templates antiguos â”€â”€
  else if (template_id && EMAIL_CUSTOMER_TEMPLATES[template_id]) {
    const tpl = EMAIL_CUSTOMER_TEMPLATES[template_id];
    finalText = tpl(detail);
    finalSubject = legacySubject || "A quick question from POTISSE";
  }
  // â”€â”€ Fallback total: custom libre sin template â”€â”€
  else {
    if (!custom_message) {
      return new Response(JSON.stringify({ error: "missing_custom_message" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    finalText = custom_message;
    finalSubject = legacySubject || "A note from POTISSE";
  }

  let sendOk = true;
  try {
    const resendBody = {
      from: replyTo === "50430@potisse.com" ? "POTISSE 50430 <50430@potisse.com>" : "POTISSE <hola@potisse.com>",
      to: profile.email,
      subject: finalSubject,
      text: finalText
    };
    if (replyTo) resendBody.reply_to = replyTo;
    if (finalHtml) {
      resendBody.html = finalHtml;
    }
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(resendBody)
    });
    if (!res.ok) {
      sendOk = false;
      const errText = await res.text();
      console.error(`email-customer Resend failed: ${res.status} ${errText}`);
    }
  } catch (err) {
    sendOk = false;
    console.error(`email-customer Resend threw: ${err.message}`);
  }

  const sentAt = new Date().toISOString();
  const logKey = `customer_${customer_id}_email_history`;
  const logRaw = await env.POTISSE_NFC.get(logKey);
  let log = [];
  if (logRaw) {
    try {
      log = JSON.parse(logRaw);
    } catch {}
  }
  const logEntryId = crypto.randomUUID();
  log.push({
    id: logEntryId,
    timestamp: sentAt,
    subject: finalSubject,
    template_id: template_id || "custom",
    body_preview: finalText.slice(0, 100),
    order_id: order_id || null,
    sent_at: sendOk ? sentAt : null
  });
  await env.POTISSE_NFC.put(logKey, JSON.stringify(log));

  if (!sendOk) {
    return new Response(JSON.stringify({ ok: false, error: "send_failed", log_entry_id: logEntryId }), {
      status: 502,
      headers: { "Content-Type": "application/json" }
    });
  }

  return new Response(JSON.stringify({ ok: true, log_entry_id: logEntryId, sent_at: sentAt }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminEmailCustomer, "handleAdminEmailCustomer");

// â”€â”€ 9.2.4/9.2.5/9.2.6: Members profile (list / detail / edit) â”€â”€â”€â”€â”€â”€
async function listAllCustomerProfiles(env) {
  const keys = await listAllKeysWithPrefix(env, "customer_");
  const profileKeys = keys.filter((k) => k.name.endsWith("_profile"));
  const profiles = [];
  for (const key of profileKeys) {
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    try {
      const profile = JSON.parse(raw);
      // Fallback defensivo: si el perfil no trae customer_id embebido, lo
      // derivamos de la propia key (customer_<id>_profile).
      if (profile.customer_id == null) {
        const match = key.name.match(/^customer_(.+)_profile$/);
        if (match) profile.customer_id = Number(match[1]);
      }
      profiles.push(profile);
    } catch {}
  }
  return profiles;
}
__name(listAllCustomerProfiles, "listAllCustomerProfiles");

async function handleAdminCustomersList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const search = (url.searchParams.get("search") || "").toLowerCase().trim();

  const profiles = await listAllCustomerProfiles(env);
  const alertsRaw = await env.POTISSE_NFC.get("access_alerts_active");
  const alerts = alertsRaw ? JSON.parse(alertsRaw) : { iberian: [], european: [] };

  const customers = [];
  for (const profile of profiles) {
    const customerId = profile.customer_id;
    if (search) {
      const haystack = `${profile.first_name || ""} ${profile.last_name || ""} ${profile.email || ""} ${customerId}`.toLowerCase();
      if (!haystack.includes(search)) continue;
    }

    const piecesIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
    const piecesCount = piecesIndexRaw ? (JSON.parse(piecesIndexRaw).piece_ids || []).length : 0;

    const retractRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
    const retractCount = retractRaw ? (JSON.parse(retractRaw).total || 0) : 0;

    const hasAccessAlert = ["iberian", "european"].some((zone) =>
      (alerts[zone] || []).some((e) => e.customer_id === customerId));

    // Fase 9.2, CorrecciÃ³n 2: tags cacheadas 24h (evita N+1 real por fila,
    // ver hallazgo del testing anterior â€” 19s con 8 customers sin cache)
    const tags = await getCachedShopifyTags(env, customerId, profile.email);

    customers.push({
      customer_id: customerId,
      first_name: profile.first_name,
      last_name: profile.last_name,
      email: profile.email,
      phone: profile.phone,
      address_city: profile.address || null,
      registered_at: profile.registered_at,
      tags,
      pieces_count: piecesCount,
      retract_count: retractCount,
      has_access_alert: hasAccessAlert,
      excessive_retract_flagged: !!profile.excessive_retract_flagged_at
    });
  }

  return new Response(JSON.stringify({ ok: true, count: customers.length, customers }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminCustomersList, "handleAdminCustomersList");

async function handleAdminCustomerDetail(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  const profile = JSON.parse(profileRaw);

  const piecesIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
  const pieceIds = piecesIndexRaw ? (JSON.parse(piecesIndexRaw).piece_ids || []) : [];
  const pieces = [];
  for (const pid of pieceIds) {
    const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
    if (!pRaw) continue;
    const p = JSON.parse(pRaw);
    const washes = await listWashesForPiece(env, pid);
    const activeWashes = washes.filter((w) => !w.deleted_at);
    pieces.push({
      piece_id: p.piece_id,
      product_name: p.product_name,
      origin_date: p.origin_date,
      wash_count: activeWashes.length,
      rhythm: computeRhythm(activeWashes.length)
    });
  }

  const postIds = await getCustomerPostIds(env, customerId);
  const posts = [];
  for (const pid of postIds) {
    const raw = await env.POTISSE_NFC.get(`post_${pid}`);
    if (!raw) continue;
    try {
      posts.push(JSON.parse(raw));
    } catch {}
  }

  const retractRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
  const retractCount = retractRaw ? JSON.parse(retractRaw) : { total: 0, last_retract: null };

  const emailHistoryRaw = await env.POTISSE_NFC.get(`customer_${customerId}_email_history`);
  const emailHistory = emailHistoryRaw ? JSON.parse(emailHistoryRaw) : [];

  const accessAlertActionsRaw = await env.POTISSE_NFC.get(`customer_${customerId}_access_alert_actions`);
  const accessAlertActions = accessAlertActionsRaw ? JSON.parse(accessAlertActionsRaw) : [];

  // Tap history: uid_<uid> guarda customer_id pero no hay Ã­ndice inverso
  // customerâ†’uid, asÃ­ que escaneamos uid_ (volumen bajo pre-launch).
  const uidKeys = await listAllKeysWithPrefix(env, "uid_");
  let tapHistory = [];
  for (const key of uidKeys) {
    if (key.name.endsWith("_tap_history")) continue;
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    let uidData;
    try {
      uidData = JSON.parse(raw);
    } catch {
      continue;
    }
    if (uidData.customer_id !== customerId) continue;
    const uid = key.name.slice("uid_".length);
    const thRaw = await env.POTISSE_NFC.get(`uid_${uid}_tap_history`);
    if (thRaw) {
      try {
        tapHistory = tapHistory.concat(JSON.parse(thRaw).history || []);
      } catch {}
    }
  }

  const shopifyInfo = await getShopifyCustomerBasic(env, customerId, profile.email);
  const clubStatsRaw = await env.POTISSE_NFC.get(`customer_${customerId}_club_stats`);
  const clubStats = clubStatsRaw ? JSON.parse(clubStatsRaw) : null;

  return new Response(JSON.stringify({
    ok: true,
    profile: { ...profile, tags: shopifyInfo.tags || "" },
    pieces,
    posts,
    retract_count: retractCount,
    email_history: emailHistory,
    access_alert_actions: accessAlertActions,
    tap_history: tapHistory
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminCustomerDetail, "handleAdminCustomerDetail");

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// B.2 â€” Address sync with Shopify + post-write verification
// Si Shopify no persiste la direcciÃ³n, propagamos el fallo
// honestamente al frontend SIN tocar KV.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// B.2 â€” Helper: equivalencia ISOâ†”nombre de paÃ­s para verificaciÃ³n post-write
const COUNTRY_ISO_TO_NAME = {
  "es": "spain", "pt": "portugal", "fr": "france", "de": "germany",
  "it": "italy", "nl": "netherlands", "be": "belgium", "lu": "luxembourg",
  "at": "austria", "ie": "ireland", "dk": "denmark", "se": "sweden",
  "fi": "finland", "gr": "greece", "cy": "cyprus", "mt": "malta",
  "ee": "estonia", "lv": "latvia", "lt": "lithuania", "pl": "poland",
  "cz": "czech republic", "sk": "slovakia", "si": "slovenia",
  "hu": "hungary", "hr": "croatia", "ro": "romania", "bg": "bulgaria"
};


// ===== v6.9.1 Hallazgo 12: readProfileField helper =====
function readProfileField(profile, field) {
  if (!profile) return null;
  if (profile.identity && profile.identity[field] !== undefined) {
    return profile.identity[field];
  }
  if (profile[field] !== undefined) {
    return profile[field];
  }
  return null;
}
// ========================================================

function normalizeCountry(v) {
  if (v == null) return "";
  const s = String(v).trim().toLowerCase();
  if (COUNTRY_ISO_TO_NAME[s]) return s;
  for (const [iso, name] of Object.entries(COUNTRY_ISO_TO_NAME)) {
    if (name === s) return iso;
  }
  return s;
}
async function handleAdminCustomerEdit(request, env, url, customerIdParam) {
  const providedAdminKey = request.headers.get("X-Admin-Key") || url.searchParams.get("admin");
  if (providedAdminKey !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const customerId = Number(customerIdParam);

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return jsonResponse({ error: "customer_not_found" }, 404);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }

  const profile = JSON.parse(profileRaw);

  // v6.9.3: Shopify es fuente de verdad PII. Solo notes/language/tags son editables en panel.
  const EDITABLE_FIELDS = ["notes", "language", "tags"];
  const PII_FIELDS = ["first_name", "last_name", "email", "phone", "address_line1", "address_line2", "city", "province", "postal_code", "country"];

  // Rechazar si body contiene campos PII
  const piiInBody = Object.keys(body).filter(k => PII_FIELDS.includes(k));
  if (piiInBody.length > 0) {
    return jsonResponse({
      error: "pii_edit_not_allowed",
      message: "PII fields must be edited in Shopify Admin. See /refresh-from-shopify to sync changes."
    }, 400);
  }

  const changedFields = [];
  for (const field of EDITABLE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      profile[field] = body[field];
      changedFields.push(field);
    }
  }

  profile.updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put(`customer_${customerId}_profile`, JSON.stringify(profile));

  // Invalidar cache de tags
  await env.POTISSE_NFC.delete(`customer_${customerId}_tags_cache`);

  if (changedFields.length > 0) {
    await writeTimelineEvent(env, {
      category: "members",
      severity: "info",
      actor: "admin",
      customer_id: customerId,
      type: "customer_edited",
      title: `Profile edited: ${changedFields.join(", ")}`,
      details: null,
      metadata: { changed_fields: changedFields }
    });
  }

  return jsonResponse({ ok: true, profile }, 200);
}
__name(handleAdminCustomerEdit, "handleAdminCustomerEdit");
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SYNC STATUS & RETRY â€” Address sync visibility + manual retry
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// B.2 â€” Webhook Shopify customers/update â†’ KV
// Cuando un cliente edita sus datos en Shopify, actualizamos KV.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function handleWebhookCustomersUpdate(request, env, ctx) {
  const rawBodyBytes = new Uint8Array(await request.arrayBuffer());
  const hmacHeader = request.headers.get("X-Shopify-Hmac-SHA256");
  if (!env.SHOPIFY_WEBHOOK_SECRET) {
    if (env.ALLOW_UNVERIFIED_WEBHOOKS === "true") {
      console.warn("[webhook customers/update] ALLOW_UNVERIFIED_WEBHOOKS=true, skipping HMAC verification");
    } else {
      return new Response("Webhook secret not configured", { status: 500 });
    }
  } else {
    const expectedHmac = await computeHmacBase64(env.SHOPIFY_WEBHOOK_SECRET, rawBodyBytes);
    const hmacMatch = await timingSafeStringEqual(hmacHeader, expectedHmac);
    if (!hmacMatch) {
      return new Response("Unauthorized", { status: 401 });
    }
  }
  let customer;
  try {
    customer = JSON.parse(new TextDecoder().decode(rawBodyBytes));
  } catch {
    return new Response("Bad JSON", { status: 400 });
  }

  // ValidaciÃ³n de sanidad
  if (!customer.id) {
    ctx.waitUntil(writeTimelineEvent(env, {
      category: "members",
      severity: "warning",
      actor: "shopify",
      title: "Webhook customers/update ignored â€” no customer.id",
      details: "Received payload without customer id, KV not updated"
    }));
    return new Response("OK", { status: 200 });
  }

  if (typeof customer.email !== "string" && customer.email !== null) {
    ctx.waitUntil(writeTimelineEvent(env, {
      category: "members",
      severity: "warning",
      actor: "shopify",
      title: "Webhook customers/update ignored â€” invalid payload structure",
      details: `email field type is ${typeof customer.email}, expected string or null`
    }));
    return new Response("OK", { status: 200 });
  }

  const customerId = customer.id;

  const profileKey = `customer_${customerId}_profile`;
  const profileRaw = await env.POTISSE_NFC.get(profileKey);
  if (!profileRaw) {
    console.log(`[customers/update] No KV profile for customer ${customerId}, skipping`);
    return new Response("OK", { status: 200 });
  }

  let profile;
  try {
    profile = JSON.parse(profileRaw);
  } catch {
    return new Response("Corrupted profile", { status: 500 });
  }

  // v6.9.2: Shopify es fuente de verdad PII. Actualizar KV directamente.
  // Fix: "in" preserva borrados intencionales (null/empty string)
  if ("first_name" in customer) profile.first_name = customer.first_name || null;
  if ("last_name" in customer) profile.last_name = customer.last_name || null;
  if ("email" in customer) profile.email = customer.email || null;
  if ("phone" in customer) profile.phone = customer.phone || null;

  const da = customer.default_address || {};
  if ("address1" in da) profile.address_line1 = da.address1 || null;
  if ("address2" in da) profile.address_line2 = da.address2 || null;
  if ("city" in da) profile.city = da.city || null;
  if ("province" in da) profile.province = da.province || null;
  if ("zip" in da) profile.postal_code = da.zip || null;
  if ("country_code" in da) profile.country = da.country_code || da.country || null;
  else if ("country" in da) profile.country = da.country || null;

  profile.last_synced_from_shopify_at = new Date().toISOString();

  await env.POTISSE_NFC.put(profileKey, JSON.stringify(profile));
  console.log(`[customers/update] customer=${customerId} updated from Shopify webhook`);
  return new Response("OK", { status: 200 });
}
__name(handleWebhookCustomersUpdate, "handleWebhookCustomersUpdate");

// v6.9.2 â€” GET /api/admin/members/:id/refresh-from-shopify
// READ-ONLY: compara KV vs Shopify y devuelve diff. NUNCA escribe.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function handleAdminMembersRefreshFromShopify(request, env, url, customerIdParam) {
  const customerId = customerIdParam;

  // 1. Fetch Shopify
  let shopifyRes;
  try {
    shopifyRes = await fetch(
      `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/${customerId}.json`,
      { headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN } }
    );
  } catch (err) {
    return jsonResponse({ ok: false, error: "shopify_unreachable", detail: err.message }, 502);
  }

  // 2. Validaciones de sanidad
  if (!shopifyRes.ok) {
    return jsonResponse({ ok: false, error: "shopify_error", detail: `HTTP ${shopifyRes.status}` }, 502);
  }

  let shopifyData;
  try {
    shopifyData = await shopifyRes.json();
  } catch {
    return jsonResponse({ ok: false, error: "shopify_invalid_json" }, 502);
  }

  if (!shopifyData?.customer) {
    return jsonResponse({ ok: false, error: "shopify_no_customer_object" }, 502);
  }

  const c = shopifyData.customer;
  if (!c.id) {
    return jsonResponse({ ok: false, error: "shopify_empty_customer_id" }, 502);
  }

  const hasAnyData = c.email || c.first_name || c.last_name || c.phone || c.default_address;
  if (!hasAnyData) {
    return jsonResponse({ ok: false, error: "shopify_all_fields_empty" }, 502);
  }

  // 3. Fetch KV profile
  const profileKey = `customer_${customerId}_profile`;
  const profileRaw = await env.POTISSE_NFC.get(profileKey);
  if (!profileRaw) {
    return jsonResponse({ ok: false, error: "profile_not_found_in_kv" }, 404);
  }
  const profile = JSON.parse(profileRaw);

  // 4. Build shopifyPII normalizado
  const da = c.default_address || {};
  const shopifyPII = {
    first_name: c.first_name || null,
    last_name: c.last_name || null,
    email: c.email || null,
    phone: c.phone || null,
    address_line1: da.address1 || null,
    address_line2: da.address2 || null,
    city: da.city || null,
    province: da.province || null,
    postal_code: da.zip || null,
    country: da.country_code || da.country || null
  };

  // 5. Diff campo por campo
  const diff = [];
  for (const field of Object.keys(shopifyPII)) {
    const kvVal = profile[field] ?? null;
    const shopifyVal = shopifyPII[field] ?? null;
    if (kvVal !== shopifyVal) {
      diff.push({ field, kv: kvVal, shopify: shopifyVal });
    }
  }

  return jsonResponse({
    ok: true,
    in_sync: diff.length === 0,
    diff,
    shopify_fetched_at: new Date().toISOString(),
    kv_last_synced_at: profile.last_synced_from_shopify_at || null
  }, 200);
}
__name(handleAdminMembersRefreshFromShopify, "handleAdminMembersRefreshFromShopify");

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// v6.9.2 â€” POST /api/admin/members/:id/apply-shopify-refresh
// Escribe en KV tras confirmaciÃ³n explÃ­cita del operador.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function handleAdminMembersApplyShopifyRefresh(request, env, url, customerIdParam) {
  const customerId = customerIdParam;
  const body = await request.json();
  const { fields_to_apply } = body;

  if (!fields_to_apply || typeof fields_to_apply !== "object") {
    return jsonResponse({ error: "fields_to_apply required" }, 400);
  }

  const ALLOWED_FIELDS = [
    "first_name", "last_name", "email", "phone",
    "address_line1", "address_line2", "city", "province", "postal_code", "country"
  ];

  const profileKey = `customer_${customerId}_profile`;
  const profileRaw = await env.POTISSE_NFC.get(profileKey);
  if (!profileRaw) return jsonResponse({ error: "profile_not_found" }, 404);
  const profile = JSON.parse(profileRaw);

  const applied = [];
  for (const [field, value] of Object.entries(fields_to_apply)) {
    if (!ALLOWED_FIELDS.includes(field)) continue;
    profile[field] = value;
    applied.push(field);
  }

  profile.last_synced_from_shopify_at = new Date().toISOString();

  await env.POTISSE_NFC.put(profileKey, JSON.stringify(profile));

  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "fran",
    customer_id: customerId,
    type: "manual_refresh_from_shopify_applied",
    title: "Manual refresh from Shopify applied to KV",
    details: `Fields updated: ${applied.join(", ")}`,
    metadata: { fields_applied: applied }
  });

  return jsonResponse({ ok: true, applied }, 200);
}
__name(handleAdminMembersApplyShopifyRefresh, "handleAdminMembersApplyShopifyRefresh");

// v6.7-members-admin â€” Fase 9.4.3 Oleada 1, backend Members
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Nota de campos pendientes (decisiÃ³n Fran, empty-state + push futuro):
// - access_status / club_visits_count / first_club_entry_at: unknown/0/null.
//   Falta escribir esto en /api/validate en un tap NFC exitoso.
// - total_spent / aov: commercial?.aov || null. Requiere capturar total_price en el webhook
//   orders-create, o un cron nocturno de sync con Shopify.
// - recent_sessions[].device: null. Requiere parsear User-Agent en la
//   emisiÃ³n de sesiÃ³n en /api/validate.
// - Filtro quiet_list: array vacÃ­o. Los signups de Quiet List son
//   customers de Shopify (tag *-pending vÃ­a /api/subscribe) sin
//   customer_<id>_profile en KV â€” invisibles para cualquier endpoint que
//   escanee el prefijo customer_. Requiere push separado
//   "Members-Quiet-List-Sync" con Shopify customers/search.json?query=tag:*-pending.

// Deriva el estado del toolbar (all/members/buyers/registered) a partir de
// seÃ±ales reales ya existentes: nÂº de pedidos (customer:<id>.orders) y nÂº
// de piezas con first_tap_at. Distinto del bloque access_status (entered/
// waiting/overdue), que es un concepto separado y hoy vuelve "unknown".
function deriveMemberState(ordersCount, tappedPiecesCount) {
  if (ordersCount === 0) return "registered";
  if (tappedPiecesCount > 0) return "members";
  return "buyers";
}
__name(deriveMemberState, "deriveMemberState");


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// QUIET LIST â€” Dedicated endpoint with stats
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function handleAdminQuietList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }

  const search = (url.searchParams.get("search") || "").toLowerCase().trim();
  const statusFilter = url.searchParams.get("status") || "all"; // all | verified | pending

  const quietListRaw = await env.POTISSE_NFC.get("quiet_list_pending");
  const quietList = quietListRaw ? JSON.parse(quietListRaw) : { emails: [] };

  const customers = [];
  let verifiedCount = 0;
  let pendingCount = 0;

  for (const email of quietList.emails || []) {
    try {
      const searchRes = await fetch(
        `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/search.json?query=email:${encodeURIComponent(email)}`,
        { headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN } }
      );
      if (searchRes.ok) {
        const searchData = await searchRes.json();
        const customer = (searchData.customers || [])[0];
        if (customer) {
          const isVerified = customer.email_marketing_consent?.state === "subscribed";
          const sourceTag = (customer.tags || "").split(",").map(t => t.trim()).find(t => t.endsWith("-pending") || t.endsWith("-verified")) || "unknown";

          if (isVerified) verifiedCount++;
          else pendingCount++;

          // Apply status filter
          if (statusFilter === "verified" && !isVerified) continue;
          if (statusFilter === "pending" && isVerified) continue;

          // Apply search filter
          if (search) {
            const haystack = `${customer.first_name || ""} ${customer.last_name || ""} ${customer.email || ""}`.toLowerCase();
            if (!haystack.includes(search)) continue;
          }

          customers.push({
            customer_id: customer.id,
            first_name: customer.first_name,
            last_name: customer.last_name,
            email: customer.email,
            phone: customer.phone,
            created_at: customer.created_at,
            updated_at: customer.updated_at,
            tags: customer.tags || "",
            verified: isVerified,
            source_tag: sourceTag
          });
        }
      }
    } catch (err) {
      console.error(`quiet_list: failed to fetch customer for ${email}: ${err.message}`);
    }
  }

  return new Response(JSON.stringify({
    ok: true,
    stats: {
      total: verifiedCount + pendingCount,
      verified: verifiedCount,
      pending: pendingCount
    },
    customers
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminQuietList, "handleAdminQuietList");

async function handleAdminQuietListBackfill(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }

  const quietListRaw = await env.POTISSE_NFC.get("quiet_list_pending");
  const quietList = quietListRaw ? JSON.parse(quietListRaw) : { emails: [] };

  let created = 0;
  let skipped = 0;
  let failed = 0;
  const now = new Date().toISOString();

  for (const email of quietList.emails || []) {
    try {
      const searchRes = await fetch(
        `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/search.json?query=email:${encodeURIComponent(email)}`,
        { headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN } }
      );
      if (!searchRes.ok) {
        failed++;
        console.error(`[backfill] search failed for ${email}: ${searchRes.status}`);
        continue;
      }
      const searchData = await searchRes.json();
      const customer = (searchData.customers || [])[0];
      if (!customer) {
        skipped++;
        console.warn(`[backfill] customer not found for ${email}`);
        continue;
      }

      const profileKey = `customer_${customer.id}_profile`;
      const existingProfileRaw = await env.POTISSE_NFC.get(profileKey);
      if (existingProfileRaw) {
        skipped++;
        continue;
      }

      const profileObj = {
        customer_id: customer.id,
        email: customer.email || email,
        first_name: customer.first_name || null,
        last_name: customer.last_name || null,
        phone: customer.phone || null,
        address_line1: null,
        address_line2: null,
        city: null,
        province: null,
        postal_code: null,
        country: null,
        language: null,
        notes: null,
        notes_free: null,
        registered_at: now,
        first_seen_at: now,
        updated_at: now,
        source: "quiet_list"
      };
      await env.POTISSE_NFC.put(profileKey, JSON.stringify(profileObj));
      created++;
      console.log(`[backfill] Created profile for customer ${customer.id} (${email})`);
    } catch (err) {
      failed++;
      console.error(`[backfill] exception for ${email}: ${err.message}`);
    }
  }

  return new Response(JSON.stringify({
    ok: true,
    processed: (quietList.emails || []).length,
    created,
    skipped,
    failed
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminQuietListBackfill, "handleAdminQuietListBackfill");

// ── C.M-cache: Members summary cache builder ──
async function refreshMembersSummaryCache(env) {
  const profiles = await listAllCustomerProfiles(env);
  const customers = [];

  // Process in batches of 10 to avoid overwhelming KV
  const BATCH_SIZE = 10;
  for (let i = 0; i < profiles.length; i += BATCH_SIZE) {
    const batch = profiles.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(async (profile) => {
        const customerId = profile.customer_id;
        if (!customerId) return null;

        try {
          // Commercial data (orders)
          const commercialRaw = await env.POTISSE_NFC.get(`customer:${customerId}`);
          const commercial = commercialRaw ? JSON.parse(commercialRaw) : null;
          const ordersCount = commercial?.orders?.length || 0;

          // Pieces
          const piecesIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
          const pieceIds = piecesIndexRaw ? (JSON.parse(piecesIndexRaw).piece_ids || []) : [];
          let tappedCount = 0;
          for (const pid of pieceIds) {
            const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
            if (!pRaw) continue;
            const p = JSON.parse(pRaw);
            if (p.first_tap_at) tappedCount++;
          }

          // Member state
          const memberState = deriveMemberState(ordersCount, tappedCount);

          // Retracts
          const retractRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
          const retractCount = retractRaw ? (JSON.parse(retractRaw).total || 0) : 0;

          // Tags (from cache, no Shopify fetch in cron)
          const tagsCacheRaw = await env.POTISSE_NFC.get(`customer_${customerId}_tags_cache`);
          const tags = tagsCacheRaw ? (JSON.parse(tagsCacheRaw).tags || "") : "";

          return {
            customer_id: customerId,
            first_name: profile.first_name,
            last_name: profile.last_name,
            email: profile.email,
            phone: profile.phone,
            language_chip: profile.language || null,
            country: profile.country || null,
            tags,
            access_status: { state: "unknown", club_visits_count: 0, days_since_delivered: null },
            first_seen_at: profile.first_seen_at || profile.registered_at || null,
            account_created_at: profile.registered_at || null,
            first_purchase_at: commercial?.orders?.[0]?.created_at || null,
            first_club_entry_at: null,
            pieces_count: pieceIds.length,
            retract_history_count: retractCount,
            member_state: memberState
          };
        } catch (err) {
          console.error(`[members-cache] Error processing customer ${customerId}: ${err.message}`);
          return null;
        }
      })
    );

    for (const result of batchResults) {
      if (result) customers.push(result);
    }
  }

  const cachePayload = {
    customers,
    count: customers.length,
    updated_at: new Date().toISOString()
  };

  await env.POTISSE_NFC.put("members_summary_cache", JSON.stringify(cachePayload));
  console.log(`[members-cache] Refreshed ${customers.length} customers`);
  return cachePayload;
}
__name(refreshMembersSummaryCache, "refreshMembersSummaryCache");

async function handleAdminMembersList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const filter = url.searchParams.get("filter") || "all";

  // ── QUIET LIST: siempre live (no cachea) ──
  if (filter === "quiet_list") {
    const quietListRaw = await env.POTISSE_NFC.get("quiet_list_pending");
    const quietList = quietListRaw ? JSON.parse(quietListRaw) : { emails: [] };
    const customers = [];
    for (const email of quietList.emails || []) {
      try {
        const searchRes = await fetch(
          `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/search.json?query=email:${encodeURIComponent(email)}`,
          { headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN } }
        );
        if (searchRes.ok) {
          const searchData = await searchRes.json();
          const customer = (searchData.customers || [])[0];
          if (customer) {
            customers.push({
              customer_id: customer.id,
              first_name: customer.first_name,
              last_name: customer.last_name,
              email: customer.email,
              phone: customer.phone,
              language_chip: null,
              country: null,
              tags: customer.tags || "",
              access_status: { state: "unknown", club_visits_count: 0, days_since_delivered: null },
              first_seen_at: customer.created_at,
              account_created_at: customer.created_at,
              first_purchase_at: null,
              first_club_entry_at: null,
              pieces_count: 0,
              retract_history_count: 0,
              member_state: "registered"
            });
          }
        }
      } catch (err) {
        console.error(`quiet_list: failed to fetch customer for ${email}: ${err.message}`);
      }
    }
    return new Response(JSON.stringify({
      ok: true,
      count: customers.length,
      customers,
      cursor: null,
      quiet_list_sync_pending: false,
      source: "live"
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  }

  const search = (url.searchParams.get("search") || "").toLowerCase().trim();
  const limit = Number(url.searchParams.get("limit")) || 50;
  const cursorParam = url.searchParams.get("cursor");
  const offset = cursorParam ? parseInt(cursorParam, 10) || 0 : 0;

  // ── INTENTAR CACHE PRIMERO ──
  const cacheRaw = await env.POTISSE_NFC.get("members_summary_cache");
  let allCustomers = [];
  let source = "cache";

  if (cacheRaw) {
    try {
      const cache = JSON.parse(cacheRaw);
      allCustomers = cache.customers || [];
    } catch (err) {
      console.error("[members-list] Cache parse error:", err.message);
      allCustomers = [];
    }
  }

  // ── FALLBACK: si no hay cache, generar on-the-fly (lento, solo emergencia) ──
  if (allCustomers.length === 0) {
    console.warn("[members-list] No cache found, falling back to live query (slow)");
    source = "live-fallback";
    const profiles = await listAllCustomerProfiles(env);
    for (const profile of profiles) {
      const customerId = profile.customer_id;
      if (!customerId) continue;
      try {
        const commercialRaw = await env.POTISSE_NFC.get(`customer:${customerId}`);
        const commercial = commercialRaw ? JSON.parse(commercialRaw) : null;
        const ordersCount = commercial?.orders?.length || 0;

        const piecesIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
        const pieceIds = piecesIndexRaw ? (JSON.parse(piecesIndexRaw).piece_ids || []) : [];
        let tappedCount = 0;
        for (const pid of pieceIds) {
          const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
          if (!pRaw) continue;
          const p = JSON.parse(pRaw);
          if (p.first_tap_at) tappedCount++;
        }

        const memberState = deriveMemberState(ordersCount, tappedCount);
        const retractRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
        const retractCount = retractRaw ? (JSON.parse(retractRaw).total || 0) : 0;
        const tags = await getCachedShopifyTags(env, customerId, profile.email);

        allCustomers.push({
          customer_id: customerId,
          first_name: profile.first_name,
          last_name: profile.last_name,
          email: profile.email,
          phone: profile.phone,
          language_chip: profile.language || null,
          country: profile.country || null,
          tags,
          access_status: { state: "unknown", club_visits_count: 0, days_since_delivered: null },
          first_seen_at: profile.first_seen_at || profile.registered_at || null,
          account_created_at: profile.registered_at || null,
          first_purchase_at: commercial?.orders?.[0]?.created_at || null,
          first_club_entry_at: null,
          pieces_count: pieceIds.length,
          retract_history_count: retractCount,
          member_state: memberState
        });
      } catch (err) {
        console.error(`[members-list] Fallback error for ${customerId}: ${err.message}`);
      }
    }
  }

  // ── APLICAR FILTROS ──
  let matched = allCustomers;

  if (search) {
    matched = allCustomers.filter(c => {
      const haystack = `${c.first_name || ""} ${c.last_name || ""} ${c.email || ""} ${c.customer_id}`.toLowerCase();
      return haystack.includes(search);
    });
  }

  if (filter !== "all") {
    matched = matched.filter(c => c.member_state === filter);
  }

  const page = matched.slice(offset, offset + limit);
  const nextCursor = offset + limit < matched.length ? String(offset + limit) : null;

  return new Response(JSON.stringify({
    ok: true,
    count: matched.length,
    customers: page,
    cursor: nextCursor,
    source
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMembersList, "handleAdminMembersList");

async function handleAdminMembersProfile(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  const profile = JSON.parse(profileRaw);

  // Backfill lazy de first_seen_at (decisiÃ³n Fran, Oleada 1)
  if (!profile.first_seen_at) {
    profile.first_seen_at = profile.registered_at || new Date().toISOString();
    await env.POTISSE_NFC.put(`customer_${customerId}_profile`, JSON.stringify(profile));
  }

  // JOIN: identidad (customer_<id>_profile) + comercial (customer:<id>,
  // dos puntos â€” key real del webhook Silencio 1, distinta de la key con
  // guion bajo de arriba).
  const commercialRaw = await env.POTISSE_NFC.get(`customer:${customerId}`);
  const commercial = commercialRaw ? JSON.parse(commercialRaw) : null;

  const piecesIndexRaw = await env.POTISSE_NFC.get(`customer_${customerId}_pieces_index`);
  const pieceIds = piecesIndexRaw ? (JSON.parse(piecesIndexRaw).piece_ids || []) : [];
  const pieces = [];
  for (const pid of pieceIds) {
    const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
    if (!pRaw) continue;
    const p = JSON.parse(pRaw);
    const washes = await listWashesForPiece(env, pid);
    const activeWashes = washes.filter((w) => !w.deleted_at);
    pieces.push({
      piece_id: p.piece_id,
      sku: p.sku || null,
      product_name: p.product_name,
      purchase_date: p.origin_date || null,
      first_tap_at: p.first_tap_at || null,
      wash_count: activeWashes.length,
      rhythm_phase: computeRhythm(activeWashes.length).phase,
      retract_history: []
    });
  }

  const postIds = await getCustomerPostIds(env, customerId);
  let kept = 0, published = 0, discarded = 0;
  const posts = [];
  for (const pid of postIds) {
    const raw = await env.POTISSE_NFC.get(`post_${pid}`);
    if (!raw) continue;
    let post;
    try {
      post = JSON.parse(raw);
    } catch {
      continue;
    }
    posts.push(post);
    if (post.status === "kept") kept++;
    else if (post.status === "published_ig") published++;
    else if (post.status === "discarded") discarded++;
  }

  const sessionKeys = await listAllKeysWithPrefix(env, "session_");
  let sessions = [];
  for (const key of sessionKeys) {
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    let s;
    try {
      s = JSON.parse(raw);
    } catch {
      continue;
    }
    if (s.customer_id !== customerId) continue;
    sessions.push({ timestamp: s.created_at, device: s.device || null });
  }
  sessions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  sessions = sessions.slice(0, 10);

  const uidKeys = await listAllKeysWithPrefix(env, "uid_");
  let tapHistory = [];
  for (const key of uidKeys) {
    if (key.name.endsWith("_tap_history")) continue;
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    let uidData;
    try {
      uidData = JSON.parse(raw);
    } catch {
      continue;
    }
    if (uidData.customer_id !== customerId) continue;
    const uid = key.name.slice("uid_".length);
    const thRaw = await env.POTISSE_NFC.get(`uid_${uid}_tap_history`);
    if (thRaw) {
      try {
        tapHistory = tapHistory.concat(JSON.parse(thRaw).history || []);
      } catch {}
    }
  }

  const totalWashes = pieces.reduce((sum, p) => sum + p.wash_count, 0);

  const retractRaw = await env.POTISSE_NFC.get(`customer_${customerId}_retract_count`);
  const retractCount = retractRaw ? JSON.parse(retractRaw) : { total: 0, last_retract: null };

  const emailHistoryRaw = await env.POTISSE_NFC.get(`customer_${customerId}_email_history`);
  const emailHistory = emailHistoryRaw ? JSON.parse(emailHistoryRaw) : [];

  const accessAlertActionsRaw = await env.POTISSE_NFC.get(`customer_${customerId}_access_alert_actions`);
  const accessAlertActions = accessAlertActionsRaw ? JSON.parse(accessAlertActionsRaw) : [];

  const shopifyInfo = await getShopifyCustomerBasic(env, customerId, profile.email);
  const clubStatsRaw = await env.POTISSE_NFC.get(`customer_${customerId}_club_stats`);
  const clubStats = clubStatsRaw ? JSON.parse(clubStatsRaw) : null;

  return new Response(JSON.stringify({
    ok: true,
    identity: {
      first_name: profile.first_name || null,
      last_name: profile.last_name || null,
      email: profile.email || null,
      phone: profile.phone || null,
      address_line1: profile.address_line1 || profile.address || null,
      address_line2: profile.address_line2 || null,
      city: profile.city || null,
      province: profile.province || null,
      postal_code: profile.postal_code || null,
      country: profile.country || null,
      language: profile.language || null,
      private_notes: profile.notes || null
    },
    commercial: {
      registered_at: profile.registered_at || null,
      first_purchase_at: commercial?.orders?.[0]?.created_at || null,
      last_purchase_at: commercial?.silencio_1?.last_purchase_at || null,
      total_spent: commercial?.total_spent || null,
      orders_count: commercial?.orders?.length || 0,
      aov: commercial?.aov || null
    },
    club: {
      first_club_entry_at: clubStats?.first_entry_at || null,
      club_visits_count: clubStats?.visits_count || 0,
      last_visit: clubStats?.last_entry_at || sessions[0]?.timestamp || null,
      recent_sessions: sessions,
      total_washes: totalWashes,
      moments_shared: posts.length,
      post_history: { kept, published, discarded }
    },
    pieces,
    access_status: { state: "unknown", zone: null, history: accessAlertActions },
    communications: { email_timeline: emailHistory },
    silencios_received: {
      silencio_1: commercial?.silencio_1 ? [commercial.silencio_1] : [],
      silencio_2: [],
      silencio_3: []
    },
    tags_shopify: (shopifyInfo.tags || "").split(",").map((t) => t.trim()).filter(Boolean),
    notes_free: profile.notes_free || null,
    first_seen_at: profile.first_seen_at,
    last_synced_from_shopify_at: profile.last_synced_from_shopify_at || null,
    tap_history: tapHistory,
    retract_count: retractCount
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminMembersProfile, "handleAdminMembersProfile");

async function handleAdminMembersTags(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  const { action, tag } = body || {};
  if (!["add", "remove"].includes(action) || !tag || typeof tag !== "string") {
    return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
  }
  const profile = JSON.parse(profileRaw);

  const shopifyInfo = await getShopifyCustomerBasic(env, customerId, profile.email);
  if (!shopifyInfo.ok) {
    return new Response(JSON.stringify({ error: "shopify_fetch_failed" }), { status: 502, headers: { "Content-Type": "application/json" } });
  }

  let tags = (shopifyInfo.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
  if (action === "add") {
    if (!tags.includes(tag)) tags.push(tag);
  } else {
    tags = tags.filter((t) => t !== tag);
  }
  const newTagsStr = tags.join(", ");

  try {
    const res = await fetch(`https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/customers/${customerId}.json`, {
      method: "PUT",
      headers: { "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify({ customer: { id: customerId, tags: newTagsStr } })
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error(`members/tags Shopify update failed: ${res.status} ${errText}`);
      return new Response(JSON.stringify({ error: "shopify_update_failed" }), { status: 502, headers: { "Content-Type": "application/json" } });
    }
  } catch (err) {
    console.error(`members/tags Shopify update threw: ${err.message}`);
    return new Response(JSON.stringify({ error: "shopify_update_failed" }), { status: 502, headers: { "Content-Type": "application/json" } });
  }

  await env.POTISSE_NFC.delete(`customer_${customerId}_tags_cache`);

  // v6.7.1: envio_cortesia_activo es semÃ¡nticamente un evento editorial
  // (Silencio 1 manual), no un tag genÃ©rico â€” Timeline lo distingue.
  const isCourtesyShippingTag = tag === "envio_cortesia_activo";
  const eventType = isCourtesyShippingTag
    ? (action === "add" ? "silencio_sent" : "silencio_revoked")
    : (action === "add" ? "tag_added" : "tag_removed");
  const eventTitle = isCourtesyShippingTag
    ? (action === "add" ? "Silencio 1 sent (courtesy shipping applied)" : "Silencio 1 revoked (courtesy shipping removed)")
    : `${action === "add" ? "Tag added" : "Tag removed"}: ${tag}`;

  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "admin",
    customer_id: customerId,
    type: eventType,
    title: eventTitle,
    details: null,
    metadata: { tag, action }
  });

  return new Response(JSON.stringify({ ok: true, tags }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminMembersTags, "handleAdminMembersTags");

async function handleAdminMembersNotes(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);

  const profileRaw = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
  if (!profileRaw) {
    return new Response(JSON.stringify({ error: "customer_not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  if (typeof body?.notes_free !== "string") {
    return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const profile = JSON.parse(profileRaw);
  profile.notes_free = body.notes_free;
  profile.updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put(`customer_${customerId}_profile`, JSON.stringify(profile));

  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "admin",
    customer_id: customerId,
    type: "customer_notes_updated",
    title: "Free notes updated",
    details: null
  });

  return new Response(JSON.stringify({ ok: true, notes_free: profile.notes_free }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminMembersNotes, "handleAdminMembersNotes");

// â”€â”€ 9.2.7/9.2.8/9.2.9: Stock (packaging + garments + production) â”€â”€
async function getStockData(env, key) {
  const raw = await env.POTISSE_NFC.get(key);
  if (raw) {
    try {
      return JSON.parse(raw);
    } catch {}
  }
  return { items: {} };
}
__name(getStockData, "getStockData");

// ═══════════════════════════════════════════════════════════════════════
// C.5-A.2 HELPERS — Batches + Activity Log + Genealogy
// ═══════════════════════════════════════════════════════════════════════

const BATCH_STATUSES = [
  "to_order", "ordered", "in_house", "with_artisan",
  "qc_pending", "stock_ready", "discarded"
];

const BATCH_VALID_TRANSITIONS = {
  to_order: ["ordered", "discarded"],
  ordered: ["in_house", "discarded"],
  in_house: ["with_artisan", "qc_pending", "discarded"],
  with_artisan: ["in_house", "qc_pending", "discarded"],
  qc_pending: ["stock_ready", "discarded", "in_house"],
  stock_ready: ["discarded"],
  discarded: []
};

function isValidBatchTransition(fromStatus, toStatus) {
  const allowed = BATCH_VALID_TRANSITIONS[fromStatus] || [];
  return allowed.includes(toStatus);
}
__name(isValidBatchTransition, "isValidBatchTransition");

function getActor(request) {
  return request.headers.get("X-Actor") === "POT" ? "POT" : "Fran";
}
__name(getActor, "getActor");

async function getNextBatchSeq(env, dateStr) {
  const allKeys = await listAllKeysWithPrefix(env, "stock_batch_");
  let maxSeq = 0;
  for (const key of allKeys) {
    const match = key.match(/^stock_batch_(\d{8})_(\d{3})$/);
    if (match && match[1] === dateStr) {
      const seq = parseInt(match[2], 10);
      if (seq > maxSeq) maxSeq = seq;
    }
  }
  return String(maxSeq + 1).padStart(3, "0");
}
__name(getNextBatchSeq, "getNextBatchSeq");

async function getBatch(env, batchId) {
  const raw = await env.POTISSE_NFC.get(`stock_batch_${batchId}`);
  return raw ? JSON.parse(raw) : null;
}
__name(getBatch, "getBatch");

async function putBatch(env, batch) {
  await env.POTISSE_NFC.put(`stock_batch_${batch.id}`, JSON.stringify(batch));
}
__name(putBatch, "putBatch");

// FIX: stock_items se almacena indexado por "id", no por "sku".
// Esta función convierte el diccionario id-indexado a sku-indexado
// para que los batch handlers puedan buscar por item_sku.
async function getStockItemCatalog(env) {
  const list = await env.POTISSE_NFC.list({ prefix: "stock_item_" });
  const bySku = {};
  for (const k of list.keys || []) {
    const raw = await env.POTISSE_NFC.get(k.name);
    if (raw) {
      try {
        const item = JSON.parse(raw);
        if (item && item.sku) bySku[item.sku] = item;
      } catch {}
    }
  }
  return { items: bySku };
}
__name(getStockItemCatalog, "getStockItemCatalog");
__name(getStockItemCatalog, "getStockItemCatalog");

async function getStockSuppliers(env) {
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  return raw ? JSON.parse(raw) : { suppliers: {} };
}
__name(getStockSuppliers, "getStockSuppliers");

function enrichBatchList(batch, items, suppliers) {
  const item = items[batch.item_sku] || null;
  const holder = suppliers[batch.current_holder_id] || null;
  return {
    id: batch.id,
    item_sku: batch.item_sku,
    item_name: item ? item.name : null,
    item_category: item ? item.category : null,
    quantity: batch.quantity,
    status: batch.status,
    current_holder_id: batch.current_holder_id,
    current_holder_name: holder ? holder.name : null,
    current_step_index: batch.current_step_index,
    expected_completion_at: batch.expected_completion_at,
    linked_po_id: batch.linked_po_id,
    parent_batch_id: batch.parent_batch_id,
    source_batch_ids: batch.source_batch_ids || [],
    child_batch_ids: batch.child_batch_ids || [],
    notes: batch.notes,
    cost_accumulated: batch.cost_accumulated,
    currency: batch.currency,
    status_since: batch.status_since,
    last_activity_at: batch.last_activity_at,
    activity_count: (batch.activities || []).length,
    created_at: batch.created_at,
    updated_at: batch.updated_at,
    created_by: batch.created_by
  };
}
__name(enrichBatchList, "enrichBatchList");

function enrichBatchDetail(batch, items, suppliers) {
  const enriched = enrichBatchList(batch, items, suppliers);
  enriched.activities = batch.activities || [];
  return enriched;
}
__name(enrichBatchDetail, "enrichBatchDetail");

function addActivity(batch, type, actor, data) {
  const seq = (batch.activities || []).length + 1;
  const activity = {
    seq,
    timestamp: new Date().toISOString(),
    type,
    actor,
    data
  };
  if (!batch.activities) batch.activities = [];
  batch.activities.push(activity);
  batch.last_activity_at = activity.timestamp;
  batch.updated_at = activity.timestamp;
  return activity;
}
__name(addActivity, "addActivity");

async function logBatchTimeline(env, ctx, batchId, type, severity, title, description, actor) {
  if (ctx && ctx.waitUntil) {
    ctx.waitUntil((async () => {
      try {
        await writeTimelineEvent(env, {
          category: "stock_pipeline",
          severity: severity || "info",
          actor: actor || "Fran",
          type: type || "batch_event",
          title,
          description,
          batch_id: batchId
        });
      } catch (e) {
        console.error(`[batch timeline] error:`, e.message);
      }
    })());
  }
}
__name(logBatchTimeline, "logBatchTimeline");

function checkRecentComm(batch, hours) {
  const cutoff = Date.now() - (hours * 3600 * 1000);
  for (let i = batch.activities.length - 1; i >= 0; i--) {
    const act = batch.activities[i];
    if (act.type === "email_sent" || act.type === "call_log") {
      const actTime = new Date(act.timestamp).getTime();
      if (actTime > cutoff) {
        const hoursAgo = (Date.now() - actTime) / 3600000;
        return {
          exists: true,
          last_comm: {
            type: act.type,
            timestamp: act.timestamp,
            actor: act.actor,
            summary: act.data.subject || act.data.summary || "Communication logged"
          },
          hours_ago: Math.round(hoursAgo * 10) / 10
        };
      }
    }
  }
  return { exists: false };
}
__name(checkRecentComm, "checkRecentComm");

function computeStockStatus(current, minThreshold, criticalThreshold) {
  if (current <= 0) return "out";
  if (current <= criticalThreshold) return "critical";
  if (current <= minThreshold) return "low";
  return "ok";
}
__name(computeStockStatus, "computeStockStatus");

async function handleAdminStockSummary(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const packagingData = await getStockData(env, "stock_packaging");
  const garmentsData = await getStockData(env, "stock_garments");
  const pipelineRaw = await env.POTISSE_NFC.get("production_pipeline");
  const pipeline = pipelineRaw ? JSON.parse(pipelineRaw) : { letonia: [], modistas: [], bordadores: [] };

  const packaging = Object.entries(packagingData.items || {}).map(([itemId, item]) => ({
    item_id: itemId,
    name: item.name,
    current_stock: item.current,
    min_threshold: item.min_threshold,
    critical_threshold: item.critical_threshold,
    status: computeStockStatus(item.current, item.min_threshold, item.critical_threshold),
    monthly_consumption_avg: item.monthly_consumption_avg || null,
    in_production: item.in_production || []
  }));

  const garments = Object.entries(garmentsData.items || {}).map(([skuSize, item]) => ({
    sku: item.sku || skuSize,
    size: item.size || null,
    product_name: item.product_name || null,
    current_stock: item.current,
    min_threshold: item.min_threshold,
    critical_threshold: item.critical_threshold,
    status: computeStockStatus(item.current, item.min_threshold, item.critical_threshold),
    monthly_sales_avg: item.monthly_sales_avg || null,
    projected_stockout_days: item.projected_stockout_days || null
  }));

  return new Response(JSON.stringify({
    ok: true,
    packaging,
    garments,
    production_pipeline: pipeline
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminStockSummary, "handleAdminStockSummary");

async function handleAdminStockAdjust(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const { item_type, item_id, delta, reason, timestamp, name, min_threshold, critical_threshold } = body || {};
  if (!item_type || !["packaging", "garment"].includes(item_type) || !item_id || typeof delta !== "number") {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const stockKey = item_type === "packaging" ? "stock_packaging" : "stock_garments";
  const data = await getStockData(env, stockKey);
  if (!data.items[item_id]) {
    data.items[item_id] = {
      name: name || item_id,
      current: 0,
      min_threshold: min_threshold != null ? min_threshold : (item_type === "packaging" ? 20 : 0),
      critical_threshold: critical_threshold != null ? critical_threshold : (item_type === "packaging" ? 10 : 0),
      history: []
    };
  }
  const item = data.items[item_id];
  item.current = (item.current || 0) + delta;
  item.history.push({
    delta,
    reason: reason || null,
    timestamp: timestamp || new Date().toISOString(),
    new_total: item.current
  });

  await env.POTISSE_NFC.put(stockKey, JSON.stringify(data));

  return new Response(JSON.stringify({
    ok: true,
    item_id,
    current_stock: item.current,
    status: computeStockStatus(item.current, item.min_threshold, item.critical_threshold)
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminStockAdjust, "handleAdminStockAdjust");

async function handleAdminStockProduction(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const { item_type, item_id, units, eta_date, supplier, notes } = body || {};
  if (!item_type || !["packaging", "garment"].includes(item_type) || !item_id || !units || !eta_date) {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const stockKey = item_type === "packaging" ? "stock_packaging" : "stock_garments";
  const data = await getStockData(env, stockKey);
  if (!data.items[item_id]) {
    return new Response(JSON.stringify({ error: "item_not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  const item = data.items[item_id];
  if (!item.in_production) item.in_production = [];
  item.in_production.push({
    units,
    eta: eta_date,
    supplier: supplier || null,
    notes: notes || null,
    added_at: new Date().toISOString()
  });

  await env.POTISSE_NFC.put(stockKey, JSON.stringify(data));

  return new Response(JSON.stringify({ ok: true, item_id, in_production: item.in_production }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminStockProduction, "handleAdminStockProduction");

// â”€â”€ 9.2.10/9.2.11: Salud del sistema + timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// NOTA: varios campos requieren APIs externas sin credenciales configuradas
// (Cloudflare Analytics/Billing, Better Stack, Resend Analytics, WHOIS/SSL
// lookup). Se devuelven como null con "data_gaps" explÃ­cito en vez de
// inventar nÃºmeros â€” ver reporte Fase 9.2.
// â”€â”€ Fase 9.2, CorrecciÃ³n 3: integraciones externas para health/summary â”€â”€
async function cloudflareGraphQL(env, query, variables) {
  const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.CLOUDFLARE_ANALYTICS_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  });
  const data = await res.json();
  if (!res.ok || data.errors) {
    throw new Error(data.errors ? JSON.stringify(data.errors) : `HTTP ${res.status}`);
  }
  return data.data;
}
__name(cloudflareGraphQL, "cloudflareGraphQL");

async function fetchWorkerAnalytics(env) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const query = `
    query WorkerStats($accountTag: String!, $since: Time!, $scriptName: String!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          workersInvocationsAdaptive(
            filter: { datetime_geq: $since, scriptName: $scriptName }
            limit: 10000
          ) {
            sum { requests errors subrequests }
          }
        }
      }
    }
  `;
  const data = await cloudflareGraphQL(env, query, {
    accountTag: env.CLOUDFLARE_ACCOUNT_ID,
    since,
    scriptName: "potisse-nfc"
  });
  const groups = data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
  const totals = groups.reduce((acc, g) => ({
    requests: acc.requests + (g.sum?.requests || 0),
    errors: acc.errors + (g.sum?.errors || 0)
  }), { requests: 0, errors: 0 });
  return { requests_last_24h: totals.requests, errors_last_24h: totals.errors };
}
__name(fetchWorkerAnalytics, "fetchWorkerAnalytics");

function firstDayOfMonthIso() {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}
__name(firstDayOfMonthIso, "firstDayOfMonthIso");

async function fetchKvAnalytics(env) {
  const query = `
    query KvStats($accountTag: String!, $since: Time!, $namespaceId: String!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          kvOperationsAdaptiveGroups(
            filter: { datetime_geq: $since, namespaceId: $namespaceId }
            limit: 10000
          ) {
            sum { requests }
            dimensions { actionType }
          }
        }
      }
    }
  `;
  const data = await cloudflareGraphQL(env, query, {
    accountTag: env.CLOUDFLARE_ACCOUNT_ID,
    since: firstDayOfMonthIso(),
    namespaceId: "73811bbea16343cea0fbf3c3dd9c77cf"
  });
  const groups = data?.viewer?.accounts?.[0]?.kvOperationsAdaptiveGroups || [];
  let reads = 0;
  let writes = 0;
  for (const g of groups) {
    const action = (g.dimensions?.actionType || "").toLowerCase();
    const requests = g.sum?.requests || 0;
    if (action === "read") reads += requests;
    else if (action === "write") writes += requests;
  }
  return { reads_this_month: reads, writes_this_month: writes };
}
__name(fetchKvAnalytics, "fetchKvAnalytics");

async function fetchR2Analytics(env) {
  const query = `
    query R2Stats($accountTag: String!, $since: Time!, $bucketName: String!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          r2StorageAdaptiveGroups(
            filter: { datetime_geq: $since, bucketName: $bucketName }
            limit: 100
          ) {
            max { payloadSize objectCount }
          }
          r2OperationsAdaptiveGroups(
            filter: { datetime_geq: $since, bucketName: $bucketName }
            limit: 10000
          ) {
            sum { requests }
          }
        }
      }
    }
  `;
  const data = await cloudflareGraphQL(env, query, {
    accountTag: env.CLOUDFLARE_ACCOUNT_ID,
    since: firstDayOfMonthIso(),
    bucketName: "potisse-posts"
  });
  const account = data?.viewer?.accounts?.[0] || {};
  const storageGroups = account.r2StorageAdaptiveGroups || [];
  const maxPayload = storageGroups.reduce((max, g) => Math.max(max, g.max?.payloadSize || 0), 0);
  const opsGroups = account.r2OperationsAdaptiveGroups || [];
  const totalOps = opsGroups.reduce((sum, g) => sum + (g.sum?.requests || 0), 0);
  return {
    storage_gb: maxPayload ? Number((maxPayload / 1024 ** 3).toFixed(3)) : 0,
    operations_this_month: totalOps
  };
}
__name(fetchR2Analytics, "fetchR2Analytics");

// NOTA: mapeo de campos best-effort segÃºn formato JSON:API documentado por
// Better Stack â€” no verificado contra un payload real (no hay forma de
// probarlo sin el token real corriendo en producciÃ³n). Si los nombres de
// campo no coinciden, esta funciÃ³n lanza y health/summary lo refleja en
// data_gaps sin romper el resto del endpoint.
// â”€â”€ Fase 9.2, security patch v6.6.1: redacta query params sensibles â”€â”€
// Incidente: un monitor Better Stack tenÃ­a la ADMIN_KEY embebida en su URL
// configurada, y health/summary la reflejaba tal cual. Key ya rotada,
// monitor comprometido eliminado. Esta funciÃ³n es defensa en profundidad
// para que cualquier URL de monitor externo con secretos por descuido
// nunca se refleje en la respuesta.
function redactSensitiveQueryParams(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const SENSITIVE = ["admin", "token", "key", "api_key", "apikey", "secret", "access_token", "auth", "password"];
    for (const param of SENSITIVE) {
      if (u.searchParams.has(param)) {
        u.searchParams.set(param, "***REDACTED***");
      }
    }
    return u.toString();
  } catch {
    return rawUrl;
  }
}
__name(redactSensitiveQueryParams, "redactSensitiveQueryParams");

async function fetchBetterStackMonitors(env) {
  const res = await fetch("https://uptime.betterstack.com/api/v2/monitors", {
    headers: { "Authorization": `Bearer ${env.BETTER_STACK_TOKEN}` }
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const data = await res.json();
  return (data.data || []).map((m) => {
    const safeUrl = redactSensitiveQueryParams(m.attributes?.url || "");
    return {
      // "name" tambiÃ©n puede filtrar la URL cruda si falta pronounceable_name
      // (fallback previo era m.attributes?.url sin redactar) â€” usamos la
      // versiÃ³n ya saneada aquÃ­ tambiÃ©n.
      name: m.attributes?.pronounceable_name || safeUrl || m.id,
      url: m.attributes?.url ? safeUrl : null,
      status: m.attributes?.status || "unknown",
      last_checked_at: m.attributes?.last_checked_at || null,
      uptime_last_24h_percent: m.attributes?.availability?.daily ?? null
    };
  });
}
__name(fetchBetterStackMonitors, "fetchBetterStackMonitors");

// NOTA: mismo caveat que Better Stack â€” endpoint y schema segÃºn lo
// especificado en el encargo, no verificado contra un payload real de Resend.
async function fetchResendDeliveryRate(env) {
  const res = await fetch("https://api.resend.com/emails?limit=100", {
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}` }
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const data = await res.json();
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const recent = (data.data || []).filter((e) => new Date(e.created_at).getTime() >= cutoff);
  if (recent.length === 0) return null;
  const delivered = recent.filter((e) => e.last_event === "delivered").length;
  const bounced = recent.filter((e) => e.last_event === "bounced").length;
  const complained = recent.filter((e) => e.last_event === "complained").length;
  const total = delivered + bounced + complained;
  if (total === 0) return null;
  return Number(((delivered / total) * 100).toFixed(1));
}
__name(fetchResendDeliveryRate, "fetchResendDeliveryRate");

async function getDomainSslInfo(env) {
  const raw = await env.POTISSE_NFC.get("system_domain_ssl");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
__name(getDomainSslInfo, "getDomainSslInfo");

function daysRemainingFrom(isoDate) {
  if (!isoDate) return null;
  return Math.floor((new Date(isoDate).getTime() - Date.now()) / (24 * 60 * 60 * 1000));
}
__name(daysRemainingFrom, "daysRemainingFrom");

// â”€â”€ Fase 9.2: Telegram â€” forward-compat para Fase 9.8 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID todavÃ­a no existen como secrets
// (Fase 9.8 pendiente). Sin ellos, esta funciÃ³n no-opea con un warning en
// log en vez de fallar â€” mismo patrÃ³n defensivo que el resto de integraciones.
async function sendTelegramAlert(env, title, message, severity) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    console.warn("sendTelegramAlert: TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID no configurados todavÃ­a (Fase 9.8 pendiente)");
    return false;
  }
  const text = `âš ï¸ POTISSE Alert â€” ${severity}\n${title}\n\n${message}\n\n${new Date().toISOString()}`;
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, parse_mode: "Markdown" })
    });
    if (!res.ok) {
      console.error(`sendTelegramAlert failed: ${res.status} ${await res.text()}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error(`sendTelegramAlert threw: ${err.message}`);
    return false;
  }
}
__name(sendTelegramAlert, "sendTelegramAlert");

function cronStaleStatus(lastRun, staleHours) {
  if (!lastRun) return "stale";
  const hoursSince = (Date.now() - new Date(lastRun).getTime()) / (60 * 60 * 1000);
  return hoursSince > staleHours ? "stale" : "ok";
}
__name(cronStaleStatus, "cronStaleStatus");

async function handleAdminHealthSummary(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const dataGaps = [];

  const silencio1LastRun = await env.POTISSE_NFC.get("system:last_cron_run");
  const accessAlertsRaw = await env.POTISSE_NFC.get("access_alerts_active");
  const accessAlertsLastRun = accessAlertsRaw ? JSON.parse(accessAlertsRaw).last_run : null;
  const purgeLastRun = await env.POTISSE_NFC.get("system:last_purge_retracts_run");

  const crons = [
    { name: "silencio1", schedule: "0 3 * * *", last_run: silencio1LastRun, status: cronStaleStatus(silencio1LastRun, 26) },
    { name: "access_alerts", schedule: "0 8 * * *", last_run: accessAlertsLastRun, status: cronStaleStatus(accessAlertsLastRun, 26) },
    { name: "purge_retracts", schedule: "0 * * * *", last_run: purgeLastRun, status: cronStaleStatus(purgeLastRun, 1.5) }
  ];

  let workerStats = { requests_last_24h: null, errors_last_24h: null };
  let kvStats = { reads_this_month: null, writes_this_month: null };
  let r2Stats = { storage_gb: null, operations_this_month: null };
  try {
    const [w, kv, r2] = await Promise.all([
      fetchWorkerAnalytics(env),
      fetchKvAnalytics(env),
      fetchR2Analytics(env)
    ]);
    workerStats = w;
    kvStats = kv;
    r2Stats = r2;
  } catch (err) {
    console.error(`health/summary Cloudflare Analytics failed: ${err.message}`);
    dataGaps.push(`worker/kv/r2 analytics: Cloudflare Analytics API fallÃ³ â€” ${err.message}`);
  }

  let betterStackMonitors = [];
  try {
    betterStackMonitors = await fetchBetterStackMonitors(env);
  } catch (err) {
    console.error(`health/summary Better Stack failed: ${err.message}`);
    dataGaps.push(`better_stack.monitors: API fallÃ³ â€” ${err.message}`);
  }

  let resendDeliveryRate = null;
  try {
    resendDeliveryRate = await fetchResendDeliveryRate(env);
  } catch (err) {
    console.error(`health/summary Resend failed: ${err.message}`);
    dataGaps.push(`resend.delivery_rate_24h: API fallÃ³ â€” ${err.message}`);
  }

  const domainSsl = await getDomainSslInfo(env);
  let domain = { name: "potisse.com", expires: null, days_remaining: null, auto_renew: null };
  let sslCerts = [];
  if (domainSsl) {
    const domainDays = daysRemainingFrom(domainSsl.domain_expires);
    const sslDays = daysRemainingFrom(domainSsl.ssl_cert_expires);
    domain = { name: "potisse.com", expires: domainSsl.domain_expires || null, days_remaining: domainDays, auto_renew: null };
    sslCerts = [{ name: "potisse.com", expires: domainSsl.ssl_cert_expires || null, days_remaining: sslDays }];

    if (domainDays != null && domainDays < 30) {
      await sendTelegramAlert(env, "Dominio prÃ³ximo a expirar", `potisse.com expira en ${domainDays} dÃ­as.`, "amber");
    }
    if (sslDays != null && sslDays < 30) {
      await sendTelegramAlert(env, "Certificado SSL prÃ³ximo a expirar", `Certificado de potisse.com expira en ${sslDays} dÃ­as.`, "amber");
    }
  } else {
    dataGaps.push("domain_expires / ssl_cert_expires: pendiente de introducir manualmente vÃ­a POST /api/admin/system/domain-ssl (una vez al aÃ±o)");
  }

  dataGaps.push("worker.uptime_hours_since_deploy: no observable desde dentro del Worker, requiere log de deploy externo");
  dataGaps.push("kv.storage_mb: no incluido en las queries de CorrecciÃ³n 3 (kvOperationsAdaptiveGroups no reporta tamaÃ±o de storage)");
  dataGaps.push("shopify_tokens: requiere fechas de expiraciÃ³n reales, no integrado");
  dataGaps.push("rate_limits_triggered_24h: no hay contador persistente todavÃ­a (los rate limiters actuales son en memoria)");
  dataGaps.push("cloudflare_cost_this_month.overage: API Billing restringida, ver email mensual Cloudflare");

  const anyStale = crons.some((c) => c.status === "stale");
  const masterStatus = anyStale ? "amber" : "green";

  return new Response(JSON.stringify({
    ok: true,
    master_status: masterStatus,
    worker: {
      version: "6.12.3-stock-schema-rollback",
      uptime_hours_since_deploy: null,
      requests_last_24h: workerStats.requests_last_24h,
      errors_last_24h: workerStats.errors_last_24h
    },
    kv: {
      reads_this_month: kvStats.reads_this_month,
      writes_this_month: kvStats.writes_this_month,
      storage_mb: null,
      cap_reads: 10000000,
      cap_writes: 1000000
    },
    r2: { storage_gb: r2Stats.storage_gb, operations_this_month: r2Stats.operations_this_month, cap_gb: 10 },
    crons,
    better_stack: { monitors: betterStackMonitors },
    resend: { delivery_rate_24h: resendDeliveryRate },
    ssl_certs: sslCerts,
    domain,
    shopify_tokens: [],
    rate_limits_triggered_24h: null,
    cloudflare_cost_this_month: { base: 5, overage: null, total: null },
    data_gaps: dataGaps
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminHealthSummary, "handleAdminHealthSummary");

// â”€â”€ Fase 9.2, CorrecciÃ³n 3.4: POST /api/admin/system/domain-ssl â”€â”€â”€â”€
async function handleAdminSystemDomainSsl(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const { domain_expires, ssl_cert_expires } = body || {};
  if (!domain_expires && !ssl_cert_expires) {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const existing = (await getDomainSslInfo(env)) || {};
  const updated = {
    domain_expires: domain_expires || existing.domain_expires || null,
    ssl_cert_expires: ssl_cert_expires || existing.ssl_cert_expires || null,
    updated_at: new Date().toISOString(),
    updated_by: "admin"
  };
  await env.POTISSE_NFC.put("system_domain_ssl", JSON.stringify(updated));

  return new Response(JSON.stringify({ ok: true, ...updated }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminSystemDomainSsl, "handleAdminSystemDomainSsl");

// v6.7: Timeline single-source-of-truth. Reemplaza el logTimelineEvent
// original (key Ãºnica timeline_events, nunca invocado en producciÃ³n) por
// keys individuales timeline_<YYYYMMDD>_<epoch_ms>_<random>, shape rico y
// retenciÃ³n 90 dÃ­as. Ver scripts/backfill_timeline.mjs para la migraciÃ³n
// del array legacy.
const TIMELINE_VALID_CATEGORIES = ["orders", "members", "nfc", "posts", "emails", "system", "security", "stock"];
const TIMELINE_VALID_SEVERITIES = ["info", "warning", "critical"];
const TIMELINE_VALID_ACTORS = ["admin", "worker", "customer", "cron"];
const TIMELINE_RETENTION_DAYS = 90;

function timelineRandomSuffix() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < 6; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}
__name(timelineRandomSuffix, "timelineRandomSuffix");

async function writeTimelineEvent(env, event) {
  const timestamp = event.timestamp || new Date().toISOString();
  const category = TIMELINE_VALID_CATEGORIES.includes(event.category) ? event.category : "system";
  const severity = TIMELINE_VALID_SEVERITIES.includes(event.severity) ? event.severity : "info";
  const actor = TIMELINE_VALID_ACTORS.includes(event.actor) ? event.actor : "worker";
  const dateStr = timestamp.slice(0, 10).replace(/-/g, "");
  const epochMs = new Date(timestamp).getTime();
  const key = `timeline_${dateStr}_${epochMs}_${timelineRandomSuffix()}`;
  const fullEvent = {
    id: crypto.randomUUID(),
    category,
    // type: slug corto (customer_edited, tag_added...) para filtrar en UI,
    // distinto de title (texto humano). Estaba en el diseÃ±o original de
    // Paso 4 y se cayÃ³ de la recapitulaciÃ³n de la decisiÃ³n confirmada â€”
    // lo restauro porque los eventos concretos pedidos (customer_edited,
    // tag_added, etc.) no tienen dÃ³nde vivir sin Ã©l.
    type: event.type || null,
    severity,
    actor,
    customer_id: event.customer_id ?? null,
    order_id: event.order_id ?? null,
    related_entity: event.related_entity ?? null,
    title: event.title,
    details: event.details ?? null,
    timestamp,
    metadata: event.metadata ?? null
  };
  await env.POTISSE_NFC.put(key, JSON.stringify(fullEvent), {
    expirationTtl: TIMELINE_RETENTION_DAYS * 24 * 60 * 60
  });
  return fullEvent;
}
__name(writeTimelineEvent, "writeTimelineEvent");

// Volumen bajo pre-launch (mismo patrÃ³n que listAllKeysWithPrefix en otros
// handlers): escaneo completo del prefijo timeline_ + filtrado en memoria,
// en vez de depender de rangos nativos de KV list (no existen).
async function getTimelineEvents(env, opts = {}) {
  const { from, to, categories, severity, customer_id, search, limit, cursor } = opts;
  const keys = await listAllKeysWithPrefix(env, "timeline_");
  let events = [];
  for (const key of keys) {
    const raw = await env.POTISSE_NFC.get(key.name);
    if (!raw) continue;
    try {
      events.push(JSON.parse(raw));
    } catch {}
  }
  if (from) events = events.filter((e) => new Date(e.timestamp).getTime() >= new Date(from).getTime());
  if (to) events = events.filter((e) => new Date(e.timestamp).getTime() <= new Date(to).getTime());
  if (categories && categories.length) events = events.filter((e) => categories.includes(e.category));
  if (severity) events = events.filter((e) => e.severity === severity);
  if (customer_id) events = events.filter((e) => e.customer_id === customer_id);
  if (search) {
    const needle = search.toLowerCase();
    events = events.filter((e) =>
      (e.title || "").toLowerCase().includes(needle) || (e.details || "").toLowerCase().includes(needle));
  }
  events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const offset = cursor ? parseInt(cursor, 10) || 0 : 0;
  const pageSize = limit || events.length;
  const page = events.slice(offset, offset + pageSize);
  const nextCursor = offset + pageSize < events.length ? String(offset + pageSize) : null;

  return { events: page, cursor: nextCursor, total: events.length };
}
__name(getTimelineEvents, "getTimelineEvents");

async function handleAdminHealthTimeline(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const days = Number(url.searchParams.get("days")) || 7;
  const from = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result = await getTimelineEvents(env, {
    from,
    categories: url.searchParams.get("categories")?.split(",").filter(Boolean),
    severity: url.searchParams.get("severity") || undefined,
    limit: Number(url.searchParams.get("limit")) || undefined,
    cursor: url.searchParams.get("cursor") || undefined
  });
  return new Response(JSON.stringify({ ok: true, events: result.events }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminHealthTimeline, "handleAdminHealthTimeline");

// â”€â”€ 9.2.12/9.2.13: Checklist pedido â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// NOTA: el encargo mostraba solo 4 pasos explÃ­citos seguidos de "..."
// (verify_data, email_customer_if_doubts, customer_data_kv, nfc_programmed).
// Uso esos 4 como default â€” la lista completa de pasos del protocolo real
// queda pendiente de que Fran la confirme.
const CHECKLIST_DEFAULT_STEPS = [
  "verify_data",
  "email_customer_if_doubts",
  "wait_customer_reply",
  "resolve_doubt",
  "customer_data_kv",
  "nfc_programmed",
  "nfc_linked",
  "packaging_prepared",
  "garment_confirmed",
  "gls_label_printed",
  "editorial_envelope",
  "shopify_marked_sent",
  "final_timestamp"
];

function buildDefaultChecklist() {
  const now = new Date().toISOString();
  return {
    steps: CHECKLIST_DEFAULT_STEPS.map((step) => ({ step_id: step, completed: false, timestamp: null, notes: null })),
    created_at: now,
    last_updated: now
  };
}
__name(buildDefaultChecklist, "buildDefaultChecklist");

async function handleAdminChecklistGet(request, env, url, orderId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const key = `order_${orderId}_checklist`;
  const raw = await env.POTISSE_NFC.get(key);
  let checklist;
  if (raw) {
    checklist = JSON.parse(raw);
  } else {
    checklist = buildDefaultChecklist();
    await env.POTISSE_NFC.put(key, JSON.stringify(checklist));
  }
  return new Response(JSON.stringify({ ok: true, order_id: orderId, steps: checklist.steps }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminChecklistGet, "handleAdminChecklistGet");

async function handleAdminChecklistStep(request, env, url, orderId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const { step_id, completed, notes } = body || {};
  if (!step_id || typeof completed !== "boolean") {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const key = `order_${orderId}_checklist`;
  const raw = await env.POTISSE_NFC.get(key);
  const checklist = raw ? JSON.parse(raw) : buildDefaultChecklist();

  const stepIndex = checklist.steps.findIndex((s) => s.step_id === step_id);
  if (stepIndex === -1) {
    return new Response(JSON.stringify({ error: "invalid_step_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  // "NingÃºn paso se puede saltar sin confirmar el anterior"
  if (completed && stepIndex > 0 && !checklist.steps[stepIndex - 1].completed) {
    return new Response(JSON.stringify({ error: "previous_step_not_completed" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  checklist.steps[stepIndex].completed = completed;
  checklist.steps[stepIndex].timestamp = completed ? new Date().toISOString() : null;
  checklist.steps[stepIndex].notes = notes || null;
  checklist.last_updated = new Date().toISOString();

  await env.POTISSE_NFC.put(key, JSON.stringify(checklist));

  return new Response(JSON.stringify({ ok: true, order_id: orderId, steps: checklist.steps }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminChecklistStep, "handleAdminChecklistStep");


// â”€â”€ Incidences â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleAdminMemberIncidencesGet(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);
  const key = `customer_${customerId}_incidences`;
  const raw = await env.POTISSE_NFC.get(key);
  const incidences = raw ? JSON.parse(raw) : [];
  return new Response(JSON.stringify({ ok: true, incidences }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMemberIncidencesGet, "handleAdminMemberIncidencesGet");

async function handleAdminMemberIncidencesPost(request, env, url, customerIdParam) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const { type, severity, title, description, order_id, piece_id } = body || {};
  if (!type || !severity || !title) {
    return new Response(JSON.stringify({ error: "missing_fields" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const validTypes = ["defect", "delay", "lost", "return", "other", "complaint", "silencio", "access_alert"];
  const validSeverities = ["low", "medium", "high", "critical"];
  if (!validTypes.includes(type) || !validSeverities.includes(severity)) {
    return new Response(JSON.stringify({ error: "invalid_enum" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const now = new Date().toISOString();
  const incidence = {
    incidence_id: crypto.randomUUID(),
    customer_id: customerId,
    type,
    severity,
    title: String(title).trim(),
    description: description ? String(description).trim() : null,
    status: "open",
    created_at: now,
    updated_at: now,
    resolved_at: null,
    resolved_by: null,
    assigned_to: null,
    order_id: order_id || null,
    piece_id: piece_id || null
  };

  const key = `customer_${customerId}_incidences`;
  const raw = await env.POTISSE_NFC.get(key);
  const incidences = raw ? JSON.parse(raw) : [];
  incidences.unshift(incidence);
  await env.POTISSE_NFC.put(key, JSON.stringify(incidences));

  await writeTimelineEvent(env, {
    category: "members",
    severity: severity === "critical" ? "critical" : "warning",
    actor: "admin",
    customer_id: customerId,
    type: "incidence_created",
    title: `Incidence registered: ${incidence.title}`,
    details: incidence.description,
    metadata: { incidence_id: incidence.incidence_id, type, severity, order_id, piece_id }
  });

  // Push 5.5: alerta email para incidencias crÃ­ticas
  if (severity === "critical") {
    const profileRawAlert = await env.POTISSE_NFC.get(`customer_${customerId}_profile`);
    let alertCustomerName = "";
    if (profileRawAlert) {
      try {
        const pAlert = JSON.parse(profileRawAlert);
        alertCustomerName = `${pAlert.first_name || ""} ${pAlert.last_name || ""}`.trim();
      } catch {}
    }
    await sendCriticalIncidenceAlert(env, incidence, alertCustomerName);
  }

  return new Response(JSON.stringify({ ok: true, incidence }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMemberIncidencesPost, "handleAdminMemberIncidencesPost");

// ── Helper: create incidence from access alert (C.4) ──
async function createIncidenceFromAlert(env, alertEntry, title, description, type = "access_alert", severity = "medium") {
  const customerId = alertEntry.customer_id;
  const now = new Date().toISOString();
  const incidence = {
    incidence_id: crypto.randomUUID(),
    customer_id: customerId,
    type,
    severity,
    title: String(title).trim(),
    description: description ? String(description).trim() : null,
    status: "open",
    created_at: now,
    updated_at: now,
    resolved_at: null,
    resolved_by: null,
    assigned_to: null,
    order_id: alertEntry.order_id || null,
    piece_id: alertEntry.piece_id || null,
    source: "access_alert"
  };

  const key = `customer_${customerId}_incidences`;
  const raw = await env.POTISSE_NFC.get(key);
  const incidences = raw ? JSON.parse(raw) : [];
  incidences.unshift(incidence);
  await env.POTISSE_NFC.put(key, JSON.stringify(incidences));

  await writeTimelineEvent(env, {
    category: "members",
    severity: "warning",
    actor: "admin",
    customer_id: customerId,
    type: "incidence_created_from_alert",
    title: `Access alert converted to incidence: ${incidence.title}`,
    details: incidence.description,
    metadata: { incidence_id: incidence.incidence_id, alert_order_id: alertEntry.order_id, alert_piece_id: alertEntry.piece_id }
  });

  return incidence;
}
__name(createIncidenceFromAlert, "createIncidenceFromAlert");

async function handleAdminMemberIncidenceResolve(request, env, url, customerIdParam, incidenceId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);
  const key = `customer_${customerId}_incidences`;
  const raw = await env.POTISSE_NFC.get(key);
  if (!raw) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404, headers: { "Content-Type": "application/json" }
    });
  }
  const incidences = JSON.parse(raw);
  const idx = incidences.findIndex(i => i.incidence_id === incidenceId);
  if (idx === -1) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404, headers: { "Content-Type": "application/json" }
    });
  }

  const now = new Date().toISOString();
  incidences[idx].status = "resolved";
  incidences[idx].resolved_at = now;
  incidences[idx].updated_at = now;
  incidences[idx].resolved_by = "admin";

  await env.POTISSE_NFC.put(key, JSON.stringify(incidences));

  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "admin",
    customer_id: customerId,
    type: "incidence_resolved",
    title: `Incidence resolved: ${incidences[idx].title}`,
    metadata: { incidence_id: incidenceId }
  });

  return new Response(JSON.stringify({ ok: true, incidence: incidences[idx] }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMemberIncidenceResolve, "handleAdminMemberIncidenceResolve");




async function handleAdminMemberIncidenceEdit(request, env, url, customerIdParam, incidenceId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const customerId = Number(customerIdParam);
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_body" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }
  const key = `customer_${customerId}_incidences`;
  const raw = await env.POTISSE_NFC.get(key);
  if (!raw) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404, headers: { "Content-Type": "application/json" }
    });
  }
  const incidences = JSON.parse(raw);
  const idx = incidences.findIndex(i => i.incidence_id === incidenceId);
  if (idx === -1) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404, headers: { "Content-Type": "application/json" }
    });
  }
  const validEditTypes = ["defect", "delay", "lost", "return", "other", "complaint", "silencio"];
  const validEditSeverities = ["low", "medium", "high", "critical"];
  const editable = ["type", "severity", "title", "description", "order_id", "piece_id", "assigned_to"];
  let changed = false;
  for (const field of editable) {
    if (body[field] !== undefined) {
      if (field === "type" && !validEditTypes.includes(body[field])) continue;
      if (field === "severity" && !validEditSeverities.includes(body[field])) continue;
      incidences[idx][field] = body[field];
      changed = true;
    }
  }
  if (!changed) {
    return new Response(JSON.stringify({ ok: true, incidence: incidences[idx] }), {
      status: 200, headers: { "Content-Type": "application/json" }
    });
  }
  incidences[idx].updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put(key, JSON.stringify(incidences));
  await writeTimelineEvent(env, {
    category: "members",
    severity: "info",
    actor: "admin",
    customer_id: customerId,
    type: "incidence_edited",
    title: `Incidence edited: ${incidences[idx].title}`,
    metadata: { incidence_id: incidenceId }
  });
  return new Response(JSON.stringify({ ok: true, incidence: incidences[idx] }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminMemberIncidenceEdit, "handleAdminMemberIncidenceEdit");

// â”€â”€ Incidence critical alert â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function sendCriticalIncidenceAlert(env, incidence, customerName) {
  const payload = {
    from: "POTISSE System <club@potisse.com>",
    to: ["backend@potisse.com"],
    subject: `URGENT: Critical incidence â€” ${incidence.title}`,
    html: `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="background:#0E0D0C;color:#F2F1ED;padding:48px 24px;margin:0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.7;">
<div style="max-width:480px;margin:0 auto;border-left:2px solid #B8863D;padding-left:24px;">
  <p style="font-size:11px;letter-spacing:4px;text-transform:uppercase;color:#B8863D;margin:0 0 24px 0;">POTISSE Alert</p>
  <h1 style="font-size:18px;font-weight:400;margin:0 0 16px 0;">Critical incidence registered</h1>
  <p style="margin:0 0 8px 0;"><strong>Customer:</strong> ${escapeHtml(customerName || 'Unknown')} (ID: ${incidence.customer_id})</p>
  <p style="margin:0 0 8px 0;"><strong>Title:</strong> ${escapeHtml(incidence.title)}</p>
  <p style="margin:0 0 8px 0;"><strong>Type:</strong> ${escapeHtml(incidence.type)}</p>
  <p style="margin:0 0 8px 0;"><strong>Severity:</strong> ${escapeHtml(incidence.severity)}</p>
  <p style="margin:0 0 24px 0;opacity:0.7;">${escapeHtml(incidence.description || 'No description.')}</p>
  <p style="font-size:11px;opacity:0.4;margin:0;">â€” POTISSE System Â· ${new Date().toISOString()}</p>
</div>
</body></html>`,
    text: `CRITICAL INCIDENCE\n\nCustomer: ${customerName || 'Unknown'} (ID: ${incidence.customer_id})\nTitle: ${incidence.title}\nType: ${incidence.type}\nSeverity: ${incidence.severity}\nDescription: ${incidence.description || 'N/A'}\n\nâ€” POTISSE System`
  };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.text();
      console.error(`Critical incidence alert failed: ${res.status} ${err}`);
    } else {
      console.log(`Critical incidence alert sent for customer ${incidence.customer_id}`);
    }
  } catch (err) {
    console.error(`Critical incidence alert threw: ${err.message}`);
  }
}
__name(sendCriticalIncidenceAlert, "sendCriticalIncidenceAlert");


// â”€â”€ Incidences stats (sidebar badge) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleAdminIncidencesStats(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const list = await env.POTISSE_NFC.list({ prefix: "customer_" });
  const incidenceKeys = list.keys.filter(k => k.name.endsWith("_incidences"));
  let open = 0;
  let critical = 0;
  for (const k of incidenceKeys) {
    const raw = await env.POTISSE_NFC.get(k.name);
    if (!raw) continue;
    const arr = JSON.parse(raw);
    for (const inc of arr) {
      if (inc.status === "open") {
        open++;
        if (inc.severity === "critical") critical++;
      }
    }
  }
  let accessAlerts = 0;
  try {
    const alertsRaw = await env.POTISSE_NFC.get("access_alerts_active");
    if (alertsRaw) {
      const alerts = JSON.parse(alertsRaw);
      accessAlerts = (alerts.iberian?.length || 0) + (alerts.european?.length || 0);
    }
  } catch {}

  return new Response(JSON.stringify({ ok: true, open, critical, access_alerts: accessAlerts, total: open + accessAlerts }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminIncidencesStats, "handleAdminIncidencesStats");

// â”€â”€ Incidences (global list) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleAdminIncidencesList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }
  const limit = Number(url.searchParams.get("limit")) || 50;
  const cursorParam = url.searchParams.get("cursor");
  const offset = cursorParam ? parseInt(cursorParam, 10) || 0 : 0;

  const list = await env.POTISSE_NFC.list({ prefix: "customer_" });
  const incidenceKeys = list.keys.filter(k => k.name.endsWith("_incidences"));

  const all = [];
  const profilePromises = [];

  for (const k of incidenceKeys) {
    const raw = await env.POTISSE_NFC.get(k.name);
    if (!raw) continue;
    const arr = JSON.parse(raw);
    const customerIdMatch = k.name.match(/^customer_(\d+)_incidences$/);
    const customerId = customerIdMatch ? Number(customerIdMatch[1]) : null;
    for (const inc of arr) {
      all.push({ ...inc, customer_id: customerId });
      if (customerId) {
        profilePromises.push(
          env.POTISSE_NFC.get(`customer_${customerId}_profile`).then(r => {
            if (!r) return { customer_id: customerId, name: `Customer ${customerId}` };
            const p = JSON.parse(r);
            const first = p.identity?.first_name || p.first_name || '';
            const last = p.identity?.last_name || p.last_name || '';
            return { customer_id: customerId, name: `${first} ${last}`.trim() || `Customer ${customerId}` };
          }).catch(() => ({ customer_id: customerId, name: `Customer ${customerId}` }))
        );
      }
    }
  }

  const profiles = await Promise.all(profilePromises);
  const nameMap = {};
  for (const p of profiles) nameMap[p.customer_id] = p.name;
  for (const inc of all) {
    inc.customer_name = nameMap[inc.customer_id] || `Customer ${inc.customer_id}`;
  }

  all.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const page = all.slice(offset, offset + limit);
  const nextCursor = offset + limit < all.length ? String(offset + limit) : null;

  return new Response(JSON.stringify({ ok: true, incidences: page, cursor: nextCursor, total: all.length }), {
    status: 200, headers: { "Content-Type": "application/json" }
  });
}
__name(handleAdminIncidencesList, "handleAdminIncidencesList");


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// FASE A â€” TOTP Admin
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const TOTP_ALGORITHM = "SHA-1";
const TOTP_WINDOW = 1;
const TOTP_SESSION_MINUTES = 15;

function base32Encode(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}
__name(base32Encode, "base32Encode");

function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const map = {};
  for (let i = 0; i < alphabet.length; i++) map[alphabet[i]] = i;
  let bits = 0, value = 0;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str[i].toUpperCase();
    if (!(c in map)) continue;
    value = (value << 5) | map[c];
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
__name(base32Decode, "base32Decode");

async function generateTOTP(secretBase32, timestamp) {
  const secretBytes = base32Decode(secretBase32);
  const ts = timestamp != null ? timestamp : Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(ts / TOTP_PERIOD);
  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  timeView.setUint32(4, timeStep, false);
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: TOTP_ALGORITHM }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new Uint8Array(timeBuffer));
  const hash = new Uint8Array(signature);
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff)) >>> 0;
  const str = String(code % Math.pow(10, TOTP_DIGITS));
  return str.padStart(TOTP_DIGITS, "0");
}
__name(generateTOTP, "generateTOTP");

async function verifyTOTP(secretBase32, code, env) {
  const now = Math.floor(Date.now() / 1000);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const expected = await generateTOTP(secretBase32, now + i * TOTP_PERIOD);
    if (expected === code) {
      // Replay protection: reject if this code was used in the last 90s
      if (env) {
        const codeHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(expected));
        const hashHex = Array.from(new Uint8Array(codeHash)).map(b => b.toString(16).padStart(2, '0')).join('');
        const kvKey = `totp_used_${hashHex}`;
        const existing = await env.POTISSE_NFC.get(kvKey);
        if (existing) return { valid: false, reason: "code_already_used" };
        await env.POTISSE_NFC.put(kvKey, "1", { expirationTtl: 90 });
      }
      return { valid: true };
    }
  }
  return { valid: false };
}
__name(verifyTOTP, "verifyTOTP");

function generateTOTPSecret() {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}
__name(generateTOTPSecret, "generateTOTPSecret");

function generateRecoveryCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 12; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
    if (i === 3 || i === 7) code += "-";
  }
  return code;
}
__name(generateRecoveryCode, "generateRecoveryCode");

async function signTOTPJwt(payload, secret) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const message = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, "");
  return `${message}.${sigBase64}`;
}
__name(signTOTPJwt, "signTOTPJwt");

async function verifyTOTPJwt(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const message = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expectedSig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  const expectedBase64 = btoa(String.fromCharCode(...new Uint8Array(expectedSig))).replace(/=/g, "");
  if (signature !== expectedBase64) return null;
  try { return JSON.parse(atob(body)); } catch { return null; }
}
__name(verifyTOTPJwt, "verifyTOTPJwt");

function buildTOTPSessionCookie(token) {
  return `__Host-totp_session=${token}; Path=/; Max-Age=${TOTP_SESSION_MINUTES * 60}; HttpOnly; Secure; SameSite=Strict`;
}
__name(buildTOTPSessionCookie, "buildTOTPSessionCookie");

function parseTOTPCookie(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/__Host-totp_session=([^;]+)/);
  return match ? match[1] : null;
}
__name(parseTOTPCookie, "parseTOTPCookie");

async function getActiveTOTPSecret(env) {
  if (env.TOTP_SECRET) return env.TOTP_SECRET;
  return await env.POTISSE_NFC.get("system:totp_secret");
}
__name(getActiveTOTPSecret, "getActiveTOTPSecret");

async function setTOTPSecret(env, secret) {
  await env.POTISSE_NFC.put("system:totp_secret", secret);
}
__name(setTOTPSecret, "setTOTPSecret");

async function requireTOTP(request, env, ctx, options) {
  const { critical = false } = options || {};
  const url = new URL(request.url);

  // Hallazgo 5: X-Admin-Key header first, fallback to query param (7-day backward compat)
  const adminKeyHeader = request.headers.get("X-Admin-Key");
  const adminKeyQuery = url.searchParams.get("admin");
  const providedKey = adminKeyHeader || adminKeyQuery;

  const adminKeyMatch = await timingSafeStringEqual(providedKey, env.ADMIN_KEY);
  if (!adminKeyMatch) {
    return { ok: false, response: new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } }) };
  }

  // Warn on legacy query param usage
  if (adminKeyQuery && !adminKeyHeader) {
    console.warn(`[security] ADMIN_KEY via query param used on ${url.pathname}`);
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(writeTimelineEvent(env, {
        category: "security",
        severity: "info",
        actor: "worker",
        title: "Legacy admin key usage",
        details: `Endpoint ${url.pathname} received ADMIN_KEY via query parameter`,
        metadata: { endpoint: url.pathname, ip: request.headers.get("cf-connecting-ip") || "unknown" }
      }));
    }
  }

  const secret = await getActiveTOTPSecret(env);
  if (!secret) {
    return { ok: true };
  }
  const totpCode = request.headers.get("X-TOTP-Code");
  if (critical) {
    if (!totpCode) {
      return { ok: false, response: new Response(JSON.stringify({ error: "totp_required", critical: true, message: "This action requires a TOTP code" }), { status: 403, headers: { "Content-Type": "application/json" } }) };
    }
    const totpResult = await verifyTOTP(secret, totpCode, env);
    if (!totpResult.valid) {
      // Hallazgo 3+11: Timeline event on TOTP rejection
      if (ctx && ctx.waitUntil) {
        ctx.waitUntil(writeTimelineEvent(env, {
          category: "security",
          severity: "warning",
          actor: "worker",
          title: "TOTP rejected",
          details: `TOTP ${totpResult.reason || "invalid"} on ${url.pathname}`,
          metadata: { endpoint: url.pathname, ip: request.headers.get("cf-connecting-ip") || "unknown", reason: totpResult.reason || "invalid" }
        }));
      }
      return { ok: false, response: new Response(JSON.stringify({ error: totpResult.reason || "invalid_totp" }), { status: 403, headers: { "Content-Type": "application/json" } }) };
    }
    return { ok: true };
  }
  if (totpCode) {
    const totpResult = await verifyTOTP(secret, totpCode, env);
    if (totpResult.valid) return { ok: true, refreshSession: true };
    // Hallazgo 3+11: Timeline event on TOTP rejection
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(writeTimelineEvent(env, {
        category: "security",
        severity: "warning",
        actor: "worker",
        title: "TOTP rejected",
        details: `TOTP ${totpResult.reason || "invalid"} on ${url.pathname}`,
        metadata: { endpoint: url.pathname, ip: request.headers.get("cf-connecting-ip") || "unknown", reason: totpResult.reason || "invalid" }
      }));
    }
    return { ok: false, response: new Response(JSON.stringify({ error: totpResult.reason || "invalid_totp" }), { status: 403, headers: { "Content-Type": "application/json" } }) };
  }
  const sessionToken = parseTOTPCookie(request);
  if (sessionToken) {
    const payload = await verifyTOTPJwt(sessionToken, secret);
    if (payload && payload.exp > Date.now()) {
      return { ok: true, refreshSession: true };
    }
  }
  return { ok: false, response: new Response(JSON.stringify({ error: "totp_required", critical: false, message: "TOTP session expired or missing" }), { status: 403, headers: { "Content-Type": "application/json" } }) };
}
__name(requireTOTP, "requireTOTP");

async function withTOTPRefresh(response, env, totpCheck) {
  if (totpCheck && totpCheck.refreshSession) {
    const secret = await getActiveTOTPSecret(env);
    if (secret) {
      const newToken = await signTOTPJwt({ exp: Date.now() + TOTP_SESSION_MINUTES * 60 * 1000 }, secret);
      const headers = new Headers(response.headers);
      headers.append("Set-Cookie", buildTOTPSessionCookie(newToken));
      return new Response(response.body, { status: response.status, headers });
    }
  }
  return response;
}
__name(withTOTPRefresh, "withTOTPRefresh");

// â”€â”€ TOTP Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function handleAdminTOTPStatus(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const secret = await getActiveTOTPSecret(env);
  if (!secret) {
    return new Response(JSON.stringify({ configured: false, setup_needed: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  const sessionToken = parseTOTPCookie(request);
  let sessionValid = false;
  if (sessionToken) {
    const payload = await verifyTOTPJwt(sessionToken, secret);
    sessionValid = payload && payload.exp > Date.now();
  }
  return new Response(JSON.stringify({ configured: true, session_valid: sessionValid }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminTOTPStatus, "handleAdminTOTPStatus");

async function handleAdminTOTPSetup(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const existingSecret = await getActiveTOTPSecret(env);
  if (existingSecret) {
    return new Response(JSON.stringify({ error: "already_configured" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  const secret = generateTOTPSecret();
  const recoveryCode = generateRecoveryCode();
  await setTOTPSecret(env, secret);
  await env.POTISSE_NFC.put("system:totp_recovery_code", recoveryCode);
  const qrUrl = `otpauth://totp/POTISSE%20Workshop%20Tools:Fran?secret=${secret}&issuer=POTISSE&algorithm=SHA1&digits=6&period=30`;
  const sessionToken = await signTOTPJwt({ exp: Date.now() + TOTP_SESSION_MINUTES * 60 * 1000 }, secret);
  return new Response(JSON.stringify({ ok: true, secret, recovery_code: recoveryCode, qr_url: qrUrl }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": buildTOTPSessionCookie(sessionToken) }
  });
}
__name(handleAdminTOTPSetup, "handleAdminTOTPSetup");

async function handleAdminTOTPVerify(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const secret = await getActiveTOTPSecret(env);
  if (!secret) {
    return new Response(JSON.stringify({ error: "not_configured" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  let body;
  try { body = await request.json(); } catch { return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } }); }
  const { code } = body || {};
  if (!code) return new Response(JSON.stringify({ error: "missing_code" }), { status: 400, headers: { "Content-Type": "application/json" } });
  const valid = await verifyTOTP(secret, code);
  if (!valid) return new Response(JSON.stringify({ error: "invalid_code" }), { status: 403, headers: { "Content-Type": "application/json" } });
  const sessionToken = await signTOTPJwt({ exp: Date.now() + TOTP_SESSION_MINUTES * 60 * 1000 }, secret);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": buildTOTPSessionCookie(sessionToken) } });
}
__name(handleAdminTOTPVerify, "handleAdminTOTPVerify");

async function handleAdminTOTPReset(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  let body;
  try { body = await request.json(); } catch { return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } }); }
  const { recovery_code } = body || {};
  if (!recovery_code) return new Response(JSON.stringify({ error: "missing_recovery_code" }), { status: 400, headers: { "Content-Type": "application/json" } });
  const storedCode = await env.POTISSE_NFC.get("system:totp_recovery_code");
  if (storedCode !== recovery_code) return new Response(JSON.stringify({ error: "invalid_recovery_code" }), { status: 403, headers: { "Content-Type": "application/json" } });
  await env.POTISSE_NFC.delete("system:totp_secret");
  await env.POTISSE_NFC.delete("system:totp_recovery_code");
  const secret = generateTOTPSecret();
  const newRecoveryCode = generateRecoveryCode();
  await setTOTPSecret(env, secret);
  await env.POTISSE_NFC.put("system:totp_recovery_code", newRecoveryCode);
  const qrUrl = `otpauth://totp/POTISSE%20Workshop%20Tools:Fran?secret=${secret}&issuer=POTISSE&algorithm=SHA1&digits=6&period=30`;
  const sessionToken = await signTOTPJwt({ exp: Date.now() + TOTP_SESSION_MINUTES * 60 * 1000 }, secret);
  return new Response(JSON.stringify({ ok: true, secret, recovery_code: newRecoveryCode, qr_url: qrUrl }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": buildTOTPSessionCookie(sessionToken) }
  });
}
__name(handleAdminTOTPReset, "handleAdminTOTPReset");


async function handleAdminTOTPDisable(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const secret = await getActiveTOTPSecret(env);
  if (!secret) {
    return new Response(JSON.stringify({ error: "not_configured" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  let body;
  try { body = await request.json(); } catch { return new Response(JSON.stringify({ error: "invalid_body" }), { status: 400, headers: { "Content-Type": "application/json" } }); }
  const { code } = body || {};
  if (!code) return new Response(JSON.stringify({ error: "missing_code" }), { status: 400, headers: { "Content-Type": "application/json" } });
  const valid = await verifyTOTP(secret, code);
  if (!valid) return new Response(JSON.stringify({ error: "invalid_code" }), { status: 403, headers: { "Content-Type": "application/json" } });
  await env.POTISSE_NFC.delete("system:totp_secret");
  await env.POTISSE_NFC.delete("system:totp_recovery_code");
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminTOTPDisable, "handleAdminTOTPDisable");

async function handleAdminTOTPForceReset(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  await env.POTISSE_NFC.delete("system:totp_secret");
  await env.POTISSE_NFC.delete("system:totp_recovery_code");
  return new Response(JSON.stringify({ ok: true, message: "TOTP reset. Setup again from Settings." }), { status: 200, headers: { "Content-Type": "application/json" } });
}
__name(handleAdminTOTPForceReset, "handleAdminTOTPForceReset");


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// R2 upload-snapshot endpoint
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const R2_PUBLIC_URL = "https://pub-b78965cde2fb4191a12db2238e97dcaf.r2.dev";

// ── C.2 Orders Push A ──
async function handleAdminOrdersList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const status = url.searchParams.get("status") || "any";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 250);

  try {
    const shopifyUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/orders.json?status=${encodeURIComponent(status)}&limit=${limit}&fields=id,name,order_number,created_at,financial_status,fulfillment_status,total_price,customer,line_items`;
    const res = await fetch(shopifyUrl, {
      headers: {
        "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
      }
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error("[orders/list] Shopify error:", res.status, errText);
      return jsonResponse({ error: "shopify_error", status: res.status }, 502);
    }
    const data = await res.json();
    return jsonResponse({ orders: data.orders || [] });
  } catch (err) {
    console.error("[orders/list] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}

async function handleAdminOrderGet(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const match = url.pathname.match(/^\/api\/admin\/orders\/(\d+)$/);
  const orderId = match ? match[1] : null;
  if (!orderId) {
    return jsonResponse({ error: "invalid_order_id" }, 400);
  }

  try {
    const shopifyUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/orders/${orderId}.json`;
    const res = await fetch(shopifyUrl, {
      headers: {
        "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
      }
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error("[order/get] Shopify error:", res.status, errText);
      return jsonResponse({ error: "shopify_error", status: res.status }, 502);
    }
    const data = await res.json();
    return jsonResponse({ order: data.order });
  } catch (err) {
    console.error("[order/get] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}

async function handleAdminOrderFulfill(request, env, url) {
  const adminKeyHeader = request.headers.get("X-Admin-Key");
  const adminKeyQuery = url.searchParams.get("admin");
  const providedKey = adminKeyHeader || adminKeyQuery;
  if (!providedKey || !(await timingSafeStringEqual(providedKey, env.ADMIN_KEY))) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  const match = url.pathname.match(/^\/api\/admin\/orders\/(\d+)\/fulfill$/);
  const orderId = match ? match[1] : null;
  if (!orderId) {
    return jsonResponse({ error: "invalid_order_id" }, 400);
  }

  try {
    // 1) Leer orden para saber qué líneas fulfillar
    const getUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/orders/${orderId}.json`;
    const getRes = await fetch(getUrl, {
      headers: {
        "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
      }
    });
    if (!getRes.ok) {
      const errText = await getRes.text();
      console.error("[order/fulfill] Shopify get error:", getRes.status, errText);
      return jsonResponse({ error: "shopify_error", status: getRes.status }, 502);
    }
    const orderData = await getRes.json();
    const order = orderData.order;

    const lineItems = (order.line_items || []).map(item => ({
      id: item.id,
      quantity: item.fulfillable_quantity || item.quantity
    })).filter(item => item.quantity > 0);

    if (lineItems.length === 0) {
      return jsonResponse({ error: "nothing_to_fulfill" }, 400);
    }

    // 2) Crear fulfillment
    const fulfillUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01/orders/${orderId}/fulfillments.json`;
    const payload = {
      fulfillment: {
        line_items: lineItems
      }
    };
    if (env.SHOPIFY_LOCATION_ID) {
      payload.fulfillment.location_id = parseInt(env.SHOPIFY_LOCATION_ID, 10);
    }

    const fulfillRes = await fetch(fulfillUrl, {
      method: "POST",
      headers: {
        "X-Shopify-Access-Token": env.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!fulfillRes.ok) {
      const errText = await fulfillRes.text();
      console.error("[order/fulfill] Shopify fulfill error:", fulfillRes.status, errText);
      return jsonResponse({ error: "shopify_error", status: fulfillRes.status, details: errText }, 502);
    }

    const fulfillData = await fulfillRes.json();
    return jsonResponse({ ok: true, fulfillment: fulfillData.fulfillment });
  } catch (err) {
    console.error("[order/fulfill] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}

async function handleUploadSnapshot(request, env, url) {
  try {
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405, headers: { "Content-Type": "application/json" }
      });
    }
    // v6.9.2-fix: soportar key via query param, X-Admin-Key header, o Authorization Bearer
    const adminKeyQuery = url.searchParams.get("admin");
    const adminKeyHeader = request.headers.get("X-Admin-Key");
    const authHeader = request.headers.get("Authorization") || "";
    const bearerKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    const providedKey = adminKeyQuery || adminKeyHeader || bearerKey;
    if (providedKey !== env.ADMIN_KEY) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json" }
      });
    }

    const contentType = request.headers.get("Content-Type") || "";
    let fileBuffer;
    let fileName = "snapshot.zip";

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file");
      if (!file || typeof file === "string" || !file.type) {
        return new Response(JSON.stringify({ error: "No file provided" }), {
          status: 400, headers: { "Content-Type": "application/json" }
        });
      }
      fileBuffer = await file.arrayBuffer();
      fileName = file.name || fileName;
    } else {
      fileBuffer = await request.arrayBuffer();
      fileName = url.searchParams.get("filename") || fileName;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const uuid = crypto.randomUUID();
    const key = `snapshots/${timestamp}-${uuid}-${fileName}`;

    await env.SNAPSHOT_BUCKET.put(key, fileBuffer, {
      httpMetadata: {
        contentType: "application/zip",
        contentDisposition: `attachment; filename="${fileName}"`
      },
      customMetadata: {
        uploadedBy: "admin",
        uploadedAt: new Date().toISOString()
      }
    });

    const publicUrl = `${R2_PUBLIC_URL}/${key}`;

    return new Response(JSON.stringify({
      success: true,
      key,
      url: publicUrl,
      size: fileBuffer.byteLength
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  } catch (err) {
    return new Response(JSON.stringify({
      error: err.message,
      stack: err.stack
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleUploadSnapshot, "handleUploadSnapshot");

var worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Hallazgo 5: normalize X-Admin-Key header into query param for backward compat
    const adminKeyHeader = request.headers.get("X-Admin-Key");
    if (adminKeyHeader && !url.searchParams.get("admin")) {
      url.searchParams.set("admin", adminKeyHeader);
    }
    console.log(`[WORKER] ${request.method} ${url.pathname}`);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Auth-Token"
    };
    if (request.method === "OPTIONS") {
      if (url.pathname.startsWith("/api/club/")) {
        return new Response(null, { headers: clubCorsHeaders(request) });
      }
      return new Response(null, { headers: corsHeaders });
    }
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // v6.9.0 â€” Global TOTP middleware for POST/PUT /api/admin/*
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    const TOTP_CRITICAL_PATHS = [
      /^\/api\/admin\/nfc-card$/,
      /^\/api\/admin\/emergency-session$/,
      /^\/api\/admin\/system\/domain-ssl$/,
      /^\/api\/admin\/orders\/\d+\/fulfill$/,
      /^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/assign$/,
      /^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/unassign$/,
      /^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/mark-lost$/,




    ];
    function isTOTPCriticalPath(pathname) {
      return TOTP_CRITICAL_PATHS.some(pattern => pattern.test(pathname));
    }
    const TOTP_EXCLUDED_PATHS = [
      "/api/admin/totp/verify",
      "/api/admin/totp/reset",
      "/api/admin/totp/disable",
      "/api/admin/totp/force-reset",
      "/api/admin/upload-snapshot"
    ];
    let totpCheck = null;
    if ((request.method === "POST" || request.method === "PUT" || request.method === "DELETE" || request.method === "PATCH") && url.pathname.startsWith("/api/admin/")) {
      if (!TOTP_EXCLUDED_PATHS.includes(url.pathname)) {
        const secret = await getActiveTOTPSecret(env);
        if (secret) {
          const critical = isTOTPCriticalPath(url.pathname);
          totpCheck = await requireTOTP(request, env, ctx, { critical });
          if (!totpCheck.ok) {
            return totpCheck.response;
          }
        }
      }
    }

    const response = await (async () => {
      const MAKING_URL = env.MAKING_URL || "https://www.potisse.com/pages/coming-soon?view=making";
      const CLUB_URL = env.CLUB_URL || "https://www.potisse.com/pages/club";
    if (url.pathname === "/api/wash/add" && request.method === "POST") {
      console.warn(`[DEPRECATED] ${url.pathname} called - migrate to /api/club/wash. Referrer: ${request.headers.get("Referer") || "none"}. User-Agent: ${request.headers.get("User-Agent") || "none"}. Deprecation target: 30 days post-launch`);
      if (!verifyWashToken(request, env)) return new Response("Unauthorized", { status: 401 });
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response("Bad Request", { status: 400 });
      }
      const { customer_id, piece_code } = body;
      if (!customer_id || !piece_code) return new Response("Bad Request", { status: 400 });
      const result = await incrementWash(env, String(customer_id), piece_code);
      return new Response(JSON.stringify(result), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/wash/get") {
      if (!verifyWashToken(request, env)) return new Response("Unauthorized", { status: 401 });
      const customerId = url.searchParams.get("customer_id");
      const pieceCode = url.searchParams.get("piece_code");
      if (!customerId || !pieceCode) return new Response("Bad Request", { status: 400 });
      const data = await getWashData(env, customerId, pieceCode);
      return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/wash/all") {
      console.warn(`[DEPRECATED] ${url.pathname} called - migrate to /api/club/wash. Referrer: ${request.headers.get("Referer") || "none"}. User-Agent: ${request.headers.get("User-Agent") || "none"}. Deprecation target: 30 days post-launch`);
      if (!verifyWashToken(request, env)) return new Response("Unauthorized", { status: 401 });
      const customerId = url.searchParams.get("customer_id");
      if (!customerId) return new Response("Bad Request", { status: 400 });
      const prefix = `wash:${customerId}:`;
      const list = await env.POTISSE_NFC.list({ prefix });
      const result = {};
      for (const key of list.keys) {
        const pieceCode = key.name.slice(prefix.length);
        const raw = await env.POTISSE_NFC.get(key.name);
        result[pieceCode] = raw ? JSON.parse(raw) : { count: 0, last: null };
      }
      return new Response(JSON.stringify(result), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/webhook/orders-create" && request.method === "POST") {
      const rawBody = await request.arrayBuffer();
      if (env.SHOPIFY_WEBHOOK_SECRET) {
        const hmacHeader = request.headers.get("X-Shopify-Hmac-SHA256");
        const valid = await verifyShopifyHmac(rawBody, env.SHOPIFY_WEBHOOK_SECRET, hmacHeader);
        if (!valid) return new Response("Unauthorized", { status: 401 });
      }
      let order;
      try {
        order = JSON.parse(new TextDecoder().decode(rawBody));
      } catch {
        return new Response("Bad Request", { status: 400 });
      }
      const customerId = order.customer?.id;
      if (!customerId) return new Response("OK", { status: 200 });
      const processedPrefixes = /* @__PURE__ */ new Set();
      for (const item of order.line_items || []) {
        const prefix = (item.sku || "").toUpperCase().split(".")[0];
        const metafieldKey = SKU_MAP[prefix];
        if (!metafieldKey || processedPrefixes.has(prefix)) continue;
        processedPrefixes.add(prefix);
        const pieceNumber = await countOrdersWithSkuPrefix(env, prefix);
        await upsertCustomerMetafield(env, customerId, "potisse", metafieldKey, pieceNumber);
      }
      // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
      // SILENCIO 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Actualizar/crear objeto customer:{id} en KV
      // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
      try {
        await updateCustomerKvForSilencio1(env, order);
      } catch (err) {
        // Log pero NO fallar el webhook. Metafields ya se procesaron.
        console.warn("Silencio1 KV update failed:", err.message);
      }
      let piecesResult = { created: false, isMember: false };
      try {
        piecesResult = await createPiecesForOrder(env, order);
      } catch (err) {
        console.warn("Pieces creation failed:", err.message);
      }
      // Bloque B parte 2, secciÃ³n 7: solo avisar a Fran si se crearon piezas
      // NUEVAS (no en reintentos de webhook duplicado) y el cliente NO es ya
      // miembro (un miembro no necesita programar tarjeta nueva de inmediato;
      // la nueva pieza queda "arriving" y se activa sola en el fulfillment).
      if (piecesResult.created && !piecesResult.isMember) {
        try {
          await notifyFranPendingNfc(env, order);
        } catch (err) {
          console.warn("Resend NFC notification failed:", err.message);
        }
      }
      return new Response("OK", { status: 200 });
    }
    if (url.pathname === "/api/webhook/orders-fulfilled" && request.method === "POST") {
      const rawBody = await request.text();
      const hmacHeader = request.headers.get("X-Shopify-Hmac-SHA256");
      if (env.SHOPIFY_WEBHOOK_SECRET) {
        const expectedHmac = await computeHmacBase64(env.SHOPIFY_WEBHOOK_SECRET, rawBody);
        if (hmacHeader !== expectedHmac) {
          return new Response("Unauthorized", { status: 401 });
        }
      }
      let order;
      try {
        order = JSON.parse(rawBody);
      } catch {
        return new Response("Bad JSON", { status: 400 });
      }
      try {
        await handleOrdersFulfilledForSilencio1(env, order);
      } catch (err) {
        console.warn("Silencio1 fulfilled handler failed:", err.message);
      }
      try {
        await updatePiecesForFulfillment(env, order);
      } catch (err) {
        console.warn("Pieces fulfillment update failed:", err.message);
      }
      return new Response("OK", { status: 200 });
    }
    if (url.pathname === "/api/webhook/refunds-create" && request.method === "POST") {
      const rawBody = await request.text();
      const hmacHeader = request.headers.get("X-Shopify-Hmac-SHA256");
      if (env.SHOPIFY_WEBHOOK_SECRET) {
        const expectedHmac = await computeHmacBase64(env.SHOPIFY_WEBHOOK_SECRET, rawBody);
        if (hmacHeader !== expectedHmac) {
          return new Response("Unauthorized", { status: 401 });
        }
      }
      let refund;
      try {
        refund = JSON.parse(rawBody);
      } catch {
        return new Response("Bad JSON", { status: 400 });
      }
      try {
        await handleRefundsCreateForSilencio1(env, refund);
      } catch (err) {
        console.warn("Silencio1 refund handler failed:", err.message);
      }
      return new Response("OK", { status: 200 });
    }
    if (url.pathname === "/api/webhook/customers-update" && request.method === "POST") {
      return handleWebhookCustomersUpdate(request, env, ctx);
    }
    if (url.pathname === "/api/register-webhook") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const result = await registerShopifyWebhook(env, `${url.protocol}//${url.host}`);
      return new Response(JSON.stringify(result), { status: result.ok ? 200 : 422, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/validate") {
      const nfcParam = url.searchParams.get("nfc");
      const uidParam = url.searchParams.get("uid");
      const ctrParam = url.searchParams.get("ctr");
      const cmacParam = url.searchParams.get("cmac");
      const sourceParam = url.searchParams.get("source");
      if (sourceParam === "qr" && !nfcParam) {
        return Response.redirect(MAKING_URL, 302);
      }
      if (nfcParam === "valid" && uidParam && ctrParam && cmacParam) {
        try {
          const result = await verifyNfcCmac(uidParam, ctrParam, cmacParam, env);
          if (result.valid) {
            const scanData = await getScanData(env, uidParam);
            const isReplay = result.counter <= scanData.lastCounter;
            if (!isReplay) {
              scanData.scans++;
              scanData.lastScan = (/* @__PURE__ */ new Date()).toISOString();
              scanData.lastCounter = result.counter;
              if (!scanData.firstScan) scanData.firstScan = scanData.lastScan;
              await saveScanData(env, uidParam, scanData);
            }

            // â”€â”€ Bloque B parte 2, secciÃ³n 2: activaciÃ³n Club end-to-end â”€â”€
            const uid = uidParam;

            // PASO A â€” resolver order_id / customer_id / email desde uid_<uid>
            const uidDataRaw = await env.POTISSE_NFC.get(`uid_${uid}`);
            const uidObj = uidDataRaw ? JSON.parse(uidDataRaw) : null;
            if (!uidDataRaw) {
              console.warn(`Club activation: no uid_${uid} record â€” legacy tap, cookie sin activaciÃ³n de piezas`);
            }
            const orderId = uidObj?.order;
            const customerId = uidObj?.customer_id || null;
            const emailFromUid = uidObj?.email || "";
            const hasOrder = orderId !== undefined && orderId !== null && orderId !== "";

            // PASO B â€” determinar primera vez (para el redirect)
            let firstTime = true;
            let orderIndexForTap = null;
            if (hasOrder) {
              const orderIndexRaw = await env.POTISSE_NFC.get(`order_${orderId}_pieces_index`);
              if (!orderIndexRaw) {
                firstTime = true;
                console.warn(`Club activation: order_${orderId}_pieces_index no existe todavÃ­a (webhook orders/create pendiente), firstTime=true por defecto`);
              } else {
                orderIndexForTap = JSON.parse(orderIndexRaw);
                let anyTapped = false;
                for (const pid of orderIndexForTap.piece_ids) {
                  const pRaw = await env.POTISSE_NFC.get(`piece_${pid}`);
                  if (!pRaw) continue;
                  const p = JSON.parse(pRaw);
                  if (p.first_tap_at) { anyTapped = true; break; }
                }
                firstTime = !anyTapped;
              }
            }

            // PASO C â€” activaciÃ³n de piezas (idempotente por pieza), silenciosa ante fallos
            if (hasOrder && orderIndexForTap) {
              try {
                const nowIsoActivation = (/* @__PURE__ */ new Date()).toISOString();
                for (const pid of orderIndexForTap.piece_ids) {
                  const pKey = `piece_${pid}`;
                  const pRaw = await env.POTISSE_NFC.get(pKey);
                  if (!pRaw) continue;
                  const p = JSON.parse(pRaw);
                  if (!p.first_tap_at) {
                    p.first_tap_at = nowIsoActivation;
                    p.origin_date = nowIsoActivation;
                    await env.POTISSE_NFC.put(pKey, JSON.stringify(p));
                  }
                }
                const pendingRaw = await env.POTISSE_NFC.get("orders_pending_first_tap");
                if (pendingRaw) {
                  const pending = JSON.parse(pendingRaw);
                  if (pending.order_ids.some((id) => String(id) === String(orderId))) {
                    pending.order_ids = pending.order_ids.filter((id) => String(id) !== String(orderId));
                    await env.POTISSE_NFC.put("orders_pending_first_tap", JSON.stringify(pending));
                  }
                }
              } catch (err) {
                console.error(`Club activation: piece activation failed for order ${orderId}: ${err.message}`);
              }
            }

            // PASO D â€” emitir sesiÃ³n Club
            const sessionToken = crypto.randomUUID();
            const sessionNowIso = (/* @__PURE__ */ new Date()).toISOString();
            const sessionObj = {
              token: sessionToken,
              customer_id: customerId,
              email: emailFromUid,
              uid,
              device: parseDevice(request.headers.get("User-Agent") || ""),
              created_at: sessionNowIso,
              expires_at: new Date(Date.now() + 1800 * 1000).toISOString()
            };
            await env.POTISSE_NFC.put(`session_${sessionToken}`, JSON.stringify(sessionObj), { expirationTtl: 1800 });

            // Push 6: club entry stats (persistente en KV)
            if (customerId) {
              try {
                const clubStatsKey = `customer_${customerId}_club_stats`;
                const clubStatsRaw = await env.POTISSE_NFC.get(clubStatsKey);
                let clubStats = clubStatsRaw ? JSON.parse(clubStatsRaw) : { visits_count: 0, first_entry_at: null, last_entry_at: null };
                clubStats.visits_count = (clubStats.visits_count || 0) + 1;
                if (!clubStats.first_entry_at) clubStats.first_entry_at = sessionNowIso;
                clubStats.last_entry_at = sessionNowIso;
                await env.POTISSE_NFC.put(clubStatsKey, JSON.stringify(clubStats));
              } catch (err) {
                console.error(`Club stats update failed for customer ${customerId}: ${err.message}`);
              }
            }

            // PASO E â€” redirect con Set-Cookie
            let redirectUrl;
            if (firstTime) {
              const makingUrl = new URL(MAKING_URL);
              makingUrl.searchParams.set("nfc", "valid");
              makingUrl.searchParams.set("uid", uid);
              makingUrl.searchParams.set("scan", "1");
              redirectUrl = makingUrl.toString();
            } else {
              redirectUrl = CLUB_URL;
            }

            // Fase 9.2: log tap history (Ã©xito)
            await logNfcTapHistory(env, uid, {
              timestamp: new Date().toISOString(),
              ctr: ctrParam,
              cmac_valid: true,
              session_emitted: true,
              order_activated: !!(hasOrder && orderIndexForTap),
              outcome: "success"
            });

            return new Response(null, {
              status: 302,
              headers: {
                Location: redirectUrl,
                "Set-Cookie": buildSessionCookieHeader(sessionToken)
              }
            });
          } else {
            // Fase 9.2: log tap history (CMAC invÃ¡lido)
            await logNfcTapHistory(env, uidParam, {
              timestamp: new Date().toISOString(),
              ctr: ctrParam,
              cmac_valid: false,
              session_emitted: false,
              order_activated: false,
              outcome: "cmac_invalid"
            });
            return new Response(JSON.stringify({ valid: false, error: "Invalid signature" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
        } catch (err) {
          console.error(`/api/validate verification threw: ${err.message}`);
          return new Response(JSON.stringify({ valid: false, error: "Verification failed" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
      const action = url.searchParams.get("action") || "";
      if (action === "magic-link" && url.searchParams.get("email")) {
        const email = url.searchParams.get("email").toLowerCase().trim();
        const clientData = await env.POTISSE_NFC.get("client_" + email);
        if (!clientData) return new Response(JSON.stringify({ sent: false, error: "not_found" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        const client = JSON.parse(clientData);
        const token = generateToken();
        const tokenData = { email, uid: client.uid || "", created: (/* @__PURE__ */ new Date()).toISOString(), expires: Date.now() + 9e5, used: false };
        await env.POTISSE_NFC.put("magic_" + token, JSON.stringify(tokenData), { expirationTtl: 900 });
        const magicUrl = `https://potisse-nfc.javivigalicia1977.workers.dev/api/validate?token=${token}`;
        try {
          const sendResult = await sendMagicLinkEmail(env, email, magicUrl);
          return new Response(JSON.stringify(sendResult.ok ? { sent: true, email_id: sendResult.id } : { sent: false, error: sendResult.error || "send_failed" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        } catch (err) {
          console.error(`[MAGIC LINK] Exception: ${err.message}`);
          return new Response(JSON.stringify({ sent: false, error: "send_failed" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
      const tokenParam = url.searchParams.get("token");
      if (tokenParam) {
        const tokenRaw = await env.POTISSE_NFC.get("magic_" + tokenParam);
        const expiredHtml = /* @__PURE__ */ __name((msg) => `<html><head><meta charset="utf-8"><title>Potisse</title></head><body style="font-family:'Helvetica Neue',Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#F2F1ED;color:#3A322E;"><div style="text-align:center;max-width:320px;"><p style="font-size:11px;letter-spacing:4px;text-transform:uppercase;color:#C4B5A4;margin-bottom:24px;">Potisse</p><p style="font-size:15px;line-height:1.7;">${msg}</p></div></body></html>`, "expiredHtml");
        if (!tokenRaw) return new Response(expiredHtml("This key has expired."), { status: 410, headers: { "Content-Type": "text/html; charset=utf-8" } });
        const tokenData = JSON.parse(tokenRaw);
        if (Date.now() > tokenData.expires || tokenData.used) {
          await env.POTISSE_NFC.delete("magic_" + tokenParam);
          return new Response(expiredHtml("This key has already been used."), { status: 410, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        tokenData.used = true;
        await env.POTISSE_NFC.put("magic_" + tokenParam, JSON.stringify(tokenData), { expirationTtl: 60 });

        // Magic Link v2: si tiene customer_id, emitir sesiÃ³n Club directa
        if (tokenData.customer_id) {
          const sessionToken = crypto.randomUUID();
          const sessionNowIso = (/* @__PURE__ */ new Date()).toISOString();
          const userAgent = request.headers.get("User-Agent") || "";
          const sessionObj = {
            token: sessionToken,
            customer_id: tokenData.customer_id,
            email: tokenData.email || "",
            uid: "MAGIC_LINK",
            device: parseDevice(userAgent),
            created_at: sessionNowIso,
            expires_at: new Date(Date.now() + 1800 * 1000).toISOString()
          };
          await env.POTISSE_NFC.put(`session_${sessionToken}`, JSON.stringify(sessionObj), { expirationTtl: 1800 });

          // Push 6: club entry stats para magic link
          if (tokenData.customer_id) {
            try {
              const clubStatsKey = `customer_${tokenData.customer_id}_club_stats`;
              const clubStatsRaw = await env.POTISSE_NFC.get(clubStatsKey);
              let clubStats = clubStatsRaw ? JSON.parse(clubStatsRaw) : { visits_count: 0, first_entry_at: null, last_entry_at: null };
              clubStats.visits_count = (clubStats.visits_count || 0) + 1;
              if (!clubStats.first_entry_at) clubStats.first_entry_at = sessionNowIso;
              clubStats.last_entry_at = sessionNowIso;
              await env.POTISSE_NFC.put(clubStatsKey, JSON.stringify(clubStats));
            } catch (err) {
              console.error(`Club stats update failed for customer ${tokenData.customer_id}: ${err.message}`);
            }
          }

          await logNfcTapHistory(env, "MAGIC_LINK", {
            timestamp: new Date().toISOString(),
            ctr: "magic",
            cmac_valid: true,
            session_emitted: true,
            order_activated: false,
            outcome: "magic_link_success"
          });

          return new Response(null, {
            status: 302,
            headers: {
              Location: CLUB_URL,
              "Set-Cookie": buildSessionCookieHeader(sessionToken)
            }
          });
        }

        // LEGACY fallback: tokens antiguos con uid
        const uid = tokenData.uid;
        let scanData = { scans: 0, firstScan: null, lastScan: null, lastCounter: -1 };
        if (uid) scanData = await getScanData(env, uid);
        scanData.scans++;
        scanData.lastScan = (/* @__PURE__ */ new Date()).toISOString();
        if (!scanData.firstScan) scanData.firstScan = scanData.lastScan;
        if (uid) await saveScanData(env, uid, scanData);
        if (scanData.scans <= 1) {
          const makingUrl = new URL(MAKING_URL);
          makingUrl.searchParams.set("nfc", "valid");
          makingUrl.searchParams.set("scan", "1");
          return Response.redirect(makingUrl.toString(), 302);
        }
        return Response.redirect(CLUB_URL, 302);
      }
      return new Response(JSON.stringify({ valid: false }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/register-client") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const email = (url.searchParams.get("email") || "").toLowerCase().trim();
      const uid = url.searchParams.get("uid") || "";
      const name = url.searchParams.get("name") || "";
      const order = url.searchParams.get("order") || "";
      if (!email) return new Response("Missing email", { status: 400 });
      const clientData = { email, uid, name, order, registered: (/* @__PURE__ */ new Date()).toISOString() };
      await env.POTISSE_NFC.put("client_" + email, JSON.stringify(clientData));
      if (uid) await env.POTISSE_NFC.put("uid_" + uid, JSON.stringify({ email, name, order }));
      return new Response(JSON.stringify({ success: true, client: clientData }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/admin/magic-link" && request.method === "POST") {
      const res = await handleAdminMagicLink(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/nfc-card" && request.method === "POST") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const res = await handleAdminNfcCard(request, env);
      return res;
    }
    if (url.pathname === "/api/admin/emergency-session" && request.method === "GET") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const res = await handleAdminEmergencySession(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/post/curate" && request.method === "POST") {
      const res = await handleAdminPostCurate(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/posts/pending" && request.method === "GET") {
      return handleAdminPostsPending(request, env, url);
    }
    if (url.pathname === "/api/admin/posts/retracted" && request.method === "GET") {
      return handleAdminPostsRetracted(request, env, url);
    }
    if (url.pathname === "/api/admin/access-alerts" && request.method === "GET") {
      return handleAdminAccessAlertsGet(request, env, url);
    }
    if (url.pathname === "/api/admin/access-alerts/resolve" && request.method === "POST") {
      const res = await handleAdminAccessAlertResolve(request, env, url);
      return res;
    }
    if (/^\/api\/admin\/members\/\d+\/access-alert-history$/.test(url.pathname) && request.method === "GET") {
      return handleAdminMemberAccessAlertHistory(request, env, url);
    }

    // â”€â”€ Fase 9.2: Workshop Tools backend ampliado â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const postsImageMatch = url.pathname.match(/^\/api\/admin\/posts\/image\/([^/]+)$/);
    if (postsImageMatch && request.method === "GET") {
      return handleAdminPostsImage(request, env, url, postsImageMatch[1]);
    }
    if (url.pathname === "/api/admin/uid-info" && request.method === "GET") {
      return handleAdminUidInfo(request, env, url);
    }
    if (url.pathname === "/api/admin/email-customer" && request.method === "POST") {
      const res = await handleAdminEmailCustomer(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/customers/list" && request.method === "GET") {
      return handleAdminCustomersList(request, env, url);
    }
    // v6.9.2 â€” Refresh from Shopify (READ-ONLY diff)
    const refreshFromShopifyMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/refresh-from-shopify$/);
    if (refreshFromShopifyMatch && request.method === "GET") {
      return handleAdminMembersRefreshFromShopify(request, env, url, refreshFromShopifyMatch[1]);
    }// v6.9.2 â€” Apply Shopify refresh (writes KV after confirmation)
    const applyShopifyRefreshMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/apply-shopify-refresh$/);
    if (applyShopifyRefreshMatch && request.method === "POST") {
      return handleAdminMembersApplyShopifyRefresh(request, env, url, applyShopifyRefreshMatch[1]);
    }// v6.9.1-fix: alias /members/ para edit
    const membersEditMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/edit$/);
    if (membersEditMatch && request.method === "POST") {
      const res = await handleAdminCustomerEdit(request, env, url, membersEditMatch[1], ctx);
      return res;
    }// â”€â”€ v6.7-members-admin: Fase 9.4.3 Oleada 1 â”€â”€
    if (url.pathname === "/api/admin/quiet-list" && request.method === "GET") {
      return handleAdminQuietList(request, env, url);
    }
    if (url.pathname === "/api/admin/quiet-list/backfill" && request.method === "POST") {
      const res = await handleAdminQuietListBackfill(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/members/list" && request.method === "GET") {
      return handleAdminMembersList(request, env, url);
    }
    const membersTagsMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/tags$/);
    if (membersTagsMatch && request.method === "POST") {
      const res = await handleAdminMembersTags(request, env, url, membersTagsMatch[1]);
      return res;
    }
    const membersNotesMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/notes$/);
    if (membersNotesMatch && request.method === "POST") {
      const res = await handleAdminMembersNotes(request, env, url, membersNotesMatch[1]);
      return res;
    }
    const membersProfileMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/profile$/);
    if (membersProfileMatch && request.method === "GET") {
      return handleAdminMembersProfile(request, env, url, membersProfileMatch[1]);
    }
    if (url.pathname === "/api/admin/stock/summary" && request.method === "GET") {
      return handleAdminStockSummary(request, env, url);
    }
    if (url.pathname === "/api/admin/stock/adjust" && request.method === "POST") {
      const res = await handleAdminStockAdjust(request, env, url);
      return res;
    }
    if (url.pathname === "/api/admin/stock/production" && request.method === "POST") {
      const res = await handleAdminStockProduction(request, env, url);
      return res;
    }

    // === STOCK FOUNDATIONS v6.12.3 ===
    if (url.pathname === "/api/admin/stock/items" && request.method === "GET") {
      return handleAdminStockItemsList(request, env, url);
    }
    const stockItemMatch = url.pathname.match(/^\/api\/admin\/stock\/items\/([^\/]+)$/);
    if (stockItemMatch && request.method === "GET") {
      return handleAdminStockItemGet(request, env, url, stockItemMatch[1]);
    }
    if (url.pathname === "/api/admin/stock/items" && request.method === "POST") {
      const res = await handleAdminStockItemCreate(request, env, url);
      return res;
    }
    if (stockItemMatch && request.method === "PUT") {
      const res = await handleAdminStockItemUpdate(request, env, url, stockItemMatch[1]);
      return res;
    }
    if (stockItemMatch && request.method === "DELETE") {
      const res = await handleAdminStockItemDelete(request, env, url, stockItemMatch[1]);
      return res;
    }
    const stockItemBomMatch = url.pathname.match(/^\/api\/admin\/stock\/items\/([^\/]+)\/bom$/);
    if (stockItemBomMatch && request.method === "GET") {
      return handleAdminStockItemBomGet(request, env, url, stockItemBomMatch[1]);
    }
    if (stockItemBomMatch && request.method === "PUT") {
      const res = await handleAdminStockItemBomPut(request, env, url, stockItemBomMatch[1]);
      return res;
    }
    if (url.pathname === "/api/admin/stock/suppliers" && request.method === "GET") {
      return handleAdminStockSuppliersList(request, env, url);
    }
    if (url.pathname === "/api/admin/stock/suppliers/bootstrap" && request.method === "POST") {
      const res = await handleAdminStockSuppliersBootstrap(request, env, url);
      return res;
    }
    const stockSupplierMatch = url.pathname.match(/^\/api\/admin\/stock\/suppliers\/([^\/]+)$/);
    if (stockSupplierMatch && request.method === "GET") {
      return handleAdminStockSupplierGet(request, env, url, stockSupplierMatch[1]);
    }
    if (url.pathname === "/api/admin/stock/suppliers" && request.method === "POST") {
      const res = await handleAdminStockSupplierCreate(request, env, url);
      return res;
    }
    if (stockSupplierMatch && request.method === "PUT") {
      const res = await handleAdminStockSupplierUpdate(request, env, url, stockSupplierMatch[1]);
      return res;
    }
    if (stockSupplierMatch && request.method === "DELETE") {
      const res = await handleAdminStockSupplierDelete(request, env, url, stockSupplierMatch[1]);
      return res;
    }
    if (url.pathname === "/api/admin/stock/categories" && request.method === "GET") {
      return handleAdminStockCategories(request, env, url);
    }
        // === STOCK BATCHES v6.12.1 ===
    if (url.pathname === "/api/admin/stock/batches" && request.method === "GET") {
      return handleAdminStockBatchesList(request, env, url);
    }
    const stockBatchMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)$/);
    if (stockBatchMatch && request.method === "GET") {
      return handleAdminStockBatchGet(request, env, url, stockBatchMatch[1]);
    }
    if (url.pathname === "/api/admin/stock/batches" && request.method === "POST") {
      const res = await handleAdminStockBatchCreate(request, env, url, ctx);
      return res;
    }
    const stockBatchTransitionMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/transition$/);
    if (stockBatchTransitionMatch && request.method === "POST") {
      const res = await handleAdminStockBatchTransition(request, env, url, ctx, stockBatchTransitionMatch[1]);
      return res;
    }
    const stockBatchActivityNoteMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/note$/);
    if (stockBatchActivityNoteMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityNote(request, env, url, ctx, stockBatchActivityNoteMatch[1]);
      return res;
    }
    const stockBatchActivityEmailSentMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/email-sent$/);
    if (stockBatchActivityEmailSentMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityEmailSent(request, env, url, ctx, stockBatchActivityEmailSentMatch[1]);
      return res;
    }
    const stockBatchActivityEmailReceivedMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/email-received$/);
    if (stockBatchActivityEmailReceivedMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityEmailReceived(request, env, url, ctx, stockBatchActivityEmailReceivedMatch[1]);
      return res;
    }
    const stockBatchActivityCallMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/call$/);
    if (stockBatchActivityCallMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityCall(request, env, url, ctx, stockBatchActivityCallMatch[1]);
      return res;
    }
    const stockBatchActivityCostMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/cost$/);
    if (stockBatchActivityCostMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityCost(request, env, url, ctx, stockBatchActivityCostMatch[1]);
      return res;
    }
    const stockBatchActivityQcMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/qc$/);
    if (stockBatchActivityQcMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityQc(request, env, url, ctx, stockBatchActivityQcMatch[1]);
      return res;
    }
    const stockBatchActivityPhotoMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/activity\/photo$/);
    if (stockBatchActivityPhotoMatch && request.method === "POST") {
      const res = await handleAdminStockBatchActivityPhoto(request, env, url, ctx, stockBatchActivityPhotoMatch[1]);
      return res;
    }
    if (url.pathname === "/api/admin/stock/pipeline-aggregate" && request.method === "GET") {
      return handleAdminStockPipelineAggregate(request, env, url);
    }
    const stockBatchGenealogyMatch = url.pathname.match(/^\/api\/admin\/stock\/batches\/([^\/]+)\/genealogy$/);
    if (stockBatchGenealogyMatch && request.method === "GET") {
      return handleAdminStockBatchGenealogy(request, env, url, stockBatchGenealogyMatch[1]);
    }
    // === END STOCK BATCHES v6.12.1 ===

    // === STOCK POs + RESTOCK v6.12.3 ===
    if (url.pathname === "/api/admin/stock/pos" && request.method === "GET") {
      return handleAdminStockPOsList(request, env, url);
    }
    if (url.pathname === "/api/admin/stock/pos" && request.method === "POST") {
      const res = await handleAdminStockPOCreate(request, env, url);
      return res;
    }
    const poMatch = url.pathname.match(/^\/api\/admin\/stock\/pos\/([^\/]+)$/);
    if (poMatch && request.method === "GET") {
      return handleAdminStockPOGet(request, env, url, poMatch[1]);
    }
    if (poMatch && request.method === "PUT") {
      const res = await handleAdminStockPOUpdate(request, env, url, poMatch[1]);
      return res;
    }
    if (poMatch && request.method === "DELETE") {
      const res = await handleAdminStockPODelete(request, env, url, poMatch[1]);
      return res;
    }
    const poSubmitMatch = url.pathname.match(/^\/api\/admin\/stock\/pos\/([^\/]+)\/submit$/);
    if (poSubmitMatch && request.method === "POST") {
      const res = await handleAdminStockPOSubmit(request, env, url, poSubmitMatch[1]);
      return res;
    }
    const poReceiveMatch = url.pathname.match(/^\/api\/admin\/stock\/pos\/([^\/]+)\/receive$/);
    if (poReceiveMatch && request.method === "POST") {
      const res = await handleAdminStockPOReceive(request, env, url, poReceiveMatch[1]);
      return res;
    }
    if (url.pathname === "/api/admin/stock/suggested" && request.method === "GET") {
      return handleAdminStockSuggested(request, env, url);
    }
    if (url.pathname === "/api/admin/stock/restock-status" && request.method === "GET") {
      return handleAdminStockRestockStatus(request, env, url);
    }
    if (url.pathname === "/api/admin/stock/items/migrate" && request.method === "POST") {
      const res = await handleAdminStockItemsMigrate(request, env, url);
      return res;
    }
    // === END STOCK POs + RESTOCK v6.12.3 ===

    // === END STOCK FOUNDATIONS ===

    if (url.pathname === "/api/admin/health/summary" && request.method === "GET") {
      return handleAdminHealthSummary(request, env, url);
    }
    if (url.pathname === "/api/admin/health/timeline" && request.method === "GET") {
      return handleAdminHealthTimeline(request, env, url);
    }
    if (url.pathname === "/api/admin/system/domain-ssl" && request.method === "POST") {
      const res = await handleAdminSystemDomainSsl(request, env, url);
      return res;
    }
    const checklistStepMatch = url.pathname.match(/^\/api\/admin\/checklist\/pedido\/([^/]+)\/step$/);
    if (checklistStepMatch && request.method === "POST") {
      const res = await handleAdminChecklistStep(request, env, url, checklistStepMatch[1]);
      return res;
    }
    const checklistGetMatch = url.pathname.match(/^\/api\/admin\/checklist\/pedido\/([^/]+)$/);
    if (checklistGetMatch && request.method === "GET") {
      return handleAdminChecklistGet(request, env, url, checklistGetMatch[1]);
    }

    if (url.pathname === "/api/list-clients") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const list = await env.POTISSE_NFC.list({ prefix: "client_" });
      const clients = [];
      for (const key of list.keys) {
        const d = await env.POTISSE_NFC.get(key.name);
        if (d) clients.push(JSON.parse(d));
      }
      return new Response(JSON.stringify({ total: clients.length, clients }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/nfc-cards") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const list = await env.POTISSE_NFC.list({ prefix: "nfc_" });
      const cards = [];
      for (const key of list.keys) {
        const d = await env.POTISSE_NFC.get(key.name);
        if (d) {
          const p = JSON.parse(d);
          p.uid = key.name.replace("nfc_", "");
          cards.push(p);
        }
      }
      return new Response(JSON.stringify({ total: cards.length, cards }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/scan-history") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) return new Response("Unauthorized", { status: 401 });
      const uidHex = url.searchParams.get("uid");
      if (!uidHex) return new Response("Missing uid", { status: 400 });
      return new Response(JSON.stringify(await getScanData(env, uidHex)), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/api/subscribe") {
      const email = (url.searchParams.get("email") || "").toLowerCase().trim();
      const source = (url.searchParams.get("source") || "unknown").trim();
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(email)) {
        return new Response(JSON.stringify({ success: false, error: "invalid_email" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const store = env.SHOPIFY_STORE_DOMAIN;
      const apiToken = env.SHOPIFY_ACCESS_TOKEN;
      if (!store || !apiToken) {
        return new Response(JSON.stringify({ success: false, error: "shopify_not_configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const pendingTag = `${source}-pending`;
      try {
        const searchRes = await fetch(
          `https://${store}/admin/api/2024-01/customers/search.json?query=email:${encodeURIComponent(email)}`,
          { headers: { "X-Shopify-Access-Token": apiToken } }
        );
        if (!searchRes.ok) {
          return new Response(JSON.stringify({ success: false, error: "shopify_search_failed" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        const searchData = await searchRes.json();
        const existing = (searchData.customers || [])[0];
        if (existing) {
          const existingTags = (existing.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
          const consentState = existing.email_marketing_consent?.state || "";
          if (existingTags.includes(source) && consentState === "subscribed") {
            return new Response(JSON.stringify({ success: true, action: "already_subscribed" }), {
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        }
        let customerId;
        let shopifyCustomer;
        if (existing) {
          customerId = existing.id;
          shopifyCustomer = existing;
          const existingTags = (existing.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
          if (!existingTags.includes(pendingTag)) existingTags.push(pendingTag);
          const updateRes = await fetch(
            `https://${store}/admin/api/2024-01/customers/${existing.id}.json`,
            {
              method: "PUT",
              headers: { "X-Shopify-Access-Token": apiToken, "Content-Type": "application/json" },
              body: JSON.stringify({ customer: {
                id: existing.id,
                tags: existingTags.join(", "),
                email_marketing_consent: {
                  state: "pending",
                  opt_in_level: "confirmed_opt_in",
                  consent_updated_at: (/* @__PURE__ */ new Date()).toISOString()
                }
              } })
            }
          );
          if (!updateRes.ok) {
            return new Response(JSON.stringify({ success: false, error: "shopify_update_failed" }), {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        } else {
          const createRes = await fetch(
            `https://${store}/admin/api/2024-01/customers.json`,
            {
              method: "POST",
              headers: { "X-Shopify-Access-Token": apiToken, "Content-Type": "application/json" },
              body: JSON.stringify({ customer: {
                email,
                tags: pendingTag,
                email_marketing_consent: {
                  state: "pending",
                  opt_in_level: "confirmed_opt_in",
                  consent_updated_at: (/* @__PURE__ */ new Date()).toISOString()
                }
              } })
            }
          );
          if (!createRes.ok) {
            return new Response(JSON.stringify({ success: false, error: "shopify_create_failed" }), {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
          const createData = await createRes.json();
          customerId = createData.customer.id;
          shopifyCustomer = createData.customer;
        }

        // Push 4b: Crear customer_{id}_profile en KV si no existe
        try {
          const profileKey = `customer_${customerId}_profile`;
          const existingProfileRaw = await env.POTISSE_NFC.get(profileKey);
          if (!existingProfileRaw) {
            const nowIso = new Date().toISOString();
            const profileObj = {
              customer_id: customerId,
              email: shopifyCustomer.email || email,
              first_name: shopifyCustomer.first_name || null,
              last_name: shopifyCustomer.last_name || null,
              phone: shopifyCustomer.phone || null,
              address_line1: null,
              address_line2: null,
              city: null,
              province: null,
              postal_code: null,
              country: null,
              language: null,
              notes: null,
              notes_free: null,
              registered_at: nowIso,
              first_seen_at: nowIso,
              updated_at: nowIso,
              source: "quiet_list"
            };
            await env.POTISSE_NFC.put(profileKey, JSON.stringify(profileObj));
            console.log(`[subscribe] Created KV profile for customer ${customerId} (quiet_list)`);
          }
        } catch (err) {
          console.error(`[subscribe] KV profile creation failed: ${err.message}`);
        }

        // Indexar en quiet_list_pending para que aparezcan en filter=quiet_list
        try {
          const quietListRaw = await env.POTISSE_NFC.get("quiet_list_pending");
          const quietList = quietListRaw ? JSON.parse(quietListRaw) : { emails: [] };
          if (!quietList.emails.includes(email)) {
            quietList.emails.push(email);
            await env.POTISSE_NFC.put("quiet_list_pending", JSON.stringify(quietList));
          }
        } catch (err) {
          console.error(`quiet_list_pending index failed: ${err.message}`);
        }

        const verifyToken = generateToken();
        await env.POTISSE_NFC.put("verify_" + verifyToken, JSON.stringify({
          email,
          source,
          customer_id: customerId,
          created: (/* @__PURE__ */ new Date()).toISOString(),
          expires: Date.now() + 6048e5,
          used: false
        }), { expirationTtl: 604800 });
        const verifyUrl = `https://verify.potisse.com/?t=${verifyToken}`;
        try {
          await sendVerifyEmail(env, email, verifyUrl);
        } catch (err) {
          console.error("Verify email send failed:", err.message);
        }
        return new Response(JSON.stringify({ success: true, action: "pending_verification" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: "exception", message: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.hostname === "verify.potisse.com" || url.pathname === "/api/verify" || url.pathname === "/verify") {
      const tokenParam = url.searchParams.get("t");
      if (!tokenParam) return new Response("Invalid verification link.", { status: 400, headers: { "Content-Type": "text/plain" } });
      const tokenRaw = await env.POTISSE_NFC.get("verify_" + tokenParam);
      if (!tokenRaw) return new Response("This link has expired or does not exist.", { status: 410, headers: { "Content-Type": "text/plain" } });
      const tokenData = JSON.parse(tokenRaw);
      if (Date.now() > tokenData.expires || tokenData.used) {
        await env.POTISSE_NFC.delete("verify_" + tokenParam);
        return new Response("This link has expired or already been used.", { status: 410, headers: { "Content-Type": "text/plain" } });
      }
      const store = env.SHOPIFY_STORE_DOMAIN;
      const apiToken = env.SHOPIFY_ACCESS_TOKEN;
      try {
        const getRes = await fetch(
          `https://${store}/admin/api/2024-01/customers/${tokenData.customer_id}.json`,
          { headers: { "X-Shopify-Access-Token": apiToken } }
        );
        if (!getRes.ok) return new Response("Verification failed.", { status: 500, headers: { "Content-Type": "text/plain" } });
        const customer = (await getRes.json()).customer;
        const existingTags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
        const pendingTag = `${tokenData.source}-pending`;
        const finalTag = tokenData.source;
        const newTags = existingTags.filter((t) => t !== pendingTag);
        if (!newTags.includes(finalTag)) newTags.push(finalTag);
        const updateRes = await fetch(
          `https://${store}/admin/api/2024-01/customers/${tokenData.customer_id}.json`,
          {
            method: "PUT",
            headers: { "X-Shopify-Access-Token": apiToken, "Content-Type": "application/json" },
            body: JSON.stringify({ customer: {
              id: tokenData.customer_id,
              tags: newTags.join(", "),
              email_marketing_consent: {
                state: "subscribed",
                opt_in_level: "confirmed_opt_in",
                consent_updated_at: (/* @__PURE__ */ new Date()).toISOString()
              }
            } })
          }
        );
        if (!updateRes.ok) return new Response("Verification failed.", { status: 500, headers: { "Content-Type": "text/plain" } });
        await env.POTISSE_NFC.delete("verify_" + tokenParam);

        // Quitar de quiet_list_pending
        try {
          const quietListRaw = await env.POTISSE_NFC.get("quiet_list_pending");
          if (quietListRaw) {
            const quietList = JSON.parse(quietListRaw);
            quietList.emails = (quietList.emails || []).filter(e => e !== tokenData.email);
            await env.POTISSE_NFC.put("quiet_list_pending", JSON.stringify(quietList));
          }
        } catch (err) {
          console.error(`quiet_list_pending cleanup failed: ${err.message}`);
        }

        return Response.redirect("https://potisse.com/?confirmed=1", 302);
      } catch (err) {
        return new Response("Verification error: " + err.message, { status: 500, headers: { "Content-Type": "text/plain" } });
      }
    }
    // /api/customer-update ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Identity edit from /pages/you (HMAC-signed)
    if (url.pathname === "/api/customer-update") {
      if (request.method !== "POST") {
        return jsonResponse({ ok: false, error: "Method not allowed" }, 405);
      }
      return handleCustomerUpdate(request, env);
    }
    if (url.pathname === "/api/club/me" && request.method === "GET") {
      return handleClubMe(request, env);
    }
    if (url.pathname === "/api/club/wash" && request.method === "POST") {
      return handleClubWashAdd(request, env);
    }
    const clubWashDeleteMatch = url.pathname.match(/^\/api\/club\/wash\/([^/]+)$/);
    if (clubWashDeleteMatch && request.method === "DELETE") {
      return handleClubWashDelete(request, env, clubWashDeleteMatch[1]);
    }
    if (url.pathname === "/api/club/post" && request.method === "POST") {
      return handleClubPost(request, env);
    }
    if (url.pathname === "/api/club/post/retract" && request.method === "POST") {
      return handleClubPostRetract(request, env);
    }

    if (url.pathname === "/api/health") {
      let bloqueB = { pieces_created: 0, washes_active: 0, orphaned_pieces: 0, sessions_active: 0, pieces_arriving: 0 };
      try {
        const pieceKeys = await listAllKeysWithPrefix(env, "piece_");
        bloqueB.pieces_created = pieceKeys.length;

        let piecesArriving = 0;
        for (const key of pieceKeys) {
          const raw = await env.POTISSE_NFC.get(key.name);
          if (!raw) continue;
          try {
            const p = JSON.parse(raw);
            if (p.arriving === true) piecesArriving++;
          } catch {}
        }
        bloqueB.pieces_arriving = piecesArriving;

        const washKeys = await listAllKeysWithPrefix(env, "wash_");
        let washesActive = 0;
        for (const key of washKeys) {
          const raw = await env.POTISSE_NFC.get(key.name);
          if (!raw) continue;
          try {
            const w = JSON.parse(raw);
            if (!w.deleted_at) washesActive++;
          } catch {}
        }
        bloqueB.washes_active = washesActive;

        const sessionKeys = await listAllKeysWithPrefix(env, "session_");
        bloqueB.sessions_active = sessionKeys.length;
      } catch (err) {
        bloqueB.error = err.message;
      }
      return new Response(JSON.stringify({
        status: "ok",
        version: "6.12.3-stock-schema-rollback",
        timestamp: new Date().toISOString(),
        bloque_b: bloqueB
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.pathname === "/api/system-status") {
      const adminKeyHeader = request.headers.get("X-Admin-Key");
      const adminKeyQuery = url.searchParams.get("admin");
      const adminKey = adminKeyHeader || adminKeyQuery;
  if (!adminKeyHeader && adminKey) {
    console.warn("[v6.9.1] Legacy admin query param used for:", request.url);
    ctx.waitUntil(writeTimelineEvent(env, { type: "legacy_admin_key", severity: "info", endpoint: request.url, timestamp: new Date().toISOString() }));
  };
      if (adminKey !== env.ADMIN_KEY) {
        return new Response("Unauthorized", { status: 401 });
      }

      const status = {
        version: "6.12.3-stock-schema-rollback",
        timestamp: new Date().toISOString(),
        silencio_1: {
          candidates_total: 0,
          candidates_active: 0,
          last_cron_run: null,
          delivery_customization_exists: null,
          delivery_customization_id: null
        },
        kv: {
          namespace: "POTISSE_NFC",
          reachable: false
        },
        shopify_tokens: {
          themekit: "permanent",
          checkout_functions: "refreshed_via_client_credentials_24h"
        }
      };

      try {
        await env.POTISSE_NFC.get("__system_check__");
        status.kv.reachable = true;
      } catch (err) {
        status.kv.reachable = false;
        status.kv.error = err.message;
      }

      try {
        const lastCronRun = await env.POTISSE_NFC.get("system:last_cron_run");
        status.silencio_1.last_cron_run = lastCronRun;
        if (lastCronRun) {
          const hoursSince = (Date.now() - new Date(lastCronRun).getTime()) / (1000 * 60 * 60);
          status.silencio_1.hours_since_last_cron = Math.round(hoursSince * 10) / 10;
          status.silencio_1.cron_healthy = hoursSince < 30;
        } else {
          status.silencio_1.hours_since_last_cron = null;
          status.silencio_1.cron_healthy = true;
        }
      } catch (err) {
        status.silencio_1.last_cron_run_error = err.message;
        status.silencio_1.cron_healthy = false;
      }

      try {
        const customerKeys = await env.POTISSE_NFC.list({ prefix: "customer:" });
        status.silencio_1.candidates_total = customerKeys.keys.length;

        let activeCount = 0;
        for (const key of customerKeys.keys) {
          const data = await env.POTISSE_NFC.get(key.name, "json");
          if (data?.silencio_1?.is_candidate === true) {
            activeCount++;
          }
        }
        status.silencio_1.candidates_active = activeCount;
      } catch (err) {
        status.silencio_1.error = err.message;
      }

      try {
        const tokenResponse = await fetch(
          `https://${env.SHOPIFY_STORE_DOMAIN}/admin/oauth/access_token`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client_id: env.SHOPIFY_CHECKOUT_APP_CLIENT_ID,
              client_secret: env.SHOPIFY_CHECKOUT_APP_CLIENT_SECRET,
              grant_type: "client_credentials"
            })
          }
        );
        const tokenData = await tokenResponse.json();

        if (tokenData.access_token) {
          const shopifyUrl = `https://${env.SHOPIFY_STORE_DOMAIN}/admin/api/2026-10/graphql.json`;
          const dcResponse = await fetch(shopifyUrl, {
            method: "POST",
            headers: {
              "X-Shopify-Access-Token": tokenData.access_token,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              query: `query { deliveryCustomizations(first: 5) { edges { node { id title enabled } } } }`
            })
          });
          const dcData = await dcResponse.json();
          const dcs = dcData?.data?.deliveryCustomizations?.edges || [];
          const activeDc = dcs.find(e => e.node.enabled === true);
          if (activeDc) {
            status.silencio_1.delivery_customization_exists = true;
            status.silencio_1.delivery_customization_id = activeDc.node.id;
            status.silencio_1.delivery_customization_title = activeDc.node.title;
          } else {
            status.silencio_1.delivery_customization_exists = false;
          }
        }
      } catch (err) {
        status.silencio_1.delivery_customization_error = err.message;
      }

      return new Response(JSON.stringify(status, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    const incidencesGetMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/incidences$/);
    if (incidencesGetMatch && request.method === "GET") {
      return handleAdminMemberIncidencesGet(request, env, url, incidencesGetMatch[1]);
    }
    const incidencesPostMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/incidences$/);
    if (incidencesPostMatch && request.method === "POST") {
      const res = await handleAdminMemberIncidencesPost(request, env, url, incidencesPostMatch[1]);
      return res;
    }
    const incidenceResolveMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/incidences\/([^/]+)\/resolve$/);
    if (incidenceResolveMatch && request.method === "POST") {
      const res = await handleAdminMemberIncidenceResolve(request, env, url, incidenceResolveMatch[1], incidenceResolveMatch[2]);
      return res;
    }

    const incidencesListMatch = url.pathname.match(/^\/api\/admin\/incidences$/);
    if (incidencesListMatch && request.method === "GET") {
      return handleAdminIncidencesList(request, env, url);
    }
    if (url.pathname === "/api/admin/incidences/stats" && request.method === "GET") {
      return handleAdminIncidencesStats(request, env, url);
    }
    const incidenceEditMatch = url.pathname.match(/^\/api\/admin\/members\/([^/]+)\/incidences\/([^/]+)$/);
    if (incidenceEditMatch && request.method === "PUT") {
      const res = await handleAdminMemberIncidenceEdit(request, env, url, incidenceEditMatch[1], incidenceEditMatch[2]);
      return res;
    }

        if (url.pathname === "/api/admin/totp/status" && request.method === "GET") {
      return handleAdminTOTPStatus(request, env, url);
    }
    if (url.pathname === "/api/admin/totp/setup" && request.method === "GET") {
      return handleAdminTOTPSetup(request, env, url);
    }
    if (url.pathname === "/api/admin/totp/verify" && request.method === "POST") {
      return handleAdminTOTPVerify(request, env, url);
    }
    if (url.pathname === "/api/admin/totp/reset" && request.method === "POST") {
      return handleAdminTOTPReset(request, env, url);
    }
    if (url.pathname === "/api/admin/totp/disable" && request.method === "POST") {
      return handleAdminTOTPDisable(request, env, url);
    }
    if (url.pathname === "/api/admin/totp/force-reset" && request.method === "POST") {
      return handleAdminTOTPForceReset(request, env, url);
    }
    if (url.pathname === "/api/admin/upload-snapshot" && request.method === "POST") {
      return handleUploadSnapshot(request, env, url);
    }
    if (url.pathname === "/api/admin/members/refresh-cache" && request.method === "POST") {
      if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
        return jsonResponse({ error: "unauthorized" }, 401);
      }
      try {
        const result = await refreshMembersSummaryCache(env);
        return jsonResponse({ ok: true, count: result.count, updated_at: result.updated_at });
      } catch (err) {
        console.error("[members/refresh-cache] error:", err.message);
        return jsonResponse({ error: "refresh_failed", message: err.message }, 500);
      }
    }
    if (url.pathname === "/api/admin/nfc-cards/list" && request.method === "GET") {
      return handleAdminNfcCardsList(request, env, url);
    }
    if (url.pathname.match(/^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}$/) && request.method === "GET") {
      return handleAdminNfcCardGet(request, env, url);
    }
    if (url.pathname.match(/^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/assign$/) && request.method === "POST") {
      return handleAdminNfcCardAssign(request, env, url, ctx);
    }
    if (url.pathname.match(/^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/unassign$/) && request.method === "POST") {
      return handleAdminNfcCardUnassign(request, env, url, ctx);
    }
    if (url.pathname.match(/^\/api\/admin\/nfc-cards\/[0-9A-Fa-f]{14}\/mark-lost$/) && request.method === "POST") {
      return handleAdminNfcCardMarkLost(request, env, url, ctx);
    }
    if (url.pathname === "/api/admin/orders/list" && request.method === "GET") {
      return handleAdminOrdersList(request, env, url);
    }
    if (url.pathname.match(/^\/api\/admin\/orders\/\d+$/) && request.method === "GET") {
      return handleAdminOrderGet(request, env, url);
    }
    if (url.pathname.match(/^\/api\/admin\/orders\/\d+\/fulfill$/) && request.method === "POST") {
      const res = await handleAdminOrderFulfill(request, env, url);
      return res;
    }

// DIAGNÃ“STICO: si llegamos aquÃ­, ninguna ruta coincidiÃ³
    // Devolvemos el pathname recibido para debug del proxy
      return new Response(JSON.stringify({
        service: "POTISSE NFC Validation",
        version: "6.12.3-stock-schema-rollback",
      status: "active",
      debug_pathname: url.pathname,
      debug_method: request.method,
      endpoints: [
        "/api/validate",
        "/api/register-client",
        "/api/admin/nfc-card",
        "/api/admin/emergency-session",
        "/api/list-clients",
        "/api/nfc-cards",
        "/api/scan-history",
        "/api/webhook/orders-create",
        "/api/webhook/orders-fulfilled",
        "/api/webhook/refunds-create",
        "/api/register-webhook",
        "/api/wash/add",
        "/api/wash/get",
        "/api/wash/all",
        "/api/subscribe",
        "/api/verify",
        "/api/customer-update",
        "/api/club/me",
        "/api/club/wash",
        "/api/club/wash/:wash_id",
        "/api/club/post",
        "/api/club/post/retract",
        "/api/admin/post/curate",
        "/api/admin/posts/pending",
        "/api/admin/posts/retracted",
        "/api/admin/access-alerts",
        "/api/admin/access-alerts/resolve",
        "/api/admin/members/:id/access-alert-history",
        "/api/admin/posts/image/:post_id",
        "/api/admin/uid-info",
        "/api/admin/email-customer",
        "/api/admin/customers/list",
        
        
        "/api/admin/members/list",
        "/api/admin/members/:customer_id/profile",
        "/api/admin/members/:customer_id/tags",
        "/api/admin/members/:customer_id/notes",
        "/api/admin/stock/summary",
        "/api/admin/stock/adjust",
        "/api/admin/stock/production",
        "/api/admin/stock/items",
        "/api/admin/stock/items/:id",
        "/api/admin/stock/items/:id/bom",
        "/api/admin/stock/suppliers",
        "/api/admin/stock/suppliers/:id",
        "/api/admin/stock/suppliers/bootstrap",
        "/api/admin/health/summary",
        "/api/admin/health/timeline",
        "/api/admin/checklist/pedido/:order_id",
        "/api/admin/checklist/pedido/:order_id/step",
        "/api/admin/system/domain-ssl",
        "/api/admin/magic-link",
        "/api/admin/quiet-list",
        "/api/admin/quiet-list/backfill",
        "/api/admin/incidences",
        "/api/admin/incidences/stats",
        "/api/admin/members/:customer_id/incidences",
        "/api/admin/members/:customer_id/incidences/:incidence_id",
        "/api/admin/members/:customer_id/incidences/:incidence_id/resolve",
        "/api/admin/totp/status",
        "/api/admin/totp/setup",
        "/api/admin/totp/verify",
        "/api/admin/totp/reset",
        "/api/admin/totp/disable",
        "/api/admin/totp/force-reset",
        "/api/admin/upload-snapshot",
        "/api/admin/nfc-cards/list",
        "/api/admin/nfc-cards/:uid",
        "/api/admin/nfc-cards/:uid/assign",
        "/api/admin/nfc-cards/:uid/unassign",
        "/api/admin/nfc-cards/:uid/mark-lost",
        "/api/admin/orders/list",
        "/api/admin/orders/:id",
        "/api/admin/orders/:id/fulfill",
        "/api/admin/members/refresh-cache",

      ]
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    })();

    if (totpCheck && totpCheck.ok && totpCheck.refreshSession) {
      return withTOTPRefresh(response, env, totpCheck);
    }
    return response;
  },

  async scheduled(event, env, ctx) {
    console.log(`Cron triggered: ${event.cron}`);
    ctx.waitUntil((async () => {
      try {
        if (event.cron === "0 3 * * *") {
          // v6.6.2: timestamp "el cron corriÃ³" escrito ANTES de la evaluaciÃ³n,
          // no despuÃ©s â€” endurecimiento defensivo (evaluateSilencio1Candidates
          // no tiene early return hoy, pero asÃ­ queda blindado si algÃºn dÃ­a lo tiene).
          await env.POTISSE_NFC.put("system:last_cron_run", new Date().toISOString());
          await evaluateSilencio1Candidates(env);
          console.log("Silencio1 cron completed successfully");
        } else if (event.cron === "0 8 * * *") {
          await runAccessAlerts(env);
          console.log("Access alerts cron completed successfully");
        } else if (event.cron === "0 * * * *") {
          await runPurgeRetracts(env);
          console.log("Purge retracts cron completed successfully");
        } else if (event.cron === "*/5 * * * *") {
          await refreshMembersSummaryCache(env);
          console.log("Members summary cache refreshed successfully");
        } else {
          console.warn(`Unrecognized cron pattern: ${event.cron}`);
        }
      } catch (err) {
        console.error(`Cron ${event.cron} failed: ${err.message}`);
        throw err;
      }
    })());
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map







// ============================================================
// STOCK FOUNDATIONS v6.12.1 HANDLERS
// ============================================================

async function handleAdminStockItemsList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const list = await env.POTISSE_NFC.list({ prefix: "stock_item_" });
  const items = [];
  for (const k of list.keys || []) {
    const raw = await env.POTISSE_NFC.get(k.name);
    if (raw) {
      try {
        const item = JSON.parse(raw);
        if (item) {
          items.push({
            id: item.id, name: item.name, sku: item.sku, category: item.category,
            current_stock: item.quantity || 0,
            min_threshold: item.min_threshold, critical_threshold: item.critical_threshold,
            unit: item.unit, supplier_id: item.supplier_id,
            standard_lead_time_days: item.standard_lead_time_days,
            buffer_days: item.buffer_days, origin_type: item.origin_type,
            is_shopify_master: item.is_shopify_master,
            has_bom: !!(item.bom && item.bom.length), updated_at: item.updated_at
          });
        }
      } catch {}
    }
  }
  return jsonResponse({ ok: true, items }, 200);
}
__name(handleAdminStockItemsList, "handleAdminStockItemsList");

async function handleAdminStockItemGet(request, env, url, itemSku) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get(`stock_item_${itemSku}`);
  const item = raw ? JSON.parse(raw) : null;
  if (!item) return jsonResponse({ error: "item_not_found" }, 404);
  return jsonResponse({ ok: true, item }, 200);
}
__name(handleAdminStockItemGet, "handleAdminStockItemGet");

async function handleAdminStockItemCreate(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let bodyText;
  try { bodyText = await request.text(); } catch (e) { return jsonResponse({ error: "invalid_body", detail: e.message }, 400); }
  if (!bodyText || !bodyText.trim()) return jsonResponse({ error: "empty_body" }, 400);
  let body;
  try { body = JSON.parse(bodyText); } catch (e) { return jsonResponse({ error: "invalid_json", detail: e.message }, 400); }
  const { id, name, sku, category, unit, supplier_id, min_threshold, critical_threshold,
    standard_lead_time_days, buffer_days, origin_type, is_shopify_master, shopify_variant_id } = body || {};
  if (!id || !name || !sku || !category || !origin_type) {
    return jsonResponse({ error: "missing_required_fields", detail: "id, name, sku, category, origin_type required" }, 400);
  }
  const validOrigins = ["local", "eu", "extra_eu"];
  if (!validOrigins.includes(origin_type)) {
    return jsonResponse({ error: "invalid_origin_type", detail: "Must be local, eu, or extra_eu" }, 400);
  }
  const minT = parseFloat(min_threshold) || 0;
  const critT = parseFloat(critical_threshold) || 0;
  if (critT > minT) {
    return jsonResponse({ error: "invalid_thresholds", detail: "critical_threshold must be <= min_threshold" }, 400);
  }
  const existing = await env.POTISSE_NFC.get(`stock_item_${sku}`);
  if (existing) return jsonResponse({ error: "item_already_exists", detail: `SKU ${sku} already exists` }, 409);
  const now = new Date().toISOString();
  const bufferDefault = buffer_days != null ? parseFloat(buffer_days) : (origin_type === "local" ? 3 : origin_type === "eu" ? 5 : 12);
  const item = {
    id, name, sku, category, quantity: 0,
    min_threshold: minT, critical_threshold: critT,
    unit: unit || "units", supplier_id: supplier_id || null,
    standard_lead_time_days: parseFloat(standard_lead_time_days) || 7,
    buffer_days: bufferDefault, origin_type,
    is_shopify_master: !!is_shopify_master,
    shopify_variant_id: shopify_variant_id || null,
    bom: null, history: [], created_at: now, updated_at: now, created_by: "admin"
  };
  await env.POTISSE_NFC.put(`stock_item_${sku}`, JSON.stringify(item));
  return jsonResponse({ ok: true, item }, 201);
}
__name(handleAdminStockItemCreate, "handleAdminStockItemCreate");

async function handleAdminStockItemUpdate(request, env, url, itemSku) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let bodyText;
  try { bodyText = await request.text(); } catch (e) { return jsonResponse({ error: "invalid_body", detail: e.message }, 400); }
  if (!bodyText || !bodyText.trim()) return jsonResponse({ error: "empty_body" }, 400);
  let body;
  try { body = JSON.parse(bodyText); } catch (e) { return jsonResponse({ error: "invalid_json", detail: e.message }, 400); }
  const raw = await env.POTISSE_NFC.get(`stock_item_${itemSku}`);
  const item = raw ? JSON.parse(raw) : null;
  if (!item) return jsonResponse({ error: "item_not_found" }, 404);
  const allowed = ["name","category","min_threshold","critical_threshold","unit","supplier_id",
    "standard_lead_time_days","buffer_days","origin_type","is_shopify_master","shopify_variant_id"];
  for (const key of allowed) {
    if (body[key] !== undefined) item[key] = body[key];
  }
  if (body.origin_type !== undefined) {
    const validOrigins = ["local", "eu", "extra_eu"];
    if (!validOrigins.includes(body.origin_type)) return jsonResponse({ error: "invalid_origin_type" }, 400);
  }
  const minT = parseFloat(item.min_threshold) || 0;
  const critT = parseFloat(item.critical_threshold) || 0;
  if (critT > minT) return jsonResponse({ error: "invalid_thresholds", detail: "critical_threshold must be <= min_threshold" }, 400);
  item.updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put(`stock_item_${itemSku}`, JSON.stringify(item));
  return jsonResponse({ ok: true, item }, 200);
}
__name(handleAdminStockItemUpdate, "handleAdminStockItemUpdate");

async function handleAdminStockItemDelete(request, env, url, itemSku) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get(`stock_item_${itemSku}`);
  if (!raw) return jsonResponse({ error: "item_not_found" }, 404);
  await env.POTISSE_NFC.delete(`stock_item_${itemSku}`);
  return jsonResponse({ ok: true, deleted: itemSku }, 200);
}
__name(handleAdminStockItemDelete, "handleAdminStockItemDelete");

async function handleAdminStockItemBomGet(request, env, url, itemSku) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get(`stock_item_${itemSku}`);
  const item = raw ? JSON.parse(raw) : null;
  if (!item) return jsonResponse({ error: "item_not_found" }, 404);
  return jsonResponse({ ok: true, item_sku: itemSku, bom: item.bom || [] }, 200);
}
__name(handleAdminStockItemBomGet, "handleAdminStockItemBomGet");

async function handleAdminStockItemBomPut(request, env, url, itemSku) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let bodyText;
  try { bodyText = await request.text(); } catch (e) { return jsonResponse({ error: "invalid_body", detail: e.message }, 400); }
  if (!bodyText || !bodyText.trim()) return jsonResponse({ error: "empty_body" }, 400);
  let body;
  try { body = JSON.parse(bodyText); } catch (e) { return jsonResponse({ error: "invalid_json", detail: e.message }, 400); }
  const { bom } = body || {};
  if (!Array.isArray(bom)) return jsonResponse({ error: "bom_must_be_array" }, 400);
  for (const row of bom) {
    if (!row.component_id || typeof row.qty !== "number" || row.qty <= 0) {
      return jsonResponse({ error: "invalid_bom_row" }, 400);
    }
  }
  const raw = await env.POTISSE_NFC.get(`stock_item_${itemSku}`);
  const item = raw ? JSON.parse(raw) : null;
  if (!item) return jsonResponse({ error: "item_not_found" }, 404);
  item.bom = bom.map(b => ({ component_id: b.component_id, qty: b.qty, unit: b.unit || "units", notes: b.notes || null }));
  item.updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put(`stock_item_${itemSku}`, JSON.stringify(item));
  return jsonResponse({ ok: true, item_sku: itemSku, bom: item.bom }, 200);
}
__name(handleAdminStockItemBomPut, "handleAdminStockItemBomPut");

async function handleAdminStockSuppliersList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  const suppliers = Object.values(data.suppliers || {});
  return jsonResponse({ ok: true, suppliers }, 200);
}

async function handleAdminStockSupplierGet(request, env, url, supplierId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  const supplier = data.suppliers[supplierId];
  if (!supplier) return jsonResponse({ error: "supplier_not_found" }, 404);
  return jsonResponse({ ok: true, supplier }, 200);
}

async function handleAdminStockSupplierCreate(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let bodyText;
  try { bodyText = await request.text(); } catch (e) { return jsonResponse({ error: "invalid_body", detail: e.message }, 400); }
  if (!bodyText || !bodyText.trim()) return jsonResponse({ error: "empty_body" }, 400);
  let body;
  try { body = JSON.parse(bodyText); } catch (e) { return jsonResponse({ error: "invalid_json", detail: e.message }, 400); }
  const { id, name, contact_email, contact_phone, address, lead_time_days, notes } = body || {};
  if (!id || !name) return jsonResponse({ error: "missing_required_fields" }, 400);
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  if (data.suppliers[id]) return jsonResponse({ error: "supplier_already_exists" }, 409);
  const now = new Date().toISOString();
  data.suppliers[id] = {
    id, name, contact_email: contact_email || null, contact_phone: contact_phone || null,
    address: address || null, lead_time_days: lead_time_days || null, notes: notes || null,
    is_in_house: false, created_at: now, updated_at: now
  };
  await env.POTISSE_NFC.put("stock_suppliers", JSON.stringify(data));
  return jsonResponse({ ok: true, supplier: data.suppliers[id] }, 201);
}

async function handleAdminStockSupplierUpdate(request, env, url, supplierId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let bodyText;
  try { bodyText = await request.text(); } catch (e) { return jsonResponse({ error: "invalid_body", detail: e.message }, 400); }
  if (!bodyText || !bodyText.trim()) return jsonResponse({ error: "empty_body" }, 400);
  let body;
  try { body = JSON.parse(bodyText); } catch (e) { return jsonResponse({ error: "invalid_json", detail: e.message }, 400); }
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  const supplier = data.suppliers[supplierId];
  if (!supplier) return jsonResponse({ error: "supplier_not_found" }, 404);
  const allowed = ["name","contact_email","contact_phone","address","lead_time_days","notes"];
  for (const key of allowed) {
    if (body[key] !== undefined) supplier[key] = body[key];
  }
  supplier.updated_at = new Date().toISOString();
  await env.POTISSE_NFC.put("stock_suppliers", JSON.stringify(data));
  return jsonResponse({ ok: true, supplier }, 200);
}

async function handleAdminStockSupplierDelete(request, env, url, supplierId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  if (!data.suppliers[supplierId]) return jsonResponse({ error: "supplier_not_found" }, 404);
  delete data.suppliers[supplierId];
  await env.POTISSE_NFC.put("stock_suppliers", JSON.stringify(data));
  return jsonResponse({ ok: true, deleted: supplierId }, 200);
}

async function handleAdminStockSuppliersBootstrap(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  const data = raw ? JSON.parse(raw) : { suppliers: {} };
  const now = new Date().toISOString();
  if (!data.suppliers["potisse-in-house"]) {
    data.suppliers["potisse-in-house"] = {
      id: "potisse-in-house",
      name: "POTISSE In-House",
      contact_email: null,
      contact_phone: null,
      address: null,
      lead_time_days: 0,
      notes: "Produccion interna y ensamblaje POTISSE",
      is_in_house: true,
      created_at: now,
      updated_at: now
    };
    await env.POTISSE_NFC.put("stock_suppliers", JSON.stringify(data));
    return jsonResponse({ ok: true, created: true, supplier: data.suppliers["potisse-in-house"] }, 201);
  }
  return jsonResponse({ ok: true, created: false, message: "already_exists" }, 200);
}

async function handleAdminStockCategories(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const categories = [
    { id: "packaging", name: "Packaging", icon: "box" },
    { id: "garment", name: "Garment / Prenda", icon: "shirt" },
    { id: "raw_material", name: "Raw Material / Materia Prima", icon: "scissors" },
    { id: "finished_good", name: "Finished Good / Producto Terminado", icon: "package" },
    { id: "hardware", name: "Hardware / NFC", icon: "cpu" },
    { id: "label", name: "Labels / Etiquetas", icon: "tag" }
  ];
  return jsonResponse({ ok: true, categories }, 200);
}

// ═══════════════════════════════════════════════════════════════════════
// C.5-A.2 HANDLERS — Batches (FIXED: admin key only, TOTP handled by global middleware)
// ═══════════════════════════════════════════════════════════════════════

async function handleAdminStockBatchesList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const statusFilter = url.searchParams.get("status");
  const itemSkuFilter = url.searchParams.get("item_sku");
  const supplierIdFilter = url.searchParams.get("supplier_id");
  const searchQuery = url.searchParams.get("search");
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 250);

  const [itemsData, suppliersData] = await Promise.all([
    getStockItemCatalog(env),
    getStockSuppliers(env)
  ]);
  const items = itemsData.items || {};
  const suppliers = suppliersData.suppliers || {};

  const allKeys = await listAllKeysWithPrefix(env, "stock_batch_");
  let batches = [];
  for (const key of allKeys) {
    const match = key.match(/^stock_batch_(.+)$/);
    if (!match) continue;
    const raw = await env.POTISSE_NFC.get(key);
    if (!raw) continue;
    const batch = JSON.parse(raw);
    if (statusFilter && statusFilter !== "all" && batch.status !== statusFilter) continue;
    if (itemSkuFilter && batch.item_sku !== itemSkuFilter) continue;
    if (supplierIdFilter) {
      const holderMatch = batch.current_holder_id === supplierIdFilter;
      let activityMatch = false;
      for (const act of (batch.activities || [])) {
        if (act.data && (act.data.supplier_id === supplierIdFilter || act.data.contact_id === supplierIdFilter)) {
          activityMatch = true; break;
        }
      }
      if (!holderMatch && !activityMatch) continue;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const haystack = `${batch.id} ${batch.notes || ""}`.toLowerCase();
      if (!haystack.includes(q)) continue;
    }
    batches.push(enrichBatchList(batch, items, suppliers));
  }

  batches.sort((a, b) => b.created_at.localeCompare(a.created_at));
  const sliced = batches.slice(0, limit);
  return jsonResponse({ ok: true, batches: sliced, next_cursor: null });
}
__name(handleAdminStockBatchesList, "handleAdminStockBatchesList");

async function handleAdminStockBatchGet(request, env, url, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const [itemsData, suppliersData] = await Promise.all([
    getStockItemCatalog(env),
    getStockSuppliers(env)
  ]);
  return jsonResponse({ ok: true, batch: enrichBatchDetail(batch, itemsData.items || {}, suppliersData.suppliers || {}) });
}
__name(handleAdminStockBatchGet, "handleAdminStockBatchGet");

async function handleAdminStockBatchCreate(request, env, url, ctx) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { item_sku, quantity, notes, source_batch_ids, parent_batch_id } = body || {};
  if (!item_sku || !quantity || quantity <= 0) {
    return jsonResponse({ error: "missing_required_fields" }, 400);
  }

  const itemsData = await getStockItemCatalog(env);
  const item = itemsData.items ? itemsData.items[item_sku] : null;
  if (!item || item.active === false) {
    return jsonResponse({ error: "item_not_found_or_inactive" }, 400);
  }

  if (source_batch_ids && Array.isArray(source_batch_ids) && source_batch_ids.length > 0) {
    for (const sid of source_batch_ids) {
      const src = await getBatch(env, sid);
      if (!src) return jsonResponse({ error: "source_batch_not_found", batch_id: sid }, 400);
    }
  }

  if (parent_batch_id) {
    const parent = await getBatch(env, parent_batch_id);
    if (!parent) return jsonResponse({ error: "parent_batch_not_found" }, 400);
  }

  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const seq = await getNextBatchSeq(env, dateStr);
  const batchId = `batch_${dateStr}_${seq}`;
  const now = new Date().toISOString();
  const actor = getActor(request);

  let expectedCompletion = null;
  const bom = item.bom || {};
  const flow = bom.standard_flow || [];
  if (flow.length > 0) {
    const totalEta = flow.reduce((sum, step) => sum + (step.eta_days || 0), 0);
    const d = new Date(); d.setDate(d.getDate() + totalEta);
    expectedCompletion = d.toISOString();
  }

  const batch = {
    id: batchId,
    item_sku,
    quantity,
    status: "to_order",
    current_holder_id: null,
    current_step_index: 0,
    expected_completion_at: expectedCompletion,
    linked_po_id: null,
    parent_batch_id: parent_batch_id || null,
    source_batch_ids: source_batch_ids || [],
    child_batch_ids: [],
    notes: notes || null,
    cost_accumulated: 0.00,
    currency: "EUR",
    status_since: now,
    last_activity_at: now,
    activities: [],
    created_at: now,
    updated_at: now,
    created_by: actor
  };

  addActivity(batch, "transition", "system", { from_status: null, to_status: "to_order", from_holder_id: null, to_holder_id: null, note: "Batch created" });
  await putBatch(env, batch);

  if (parent_batch_id) {
    const parent = await getBatch(env, parent_batch_id);
    if (parent) {
      if (!parent.child_batch_ids) parent.child_batch_ids = [];
      parent.child_batch_ids.push(batchId);
      await putBatch(env, parent);
    }
  }
  if (source_batch_ids) {
    for (const sid of source_batch_ids) {
      const src = await getBatch(env, sid);
      if (src) {
        if (!src.child_batch_ids) src.child_batch_ids = [];
        if (!src.child_batch_ids.includes(batchId)) src.child_batch_ids.push(batchId);
        await putBatch(env, src);
      }
    }
  }

  await logBatchTimeline(env, ctx, batchId, "batch_created", "info",
    `Batch ${batchId} created for ${item_sku}`,
    `Quantity: ${quantity}, expected completion: ${expectedCompletion || "N/A"}`,
    actor
  );

  return jsonResponse({ ok: true, batch: enrichBatchDetail(batch, itemsData.items || {}, {}) });
}
__name(handleAdminStockBatchCreate, "handleAdminStockBatchCreate");

async function handleAdminStockBatchTransition(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { to_status, new_holder_id, advance_step_flow, note } = body || {};

  if (!to_status || !BATCH_STATUSES.includes(to_status)) {
    return jsonResponse({ error: "invalid_status" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const fromStatus = batch.status;
  if (!isValidBatchTransition(fromStatus, to_status)) {
    return jsonResponse({ error: "invalid_transition", from: fromStatus, to: to_status }, 400);
  }

  if (new_holder_id) {
    const suppliersData = await getStockSuppliers(env);
    if (!suppliersData.suppliers || !suppliersData.suppliers[new_holder_id]) {
      return jsonResponse({ error: "holder_not_found" }, 400);
    }
  }

  const actor = getActor(request);
  const now = new Date().toISOString();
  const oldHolder = batch.current_holder_id;

  batch.status = to_status;
  batch.status_since = now;
  if (new_holder_id !== undefined) batch.current_holder_id = new_holder_id || null;
  if (advance_step_flow && batch.current_step_index != null) {
    batch.current_step_index += 1;
  }
  batch.updated_at = now;

  const itemsData = await getStockItemCatalog(env);
  const item = itemsData.items ? itemsData.items[batch.item_sku] : null;
  const bom = item ? item.bom : null;
  const flow = bom ? bom.standard_flow : [];
  if (flow.length > 0 && batch.current_step_index < flow.length) {
    const remainingEta = flow.slice(batch.current_step_index).reduce((sum, step) => sum + (step.eta_days || 0), 0);
    const d = new Date(); d.setDate(d.getDate() + remainingEta);
    batch.expected_completion_at = d.toISOString();
  }

  addActivity(batch, "transition", actor, {
    from_status: fromStatus,
    to_status: to_status,
    from_holder_id: oldHolder,
    to_holder_id: batch.current_holder_id,
    note: note || null
  });
  await putBatch(env, batch);

  await logBatchTimeline(env, ctx, batchId, "batch_transition", "info",
    `Batch ${batchId}: ${fromStatus} → ${to_status}`,
    note || `Holder: ${oldHolder || "none"} → ${batch.current_holder_id || "none"}`,
    actor
  );

  return jsonResponse({ ok: true, batch: enrichBatchList(batch, itemsData.items || {}, (await getStockSuppliers(env)).suppliers || {}) });
}
__name(handleAdminStockBatchTransition, "handleAdminStockBatchTransition");

async function handleAdminStockBatchActivityNote(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { text } = body || {};
  if (!text || text.length < 3 || text.length > 500) {
    return jsonResponse({ error: "text_invalid", message: "Must be 3-500 chars" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const actor = getActor(request);
  addActivity(batch, "note", actor, { text });
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1] });
}
__name(handleAdminStockBatchActivityNote, "handleAdminStockBatchActivityNote");

async function handleAdminStockBatchActivityEmailSent(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const force = url.searchParams.get("force") === "1";
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }

  const { to, to_name, supplier_id, subject, body_preview, message_id } = body || {};
  if (!to || !subject) {
    return jsonResponse({ error: "missing_required_fields" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  if (!force) {
    const recent = checkRecentComm(batch, 24);
    if (recent.exists) {
      return jsonResponse({
        ok: false,
        warning: "recent_comm_exists",
        last_comm: recent.last_comm,
        hours_ago: recent.hours_ago
      }, 200);
    }
  }

  const actor = getActor(request);
  const data = {
    to, to_name: to_name || null, supplier_id: supplier_id || null,
    subject, body_preview: body_preview || null,
    attachments_count: 0, message_id: message_id || null
  };
  if (force) data.forced = true;

  addActivity(batch, "email_sent", actor, data);
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1] });
}
__name(handleAdminStockBatchActivityEmailSent, "handleAdminStockBatchActivityEmailSent");

async function handleAdminStockBatchActivityEmailReceived(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { from, from_name, subject, body_preview, in_reply_to_message_id } = body || {};

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const actor = getActor(request);
  addActivity(batch, "email_received", actor, {
    from: from || null, from_name: from_name || null,
    subject: subject || null, body_preview: body_preview || null,
    in_reply_to_message_id: in_reply_to_message_id || null
  });
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1] });
}
__name(handleAdminStockBatchActivityEmailReceived, "handleAdminStockBatchActivityEmailReceived");

async function handleAdminStockBatchActivityCall(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const force = url.searchParams.get("force") === "1";
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { medium, contact_id, contact_name, summary } = body || {};
  if (!medium || !["call", "whatsapp", "visit", "sms"].includes(medium) || !summary) {
    return jsonResponse({ error: "invalid_fields" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  if (!force) {
    const recent = checkRecentComm(batch, 24);
    if (recent.exists) {
      return jsonResponse({
        ok: false,
        warning: "recent_comm_exists",
        last_comm: recent.last_comm,
        hours_ago: recent.hours_ago
      }, 200);
    }
  }

  const actor = getActor(request);
  const data = { medium, contact_id: contact_id || null, contact_name: contact_name || null, summary };
  if (force) data.forced = true;

  addActivity(batch, "call_log", actor, data);
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1] });
}
__name(handleAdminStockBatchActivityCall, "handleAdminStockBatchActivityCall");

async function handleAdminStockBatchActivityCost(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { amount, currency: curr, reason, supplier_id, linked_invoice_id } = body || {};
  if (amount == null || isNaN(amount) || amount < 0 || !reason) {
    return jsonResponse({ error: "invalid_fields" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  batch.cost_accumulated = (batch.cost_accumulated || 0) + parseFloat(amount);
  batch.updated_at = new Date().toISOString();

  const actor = getActor(request);
  addActivity(batch, "cost_logged", actor, {
    amount: parseFloat(amount),
    currency: curr || "EUR",
    reason,
    supplier_id: supplier_id || null,
    linked_invoice_id: linked_invoice_id || null
  });
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1], cost_accumulated: batch.cost_accumulated });
}
__name(handleAdminStockBatchActivityCost, "handleAdminStockBatchActivityCost");

async function handleAdminStockBatchActivityQc(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { passed, failed, total, checklist, notes } = body || {};
  if (passed == null || failed == null || total == null || passed + failed !== total) {
    return jsonResponse({ error: "qc_validation_failed", message: "passed + failed must equal total" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const overallPass = failed === 0;
  const actor = getActor(request);

  addActivity(batch, "qc_result", actor, {
    passed, failed, total,
    checklist: checklist || [],
    overall_pass: overallPass,
    notes: notes || null
  });
  await putBatch(env, batch);

  const suggestions = [];
  if (overallPass) suggestions.push("Consider transitioning to stock_ready");
  if (!overallPass && failed > 0) suggestions.push("Consider creating a rework batch for failed units");

  return jsonResponse({
    ok: true,
    activity: batch.activities[batch.activities.length - 1],
    suggestions
  });
}
__name(handleAdminStockBatchActivityQc, "handleAdminStockBatchActivityQc");

async function handleAdminStockBatchActivityPhoto(request, env, url, ctx, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch (e) { return jsonResponse({ error: "invalid_json" }, 400); }
  const { r2_url, filename, size_bytes, description } = body || {};
  if (!r2_url || !filename) {
    return jsonResponse({ error: "missing_required_fields" }, 400);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const actor = getActor(request);
  addActivity(batch, "photo_attached", actor, {
    r2_url, filename, size_bytes: size_bytes || null, description: description || null
  });
  await putBatch(env, batch);

  return jsonResponse({ ok: true, activity: batch.activities[batch.activities.length - 1] });
}
__name(handleAdminStockBatchActivityPhoto, "handleAdminStockBatchActivityPhoto");

async function handleAdminStockPipelineAggregate(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  const allKeys = await listAllKeysWithPrefix(env, "stock_batch_");
  const totals = { to_order: 0, ordered: 0, in_house: 0, with_artisan: 0, qc_pending: 0, stock_ready: 0, discarded: 0 };
  const alerts = { over_sla: [], no_activity_48h: [], awaiting_reply: [] };
  const now = Date.now();

  const [itemsData, suppliersData] = await Promise.all([
    getStockItemCatalog(env),
    getStockSuppliers(env)
  ]);
  const items = itemsData.items || {};
  const suppliers = suppliersData.suppliers || {};

  for (const key of allKeys) {
    const raw = await env.POTISSE_NFC.get(key);
    if (!raw) continue;
    const batch = JSON.parse(raw);
    if (totals[batch.status] !== undefined) totals[batch.status]++;

    if (batch.expected_completion_at && batch.status !== "stock_ready" && batch.status !== "discarded") {
      const expected = new Date(batch.expected_completion_at).getTime();
      if (now > expected + 3 * 86400000) {
        const daysOver = Math.floor((now - expected) / 86400000);
        const item = items[batch.item_sku];
        const holder = suppliers[batch.current_holder_id];
        alerts.over_sla.push({
          batch_id: batch.id,
          days_over: daysOver,
          item_name: item ? item.name : batch.item_sku,
          holder_name: holder ? holder.name : batch.current_holder_id
        });
      }
    }

    if (batch.last_activity_at && batch.status !== "stock_ready" && batch.status !== "discarded") {
      const lastActivity = new Date(batch.last_activity_at).getTime();
      if (now > lastActivity + 48 * 3600000) {
        const hoursSince = Math.floor((now - lastActivity) / 3600000);
        const item = items[batch.item_sku];
        alerts.no_activity_48h.push({
          batch_id: batch.id,
          hours_since_last: hoursSince,
          item_name: item ? item.name : batch.item_sku
        });
      }
    }

    const activities = batch.activities || [];
    let lastEmailSent = null;
    let lastEmailReceived = null;
    for (const act of activities) {
      if (act.type === "email_sent") lastEmailSent = act;
      if (act.type === "email_received") lastEmailReceived = act;
    }
    if (lastEmailSent) {
      const sentTime = new Date(lastEmailSent.timestamp).getTime();
      if (now > sentTime + 48 * 3600000) {
        if (!lastEmailReceived || new Date(lastEmailReceived.timestamp).getTime() < sentTime) {
          const contactName = lastEmailSent.data.to_name || lastEmailSent.data.to || "Unknown";
          alerts.awaiting_reply.push({
            batch_id: batch.id,
            last_comm_at: lastEmailSent.timestamp,
            contact_name: contactName
          });
        }
      }
    }
  }

  return jsonResponse({ ok: true, totals, alerts });
}
__name(handleAdminStockPipelineAggregate, "handleAdminStockPipelineAggregate");

async function handleAdminStockBatchGenealogy(request, env, url, batchId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  const batch = await getBatch(env, batchId);
  if (!batch) return jsonResponse({ error: "batch_not_found" }, 404);

  const [itemsData, suppliersData] = await Promise.all([
    getStockItemCatalog(env),
    getStockSuppliers(env)
  ]);
  const items = itemsData.items || {};
  const suppliers = suppliersData.suppliers || {};

  async function buildAncestors(id, depth, maxDepth) {
    if (depth > maxDepth) return [];
    const b = await getBatch(env, id);
    if (!b) return [];
    const result = [];
    const srcIds = b.source_batch_ids || [];
    for (const sid of srcIds) {
      const sb = await getBatch(env, sid);
      if (!sb) continue;
      const actorSet = new Set();
      if (sb.current_holder_id) actorSet.add(sb.current_holder_id);
      for (const act of (sb.activities || [])) {
        if (act.data && act.data.supplier_id) actorSet.add(act.data.supplier_id);
        if (act.data && act.data.contact_id) actorSet.add(act.data.contact_id);
      }
      result.push({
        id: sb.id,
        item_sku: sb.item_sku,
        quantity: sb.quantity,
        suppliers: Array.from(actorSet).filter(a => {
          const s = suppliers[a];
          return s && s.type !== "artisan";
        }),
        artisans: Array.from(actorSet).filter(a => {
          const s = suppliers[a];
          return s && s.type === "artisan";
        }),
        depth
      });
      const deeper = await buildAncestors(sid, depth + 1, maxDepth);
      result.push(...deeper);
    }
    return result;
  }

  async function buildDescendants(id, depth, maxDepth) {
    if (depth > maxDepth) return [];
    const b = await getBatch(env, id);
    if (!b) return [];
    const result = [];
    const childIds = b.child_batch_ids || [];
    for (const cid of childIds) {
      const cb = await getBatch(env, cid);
      if (!cb) continue;
      result.push({
        id: cb.id,
        item_sku: cb.item_sku,
        quantity: cb.quantity,
        depth
      });
      const deeper = await buildDescendants(cid, depth + 1, maxDepth);
      result.push(...deeper);
    }
    return result;
  }

  return jsonResponse({
    ok: true,
    root: {
      id: batch.id,
      item_sku: batch.item_sku,
      quantity: batch.quantity,
      status: batch.status,
      depth: 0
    },
    ancestors: await buildAncestors(batchId, 1, 5),
    descendants: await buildDescendants(batchId, 1, 5)
  });
}

// ═══════════════════════════════════════════════════════════════════════
// C.5-A.3 HELPERS — Purchase Orders + Restock + Suggested
// ═══════════════════════════════════════════════════════════════════════

const PO_STATUSES = ["draft", "sent", "partially_received", "received", "cancelled"];

function generatePOId() {
  return "po-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6);
}
__name(generatePOId, "generatePOId");

async function getPO(env, id) {
  const raw = await env.POTISSE_NFC.get(`stock_po_${id}`);
  return raw ? JSON.parse(raw) : null;
}
__name(getPO, "getPO");

async function putPO(env, po) {
  await env.POTISSE_NFC.put(`stock_po_${po.id}`, JSON.stringify(po));
}
__name(putPO, "putPO");

async function listPOs(env) {
  const keys = await env.POTISSE_NFC.list({ prefix: "stock_po_" });
  const pos = [];
  for (const k of keys.keys || []) {
    const raw = await env.POTISSE_NFC.get(k.name);
    if (raw) { try { pos.push(JSON.parse(raw)); } catch {} }
  }
  return pos.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
}
__name(listPOs, "listPOs");

async function getStockSuppliersForPO(env) {
  const raw = await env.POTISSE_NFC.get("stock_suppliers");
  return raw ? JSON.parse(raw) : { suppliers: {} };
}
__name(getStockSuppliersForPO, "getStockSuppliersForPO");

async function getStockItemBySku(env, sku) {
  const raw = await env.POTISSE_NFC.get(`stock_item_${sku}`);
  return raw ? JSON.parse(raw) : null;
}
__name(getStockItemBySku, "getStockItemBySku");

async function handleAdminStockPOsList(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  try {
    const pos = await listPOs(env);
    return jsonResponse({ ok: true, pos });
  } catch (err) {
    console.error("[stock/pos/list] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminStockPOsList, "handleAdminStockPOsList");

async function handleAdminStockPOCreate(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch {
    return jsonResponse({ error: "invalid_json" }, 400);
  }
  const { supplier_id, items, currency, notes } = body || {};
  if (!supplier_id || !Array.isArray(items) || items.length === 0) {
    return jsonResponse({ error: "missing_fields", detail: "supplier_id and items array required" }, 400);
  }
  const suppliersData = await getStockSuppliersForPO(env);
  if (!suppliersData.suppliers || !suppliersData.suppliers[supplier_id]) {
    return jsonResponse({ error: "supplier_not_found" }, 404);
  }
  let totalCost = 0;
  const poItems = [];
  for (const it of items) {
    const item = await getStockItemBySku(env, it.item_sku);
    if (!item) return jsonResponse({ error: "item_not_found", sku: it.item_sku }, 400);
    const qty = parseInt(it.quantity_ordered, 10) || 0;
    const cost = parseFloat(it.unit_cost) || 0;
    if (qty <= 0) return jsonResponse({ error: "invalid_quantity", sku: it.item_sku }, 400);
    totalCost += qty * cost;
    poItems.push({ item_sku: it.item_sku, item_name: item.name || it.item_sku, quantity_ordered: qty, quantity_received: 0, unit_cost: cost });
  }
  const now = new Date().toISOString();
  const po = { id: generatePOId(), supplier_id, status: "draft", items: poItems, total_cost: parseFloat(totalCost.toFixed(2)), currency: currency || "EUR", notes: notes || "", created_at: now, updated_at: now, sent_at: null, received_at: null };
  await putPO(env, po);
  return jsonResponse({ ok: true, po }, 201);
}
__name(handleAdminStockPOCreate, "handleAdminStockPOCreate");

async function handleAdminStockPOGet(request, env, url, poId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const po = await getPO(env, poId);
  if (!po) return jsonResponse({ error: "po_not_found" }, 404);
  return jsonResponse({ ok: true, po });
}
__name(handleAdminStockPOGet, "handleAdminStockPOGet");

async function handleAdminStockPOUpdate(request, env, url, poId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const po = await getPO(env, poId);
  if (!po) return jsonResponse({ error: "po_not_found" }, 404);
  if (po.status !== "draft") return jsonResponse({ error: "po_not_editable", status: po.status }, 409);
  let body;
  try { body = await request.json(); } catch {
    return jsonResponse({ error: "invalid_json" }, 400);
  }
  const { items, currency, notes } = body || {};
  if (items) {
    if (!Array.isArray(items) || items.length === 0) return jsonResponse({ error: "invalid_items" }, 400);
    let totalCost = 0;
    const poItems = [];
    for (const it of items) {
      const item = await getStockItemBySku(env, it.item_sku);
      if (!item) return jsonResponse({ error: "item_not_found", sku: it.item_sku }, 400);
      const qty = parseInt(it.quantity_ordered, 10) || 0;
      const cost = parseFloat(it.unit_cost) || 0;
      if (qty <= 0) return jsonResponse({ error: "invalid_quantity", sku: it.item_sku }, 400);
      totalCost += qty * cost;
      poItems.push({ item_sku: it.item_sku, item_name: item.name || it.item_sku, quantity_ordered: qty, quantity_received: 0, unit_cost: cost });
    }
    po.items = poItems;
    po.total_cost = parseFloat(totalCost.toFixed(2));
  }
  if (currency !== undefined) po.currency = currency;
  if (notes !== undefined) po.notes = notes;
  po.updated_at = new Date().toISOString();
  await putPO(env, po);
  return jsonResponse({ ok: true, po });
}
__name(handleAdminStockPOUpdate, "handleAdminStockPOUpdate");

async function handleAdminStockPODelete(request, env, url, poId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const po = await getPO(env, poId);
  if (!po) return jsonResponse({ error: "po_not_found" }, 404);
  if (po.status !== "draft") return jsonResponse({ error: "po_not_deletable", status: po.status }, 409);
  await env.POTISSE_NFC.delete(`stock_po_${poId}`);
  return jsonResponse({ ok: true, deleted: poId });
}
__name(handleAdminStockPODelete, "handleAdminStockPODelete");

async function handleAdminStockPOSubmit(request, env, url, poId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const po = await getPO(env, poId);
  if (!po) return jsonResponse({ error: "po_not_found" }, 404);
  if (po.status !== "draft") return jsonResponse({ error: "invalid_transition", from: po.status, to: "sent" }, 409);
  po.status = "sent";
  po.sent_at = new Date().toISOString();
  po.updated_at = po.sent_at;
  await putPO(env, po);
  return jsonResponse({ ok: true, po });
}
__name(handleAdminStockPOSubmit, "handleAdminStockPOSubmit");

async function handleAdminStockPOReceive(request, env, url, poId) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const po = await getPO(env, poId);
  if (!po) return jsonResponse({ error: "po_not_found" }, 404);
  if (po.status === "draft" || po.status === "cancelled") {
    return jsonResponse({ error: "po_not_receivable", status: po.status }, 409);
  }
  let body;
  try { body = await request.json(); } catch {
    return jsonResponse({ error: "invalid_json" }, 400);
  }
  const { items: receivedItems } = body || {};
  if (!Array.isArray(receivedItems) || receivedItems.length === 0) {
    return jsonResponse({ error: "missing_received_items" }, 400);
  }
  const now = new Date().toISOString();
  let allFullyReceived = true;
  for (const rec of receivedItems) {
    const poItem = po.items.find(i => i.item_sku === rec.item_sku);
    if (!poItem) return jsonResponse({ error: "item_not_in_po", sku: rec.item_sku }, 400);
    const qty = parseInt(rec.quantity_received, 10) || 0;
    if (qty <= 0) continue;
    const newTotal = (poItem.quantity_received || 0) + qty;
    if (newTotal > poItem.quantity_ordered) {
      return jsonResponse({ error: "over_receive", sku: rec.item_sku, ordered: poItem.quantity_ordered, would_be: newTotal }, 400);
    }
    poItem.quantity_received = newTotal;
    if (newTotal < poItem.quantity_ordered) allFullyReceived = false;
    const item = await getStockItemBySku(env, rec.item_sku);
    if (item) {
      item.quantity = (item.quantity || 0) + qty;
      item.updated_at = now;
      await env.POTISSE_NFC.put(`stock_item_${rec.item_sku}`, JSON.stringify(item));
    }
  }
  if (allFullyReceived && po.items.every(i => (i.quantity_received || 0) >= i.quantity_ordered)) {
    po.status = "received";
    po.received_at = now;
  } else {
    po.status = "partially_received";
  }
  po.updated_at = now;
  await putPO(env, po);
  return jsonResponse({ ok: true, po });
}
__name(handleAdminStockPOReceive, "handleAdminStockPOReceive");

async function handleAdminStockSuggested(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  try {
    const list = await env.POTISSE_NFC.list({ prefix: "stock_item_" });
    const suggested = [];
    for (const k of list.keys || []) {
      const raw = await env.POTISSE_NFC.get(k.name);
      if (!raw) continue;
      try {
        const item = JSON.parse(raw);
        if (!item) continue;
        const minT = parseFloat(item.min_threshold) || 0;
        const critT = parseFloat(item.critical_threshold) || 0;
        const current = parseFloat(item.quantity) || 0;
        if (minT > 0 && current <= minT) {
          suggested.push({
            item_sku: item.sku, item_name: item.name || item.sku,
            current_stock: current, min_threshold: minT, critical_threshold: critT,
            suggested_qty: Math.max(minT * 2 - current, minT),
            unit_cost: item.unit_cost || null, supplier_id: item.supplier_id || null,
            standard_lead_time_days: item.standard_lead_time_days || 7,
            buffer_days: item.buffer_days || 3,
            urgency: current === 0 ? "out_of_stock" : (current <= critT ? "critical" : "low")
          });
        }
      } catch {}
    }
    suggested.sort((a, b) => {
      const order = { out_of_stock: 0, critical: 1, low: 2 };
      if (order[a.urgency] !== order[b.urgency]) return order[a.urgency] - order[b.urgency];
      return a.current_stock - b.current_stock;
    });
    return jsonResponse({ ok: true, suggested, count: suggested.length });
  } catch (err) {
    console.error("[stock/suggested] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminStockSuggested, "handleAdminStockSuggested");

async function handleAdminStockRestockStatus(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  try {
    const list = await env.POTISSE_NFC.list({ prefix: "stock_item_" });
    const allBatchKeys = await env.POTISSE_NFC.list({ prefix: "stock_batch_" });
    const stockReadyBySku = {};
    for (const bk of allBatchKeys.keys || []) {
      const raw = await env.POTISSE_NFC.get(bk.name);
      if (!raw) continue;
      try {
        const batch = JSON.parse(raw);
        if (batch.status === "stock_ready" && batch.item_sku) {
          stockReadyBySku[batch.item_sku] = (stockReadyBySku[batch.item_sku] || 0) + (batch.quantity || 0);
        }
      } catch {}
    }
    const results = [];
    for (const k of list.keys || []) {
      const raw = await env.POTISSE_NFC.get(k.name);
      if (!raw) continue;
      try {
        const item = JSON.parse(raw);
        if (!item) continue;
        const qtyAvailable = stockReadyBySku[item.sku] || 0;
        const minT = parseFloat(item.min_threshold) || 0;
        const critT = parseFloat(item.critical_threshold) || 0;
        const leadTime = parseFloat(item.standard_lead_time_days) || 7;
        const buffer = parseFloat(item.buffer_days) || 3;
        const umbralCritico = leadTime + buffer;
        const avgDailySales30d = 0;
        let urgencyLevel;
        if (qtyAvailable === 0 && avgDailySales30d > 0) urgencyLevel = "out_of_stock";
        else if (qtyAvailable <= critT) urgencyLevel = "order_now";
        else if (qtyAvailable <= minT) urgencyLevel = "order_soon";
        else if (avgDailySales30d === 0) urgencyLevel = "healthy";
        else {
          const daysRemaining = qtyAvailable / avgDailySales30d;
          if (daysRemaining < umbralCritico) urgencyLevel = "order_now";
          else if (daysRemaining < umbralCritico * 1.5) urgencyLevel = "order_soon";
          else if (daysRemaining < umbralCritico * 3) urgencyLevel = "plan_to_order";
          else urgencyLevel = "healthy";
        }
        results.push({ item_sku: item.sku, item_name: item.name || item.sku, qty_available: qtyAvailable, min_threshold: minT, critical_threshold: critT, standard_lead_time_days: leadTime, buffer_days: buffer, umbral_critico_days: umbralCritico, avg_daily_sales_30d: avgDailySales30d, urgency_level: urgencyLevel });
      } catch {}
    }
    results.sort((a, b) => {
      const order = { out_of_stock: 0, order_now: 1, order_soon: 2, plan_to_order: 3, healthy: 4 };
      return order[a.urgency_level] - order[b.urgency_level];
    });
    return jsonResponse({ ok: true, items: results, count: results.length });
  } catch (err) {
    console.error("[stock/restock-status] error:", err.message);
    return jsonResponse({ error: "internal_error" }, 500);
  }
}
__name(handleAdminStockRestockStatus, "handleAdminStockRestockStatus");

async function handleAdminStockItemsMigrate(request, env, url) {
  if (url.searchParams.get("admin") !== env.ADMIN_KEY) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const alreadyMigrated = await env.POTISSE_NFC.get("stock_items_migrated_v6.12.3");
  if (alreadyMigrated) return jsonResponse({ ok: true, migrated: false, reason: "already_migrated" });
  const oldRaw = await env.POTISSE_NFC.get("stock_items");
  if (!oldRaw) {
    await env.POTISSE_NFC.put("stock_items_migrated_v6.12.3", "true");
    return jsonResponse({ ok: true, migrated: false, reason: "no_old_data" });
  }
  try {
    const oldData = JSON.parse(oldRaw);
    let count = 0;
    for (const id in (oldData.items || {})) {
      const oldItem = oldData.items[id];
      if (oldItem && oldItem.sku) {
        const newItem = { ...oldItem, quantity: oldItem.current_stock || oldItem.quantity || 0, standard_lead_time_days: 7, buffer_days: 3, origin_type: "local", is_shopify_master: false, shopify_variant_id: null, created_by: oldItem.created_by || "admin" };
        delete newItem.type;
        delete newItem.current_stock;
        if (oldItem.unit_of_measure && !newItem.unit) newItem.unit = oldItem.unit_of_measure;
        await env.POTISSE_NFC.put(`stock_item_${oldItem.sku}`, JSON.stringify(newItem));
        count++;
      }
    }
    await env.POTISSE_NFC.put("stock_items_migrated_v6.12.3", "true");
    await env.POTISSE_NFC.delete("stock_items");
    return jsonResponse({ ok: true, migrated: true, count });
  } catch (err) {
    console.error("[stock/items/migrate] error:", err.message);
    return jsonResponse({ error: "migrate_failed", detail: err.message }, 500);
  }
}
__name(handleAdminStockItemsMigrate, "handleAdminStockItemsMigrate");
__name(handleAdminStockBatchGenealogy, "handleAdminStockBatchGenealogy");
