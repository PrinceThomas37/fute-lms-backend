// Email open/reply tracking helpers (slice 1 — infrastructure).
// Pure, dependency-light helpers shared by the tracking route (records opens)
// and, later, the send path (embeds the pixel). No DB access here.
const crypto = require('crypto');

// A 1x1 fully-transparent GIF returned by the tracking endpoint.
const TRANSPARENT_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

function newToken() { return crypto.randomBytes(16).toString('hex'); }

// The public base URL the pixel points back at. Prefers explicit env config,
// falls back to the known Render host.
function resolveBaseUrl() {
  const raw = process.env.PUBLIC_BASE_URL || process.env.APP_BASE_URL ||
    process.env.RENDER_EXTERNAL_URL || 'https://fute-lms-backend.onrender.com';
  return String(raw).replace(/\/+$/, '');
}

function pixelUrl(token, baseUrl) {
  return (baseUrl || resolveBaseUrl()) + '/o/' + encodeURIComponent(token) + '.gif';
}

// The tracking pixel markup. Hidden, no layout impact.
function pixelHtml(token, baseUrl) {
  return '<img src="' + pixelUrl(token, baseUrl) + '" width="1" height="1" alt="" ' +
    'style="display:none;width:1px;height:1px;border:0;overflow:hidden" />';
}

// Insert the pixel just before </body> when present, else append.
function injectPixel(html, token, baseUrl) {
  const img = pixelHtml(token, baseUrl);
  if (typeof html !== 'string' || !html) return String(html || '') + img;
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, img + '</body>');
  return html + img;
}

module.exports = { TRANSPARENT_GIF, newToken, resolveBaseUrl, pixelUrl, pixelHtml, injectPixel };
