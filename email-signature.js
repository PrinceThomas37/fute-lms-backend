/**
 * Per-mailbox HTML signatures (stored in app_settings as ue_{userEmailId}_signature_html).
 * Variables: {{sender}} = display name, {{senderemail}} = mailbox address.
 */

const DEFAULT_SIGNATURE_HTML = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;line-height:1.45"><p style="margin:0 0 3px"><strong>{{sender}}</strong></p><p style="margin:0 0 3px;color:#333">Recruitment Manager | <strong>Fute Global LLC</strong></p><p style="margin:0 0 3px;color:#333"><a href="mailto:{{senderemail}}" style="color:#1E7A3C;text-decoration:none">{{senderemail}}</a> | +1 (972)-452-6644 | <a href="https://www.futeglobal.com/" style="color:#1E7A3C;text-decoration:none">www.futeglobal.com</a></p><p style="margin:0;color:#555;font-size:12px;font-style:italic">Making Recruitment Easier with Future Tech</p></div>`;

function mailboxSignatureKey(userEmailId) {
  return `ue_${userEmailId}_signature_html`;
}

function legacyUserSignatureKey(userId) {
  return `u_${userId}_signature_html`;
}

const SIGNATURE_TAGLINE = 'Making Recruitment Easier with Future Tech';
const LEGACY_SIGNATURE_TAGLINES = [
  'Staffing solutions for healthcare & enterprise',
  'Staffing solutions for healthcare &amp; enterprise'
];

function isLegacyBlockSignature(signatureHtml) {
  const html = String(signatureHtml || '');
  return /&#128231;|&#128222;|&#127760;|&#128205;/.test(html)
    || /border-right:3px solid #1E7A3C/.test(html);
}

function upgradeSignatureTagline(signatureHtml) {
  let html = String(signatureHtml || '');
  LEGACY_SIGNATURE_TAGLINES.forEach((oldTagline) => {
    html = html.split(oldTagline).join(SIGNATURE_TAGLINE);
  });
  return html.replace(
    /Staffing solutions for healthcare(?:\s*(?:&amp;|&)\s*)?enterprise/gi,
    SIGNATURE_TAGLINE
  );
}

function fillSignatureHtml(signatureHtml, { displayName, emailAddress }) {
  const sender = displayName || '';
  const senderEmail = emailAddress || '';
  return String(signatureHtml || '')
    .replace(/{{sender}}/g, sender)
    .replace(/{{senderemail}}/g, senderEmail);
}

function resolveSignatureHtml(savedHtml) {
  const val = String(savedHtml || '').trim();
  if (!val) return DEFAULT_SIGNATURE_HTML;
  if (isLegacyBlockSignature(val)) return DEFAULT_SIGNATURE_HTML;
  return upgradeSignatureTagline(val);
}

module.exports = {
  DEFAULT_SIGNATURE_HTML,
  mailboxSignatureKey,
  legacyUserSignatureKey,
  SIGNATURE_TAGLINE,
  isLegacyBlockSignature,
  upgradeSignatureTagline,
  fillSignatureHtml,
  resolveSignatureHtml
};
