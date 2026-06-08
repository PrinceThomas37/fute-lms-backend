/**
 * Per-mailbox HTML signatures (stored in app_settings as ue_{userEmailId}_signature_html).
 * Variables: {{sender}} = display name, {{senderemail}} = mailbox address.
 */

const DEFAULT_SIGNATURE_HTML = `<div style="font-family:Arial,sans-serif;font-size:13px;color:#222;line-height:1.6"><p style="margin:0"><strong>{{sender}}</strong><br><span style="color:#555;font-size:12px">BD Manager, Fute Global LLC</span><br><br><a href="mailto:{{senderemail}}" style="color:#1E7A3C;text-decoration:none">{{senderemail}}</a><br><span style="color:#555">+1 (972)-452-6644</span><br><a href="https://www.futeglobal.com/" style="color:#1E7A3C;text-decoration:none">www.futeglobal.com</a></p></div>`;

function mailboxSignatureKey(userEmailId) {
  return `ue_${userEmailId}_signature_html`;
}

function legacyUserSignatureKey(userId) {
  return `u_${userId}_signature_html`;
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
  return val || DEFAULT_SIGNATURE_HTML;
}

module.exports = {
  DEFAULT_SIGNATURE_HTML,
  mailboxSignatureKey,
  legacyUserSignatureKey,
  fillSignatureHtml,
  resolveSignatureHtml
};
