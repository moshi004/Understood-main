/**
 * HTTPS mail relay for the SIONYX bridge (Render blocks SMTP ports on the free tier).
 *
 * Setup: script.google.com -> New project (signed in as the SAME Gmail account as GMAIL_USER) -> paste this file.
 * Project Settings -> Script properties -> add RELAY_SECRET = a long random string (same value as MAIL_RELAY_SECRET on Render).
 * Deploy -> New deployment -> type "Web app", Execute as: Me, Who has access: Anyone. Copy the /exec URL to MAIL_RELAY_URL.
 * Note: free Gmail accounts may send about 100 mails/day through Apps Script (Workspace: about 1500).
 */
function doGet() {
  return json_({ ok: true });
}

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);
    var secret = PropertiesService.getScriptProperties().getProperty('RELAY_SECRET');
    if (!secret || data.secret !== secret) return json_({ ok: false, error: 'unauthorized' });
    if (!data.to || !data.subject) return json_({ ok: false, error: 'missing to/subject' });
    var options = { name: data.name || 'SIONYX' };
    if (data.replyTo) options.replyTo = data.replyTo;
    GmailApp.sendEmail(data.to, data.subject, data.text || '', options);
    return json_({ ok: true });
  } catch (err) {
    return json_({ ok: false, error: String(err) });
  }
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
