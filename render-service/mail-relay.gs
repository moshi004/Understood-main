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
    if (data.action === 'poll') return json_(pollMessages_());
    if (data.action === 'ack') return json_(ackMessages_(data.ids));
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

/**
 * Replies: the bridge calls this web app with {action:'poll'} and gets the new owner replies found in Gmail,
 * then confirms the handled ones with {action:'ack', ids:[...]}. No trigger and no outgoing fetch needed.
 * Run pollMessages_ once from the editor to approve the Gmail read permission, then redeploy a new version.
 */
function splitHeaders_(raw) {
  var CR = String.fromCharCode(13);
  var LF = String.fromCharCode(10);
  var cut = raw.indexOf(CR + LF + CR + LF);
  if (cut < 0) cut = raw.indexOf(LF + LF);
  return cut > 0 ? raw.substring(0, cut) : raw;
}

function pollMessages_() {
  var done = JSON.parse(PropertiesService.getScriptProperties().getProperty('DONE_IDS') || '[]');
  var out = [];
  var groups = GmailApp.getMessagesForThreads(GmailApp.search('newer_than:2d', 0, 30));
  for (var i = 0; i < groups.length; i++) {
    for (var j = 0; j < groups[i].length; j++) {
      var msg = groups[i][j];
      var id = msg.getId();
      if (done.indexOf(id) > -1) continue;
      var to = (msg.getTo() || '') + ' ' + (msg.getCc() || '');
      if (to.indexOf('+t_') < 0) continue; // not a reply to a SIONYX inquiry
      out.push({ id: id, headers: splitHeaders_(msg.getRawContent()), text: msg.getPlainBody() });
      if (out.length >= 10) return { ok: true, messages: out };
    }
  }
  return { ok: true, messages: out };
}

function ackMessages_(ids) {
  var props = PropertiesService.getScriptProperties();
  var done = JSON.parse(props.getProperty('DONE_IDS') || '[]');
  for (var i = 0; i < (ids || []).length; i++) done.push(ids[i]);
  props.setProperty('DONE_IDS', JSON.stringify(done.slice(-300)));
  return { ok: true };
}
