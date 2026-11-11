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

/**
 * Reply poller: reads owner replies from Gmail and hands them to the bridge (no IMAP / app password needed).
 * One-time setup: Script properties -> add BRIDGE_INBOUND_URL = https://<your-bridge>/mail/inbound
 * then pick "setupTrigger" in the editor toolbar and press Run (approve the permissions).
 */
function setupTrigger() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'pollReplies') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('pollReplies').timeBased().everyMinutes(1).create();
}

function pollReplies() {
  var props = PropertiesService.getScriptProperties();
  var url = props.getProperty('BRIDGE_INBOUND_URL');
  var secret = props.getProperty('RELAY_SECRET');
  if (!url || !secret) return;

  var done = JSON.parse(props.getProperty('DONE_IDS') || '[]');
  var doneSet = {};
  done.forEach(function (id) { doneSet[id] = true; });

  var threads = GmailApp.search('newer_than:2d', 0, 30);
  var groups = GmailApp.getMessagesForThreads(threads);
  var changed = false;
  for (var i = 0; i < groups.length; i++) {
    for (var j = 0; j < groups[i].length; j++) {
      var msg = groups[i][j];
      var id = msg.getId();
      if (doneSet[id]) continue;
      var recipients = (msg.getTo() || '') + ' ' + (msg.getCc() || '');
      if (!/\+t_[a-f0-9]{16}@/i.test(recipients)) continue; // not a reply to a SIONYX inquiry

      var raw = msg.getRawContent();
      var cut = raw.search(/\r?\n\r?\n/);
      var res = UrlFetchApp.fetch(url, {
        method: 'post',
        contentType: 'application/json',
        payload: JSON.stringify({ secret: secret, headers: cut > 0 ? raw.substring(0, cut) : raw, text: msg.getPlainBody() }),
        muteHttpExceptions: true
      });
      if (res.getResponseCode() === 200) { // handled (delivered or definitively rejected): never send again
        done.push(id);
        doneSet[id] = true;
        changed = true;
      } // otherwise (bridge asleep/error) it is retried on the next run while it is within the 2-day window
    }
  }
  if (changed) props.setProperty('DONE_IDS', JSON.stringify(done.slice(-300)));
}
