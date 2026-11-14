/**
 * Email copy of kiosk inquiries + email replies back into the kiosk.
 *
 * Flow:
 *   kiosk user sends a reply to the admin  ->  organizations/{org}/userReplies/{key}
 *   this module (Firebase listener)        ->  email to the org's inquiry address
 *       Reply-To = <GMAIL_USER>+t_<tid>@gmail.com   (tid = HMAC(org|user), unguessable)
 *   owner answers by email                 ->  Gmail (IMAP IDLE)
 *   this module                            ->  organizations/{org}/messages/{push}  (toUserId = the user)
 *   the kiosk already shows organizations/{org}/messages, so no kiosk change is needed.
 *
 * Sending: HTTPS relay (Google Apps Script, MAIL_RELAY_URL) when set - Render's free tier blocks SMTP ports -
 * otherwise Gmail SMTP with an app password. Receiving: Gmail IMAP (port 993, not blocked).
 *
 * Env (everything optional; the module stays off unless GMAIL_USER and MAIL_HMAC_SECRET are set):
 *   GMAIL_USER, GMAIL_APP_PASSWORD   mailbox that sends + receives (replies need the app password)
 *   MAIL_HMAC_SECRET                 long random string; derives the per-user reply address
 *   MAIL_RELAY_URL, MAIL_RELAY_SECRET  Apps Script web app used for sending
 *   MAIL_REPLY_POLL_SECONDS          safety-net IMAP scan interval (default 60)
 *
 * Firebase paths used (admin SDK only - not reachable from clients, no rules entry = denied):
 *   mailBridge/enabledSince          ms timestamp, set once; older replies are never emailed
 *   mailBridge/sent/{org}/{replyKey} claim marker so a reply is emailed exactly once
 *   mailBridge/threads/{tid}         {orgId, userId} - resolves an incoming reply address
 *
 * Supervisor message copies (Annex A 3.4) - second outgoing flow:
 *   supervisor sends a message                ->  organizations/{org}/messages/{key}  {fromSupervisor: true, fromAdminId: <supervisor uid>, toUserId}
 *   this module (Firebase listener)           ->  email copy to
 *       (a) the org's inquiry address, ONLY when organizations/{org}/metadata/supervision/mailCopy/enabled === true
 *           (Reply-To = same per-user tag as above, so the org can answer and the answer reaches that user)
 *       (b) the supervisor's own address, when supervisors/{uid}/mailCopy = {email, enabled !== false} (copy only, no reply)
 *   Off by default: an org without the switch and a supervisor without an address send nothing.
 *   mailBridge/supervisorCopySince           ms timestamp, set once; older supervisor messages are never emailed
 *   mailBridge/sentSupervisor/{org}/{key}/{org|sup}   per-recipient claim marker, so each copy is sent exactly once
 *
 * Inquiry address per org: organizations/{org}/metadata/settings/inquiries/email,
 * falling back to metadata/admin_email. settings/inquiries/enabled === false turns it off.
 */
"use strict";

const crypto = require("crypto");
const nodemailer = require("nodemailer");
const {ImapFlow} = require("imapflow");
const {simpleParser} = require("mailparser");

const env = process.env;
const num = (v, d) => (v !== undefined && v !== "" && !Number.isNaN(Number(v)) ? Number(v) : d);

const cfg = {
  user: (env.GMAIL_USER || "").trim(),
  pass: (env.GMAIL_APP_PASSWORD || "").replace(/\s+/g, ""),
  secret: env.MAIL_HMAC_SECRET || "",
  relayUrl: (env.MAIL_RELAY_URL || "").trim(),
  relaySecret: (env.MAIL_RELAY_SECRET || "").trim(),
  pollSeconds: num(env.MAIL_REPLY_POLL_SECONDS, 60),
  fromName: env.MAIL_FROM_NAME || "SIONYX",
};

const BACKFILL_MS = 48 * 60 * 60 * 1000; // after a restart/sleep, look back this far (bounded by enabledSince)
const ORG_REFRESH_MS = 10 * 60 * 1000; // pick up newly registered orgs
const MAX_SEND_ATTEMPTS = 5;
const TAG = /\+t_([a-f0-9]{16})@/i;
const TAGGED = /\+t_/i;
const SUBJECT_TAG = /#t_([a-f0-9]{16})/i;
const SCAN_TIMEOUT_MS = 60 * 1000;

const state = {
  enabled: false,
  sendMode: null, // 'relay' | 'smtp'
  imapConnected: false,
  imapLastScanAt: 0,
  lastError: null,
  orgsWatched: 0,
  repliesSeen: 0,
  lastSeen: null,
  lastSkip: null,
  emailsSent: 0,
  supervisorCopiesSent: 0,
  repliesReceived: 0,
  inboundCalls: 0,
  lastInbound: null,
  scriptPolls: 0,
  lastScriptPollAt: 0,
  lastScriptPollError: null,
};

const log = (...a) => console.log(new Date().toISOString(), "[mail]", ...a); // eslint-disable-line no-console

// ───────────────────────── helpers ─────────────────────────

const stripBidi = (s) => String(s || "").replace(/[‎‏‪-‮⁦-⁩]/g, "");

function tidFor(orgId, userId) {
  return crypto.createHmac("sha256", cfg.secret).update(`${orgId}|${userId}`).digest("hex").slice(0, 16);
}

function replyToFor(tid) {
  const [local, domain] = cfg.user.split("@");
  return `${local}+t_${tid}@${domain}`;
}

// Keep only the new text of an emailed reply: cut quoted history and the pasted bridge address.
function extractReplyText(plainBody) {
  let text = stripBidi(plainBody).replace(/\r\n/g, "\n");
  const cutMarkers = [
    /\n[^\n]*On [^\n]*(?:\n[^\n]*)?wrote:[\s\S]*/i, // Gmail wraps this line, so it may span two lines
    /\n[^\n]*(?:כתב|כתבה|כתב\/ה)\s*:\s*\n[\s\S]*/, // Hebrew Gmail: "... כתב/ה:"
    /\nבתאריך[\s\S]*/,
    /\n-----Original Message-----[\s\S]*/i,
    /\n>[\s\S]*/,
  ];
  for (const m of cutMarkers) {
    const i = text.search(m);
    if (i !== -1) text = text.substring(0, i);
  }
  text = text.replace(/[\w.\-]*\+t_[a-f0-9]{16}@[\w.\-]+/gi, "");
  return text.trim();
}

function authResultsLine(parsed) {
  const lines = (parsed.headerLines || []).filter((h) => h.key === "authentication-results");
  return lines.length ? String(lines[0].line || "") : "";
}

// Gmail's own (topmost) Authentication-Results header must show DKIM/SPF/DMARC pass for the sender's domain.
function isAuthenticated(authLine, fromDomain) {
  if (!/mx\.google\.com/i.test(authLine) || !fromDomain) return false;
  if (/\bdmarc=pass\b/i.test(authLine)) return true;
  const d = authLine.match(/\bdkim=pass[^;]*?header\.(?:d|i)=@?([^\s;]+)/i);
  if (d && d[1].toLowerCase().endsWith(fromDomain)) return true;
  const sp = authLine.match(/\bspf=pass[^;]*?smtp\.mailfrom=(?:[^\s@;]*@)?([^\s;]+)/i);
  return !!(sp && sp[1].toLowerCase() === fromDomain);
}

function describeErr(e) {
  const parts = [e.message];
  if (e.authenticationFailed) parts.push("(authentication failed)");
  const detail = e.responseText || e.response || e.serverResponseCode;
  if (detail) parts.push(String(detail).trim());
  if (e.code) parts.push("code=" + e.code);
  return parts.join(" ");
}

function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => reject(new Error(`${label} timed out after ${ms / 1000}s`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

// ───────────────────────── sending ─────────────────────────

let smtp = null;

async function relayCall(body) {
  if (!cfg.relaySecret) throw new Error("MAIL_RELAY_SECRET not set");
  const res = await fetch(cfg.relayUrl, {
    method: "POST",
    redirect: "follow",
    // text/plain avoids a CORS preflight; Apps Script parses the JSON itself
    headers: {"Content-Type": "text/plain"},
    body: JSON.stringify({secret: cfg.relaySecret, ...body}),
    signal: AbortSignal.timeout(60000),
  });
  const raw = await res.text();
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(`relay: invalid response (HTTP ${res.status}) - is the Apps Script deployed as "Anyone" (new version)?`);
  }
  if (!data.ok) throw new Error("relay: " + (data.error || "unknown error"));
  return data;
}

async function sendViaRelay({to, subject, text, replyTo}) {
  await relayCall({to, subject, text, replyTo, name: cfg.fromName});
}

async function sendMail(message) {
  if (cfg.relayUrl) return sendViaRelay(message);
  if (!smtp) {
    smtp = nodemailer.createTransport({
      host: "smtp.gmail.com", port: 465, secure: true, auth: {user: cfg.user, pass: cfg.pass},
    });
  }
  return smtp.sendMail({
    from: {name: cfg.fromName, address: cfg.user},
    to: message.to, subject: message.subject, text: message.text, replyTo: message.replyTo,
  });
}

// ───────────────────────── org settings ─────────────────────────

async function inquiryEmailFor(db, orgId) {
  const snap = await db.ref(`organizations/${orgId}/metadata`).once("value");
  const meta = snap.val() || {};
  const s = (meta.settings && meta.settings.inquiries) || {};
  if (s.enabled === false) return {email: null, orgName: meta.name || ""};
  const email = String(s.email || meta.admin_email || "").trim().toLowerCase();
  return {email: /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ? email : null, orgName: meta.name || ""};
}

// ───────────────────────── outgoing: new kiosk reply -> email ─────────────────────────

function makeOutgoing(admin) {
  const db = admin.database();
  const retries = new Map(); // `${org}/${key}` -> attempts

  // every skip is logged and shown in /mail/health (lastSkip) so a missing email can always be explained
  function skip(orgId, key, reason) {
    state.lastSkip = {at: Date.now(), org: orgId, key, reason};
    log(`skip org=${orgId} key=${key}: ${reason}`);
  }

  async function handleReply(orgId, key, r, enabledSince) {
    state.repliesSeen++;
    state.lastSeen = {at: Date.now(), org: orgId, key};
    log(`reply seen org=${orgId} key=${key}`);
    if (!r) return skip(orgId, key, "empty record");
    if (r.fromSupervisorReply === true) return skip(orgId, key, "addressed to supervisor, not the org admin");
    if (!r.fromUserId) return skip(orgId, key, "no fromUserId");
    const message = stripBidi(r.message).trim();
    if (!message) return skip(orgId, key, "empty message");
    if (!(Number(r.timestamp) >= enabledSince)) {
      return skip(orgId, key, `timestamp ${JSON.stringify(r.timestamp)} is not a number >= enabledSince ${enabledSince} (older, or kiosk clock behind)`);
    }

    const claim = await db.ref(`mailBridge/sent/${orgId}/${key}`).transaction((cur) => (cur === null ? {at: Date.now()} : undefined));
    if (!claim.committed) return skip(orgId, key, "already handled earlier");

    const {email, orgName} = await inquiryEmailFor(db, orgId);
    if (!email) {
      await db.ref(`mailBridge/sent/${orgId}/${key}`).set({at: Date.now(), skipped: "no-email"});
      return skip(orgId, key, "no valid inquiry email for this org (settings/inquiries/email or admin_email), or disabled");
    }

    try {
      const userSnap = await db.ref(`organizations/${orgId}/users/${r.fromUserId}`).once("value");
      const u = userSnap.val() || {};
      const name = [u.firstName, u.lastName].filter(Boolean).join(" ").trim() || "משתמש";
      const tid = tidFor(orgId, r.fromUserId);
      await db.ref(`mailBridge/threads/${tid}`).set({orgId, userId: r.fromUserId});

      const dept = r.department ? `מחלקה: ${r.department}\n` : "";
      const text =
        `פנייה חדשה במערכת SIONYX${orgName ? ` - ${orgName}` : ""}\n` +
        `מאת: ${name}\n${dept}\n${message}\n\n` +
        `———\nלהשיב למשתמש: פשוט השב למייל הזה. התשובה תופיע אצלו בקיוסק.\n` +
        `אל תשנה את כתובת התגובה ואל תעביר את המייל הלאה.`;

      await sendMail({to: email, subject: `[SIONYX] פנייה חדשה מ-${name} #t_${tid}`, text, replyTo: replyToFor(tid)});
      state.emailsSent++;
      retries.delete(`${orgId}/${key}`);
      log(`sent inquiry org=${orgId} key=${key}`);
    } catch (e) {
      state.lastError = describeErr(e);
      await db.ref(`mailBridge/sent/${orgId}/${key}`).remove().catch(() => {});
      const id = `${orgId}/${key}`;
      const n = (retries.get(id) || 0) + 1;
      retries.set(id, n);
      log(`send failed (${n}/${MAX_SEND_ATTEMPTS}) org=${orgId} key=${key}: ${state.lastError}`);
      if (n < MAX_SEND_ATTEMPTS) setTimeout(() => handleReply(orgId, key, r, enabledSince).catch(() => {}), 2 * 60 * 1000 * n);
    }
  }

  return {handleReply};
}

// ───────────────────────── outgoing: supervisor message -> email copies (3.4) ─────────────────────────

const EMAIL_OK = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/**
 * Pure: who gets a copy of a supervisor message. Nothing unless a switch/address is set.
 *   orgSwitchOn   metadata/supervision/mailCopy/enabled === true
 *   orgEmail      the org's inquiry address (already null when the org disabled inquiries)
 *   supMail       supervisors/{uid}/mailCopy record or null
 */
function copyRecipients({orgSwitchOn, orgEmail, supMail}) {
  const out = [];
  if (orgSwitchOn === true && orgEmail) out.push({kind: "org", to: orgEmail});
  const supEmail = supMail && supMail.enabled !== false ? String(supMail.email || "").trim().toLowerCase() : "";
  if (EMAIL_OK.test(supEmail) && !out.some((r) => r.to === supEmail)) out.push({kind: "sup", to: supEmail});
  return out;
}

/**
 * A supervisor message mirrored into other stores (mirrorOf is set) is the same message: the supervisor already got a
 * copy for the original, so only the store's own copy (org) is kept for the mirror.
 */
function dropSupervisorCopyOnMirror(recipients, m) {
  return m && m.mirrorOf ? recipients.filter((r) => r.kind !== "sup") : recipients;
}

function makeSupervisorCopy(admin) {
  const db = admin.database();
  const retries = new Map(); // `${org}/${key}/${kind}` -> attempts

  async function handleMessage(orgId, key, m, since) {
    if (!m || m.fromSupervisor !== true || m.deleted) return;
    if (!(Number(m.timestamp) >= since)) return;
    const message = stripBidi(m.message).trim();
    if (!message) return;

    const [orgSwitchSnap, supSnap, inq] = await Promise.all([
      db.ref(`organizations/${orgId}/metadata/supervision/mailCopy/enabled`).once("value"),
      m.fromAdminId ? db.ref(`supervisors/${m.fromAdminId}/mailCopy`).once("value") : Promise.resolve({val: () => null}),
      inquiryEmailFor(db, orgId),
    ]);
    const recipients = dropSupervisorCopyOnMirror(
      copyRecipients({orgSwitchOn: orgSwitchSnap.val() === true, orgEmail: inq.email, supMail: supSnap.val()}),
      m
    );
    if (!recipients.length) return; // nothing switched on for this message: stay silent

    let name = "כל המשתמשים";
    let tid = null;
    if (m.toUserId && m.toUserId !== "all") {
      const u = (await db.ref(`organizations/${orgId}/users/${m.toUserId}`).once("value")).val();
      if (u) {
        name = [u.firstName, u.lastName].filter(Boolean).join(" ").trim() || "משתמש";
        tid = tidFor(orgId, m.toUserId);
        await db.ref(`mailBridge/threads/${tid}`).set({orgId, userId: m.toUserId});
      }
    }
    const dept = m.department ? `מחלקה: ${m.department}\n` : "";
    let supName = "";
    if (m.fromAdminId) supName = String((await db.ref(`supervisors/${m.fromAdminId}/displayName`).once("value")).val() || "").trim();

    for (const r of recipients) {
      const claimRef = db.ref(`mailBridge/sentSupervisor/${orgId}/${key}/${r.kind}`);
      const claim = await claimRef.transaction((cur) => (cur === null ? {at: Date.now()} : undefined));
      if (!claim.committed) continue; // this copy was already sent
      const id = `${orgId}/${key}/${r.kind}`;
      try {
        const canReply = r.kind === "org" && tid;
        const text =
          `הודעת מפקח${supName ? ` (${supName})` : ""}${inq.orgName ? ` - ${inq.orgName}` : ""}\n` +
          `אל: ${name}\n${dept}\n${message}\n\n———\n` +
          (canReply
            ? "להשיב למשתמש: פשוט השב למייל הזה. התשובה תופיע אצלו בקיוסק.\nאל תשנה את כתובת התגובה ואל תעביר את המייל הלאה."
            : "זהו עותק לידיעה בלבד.");
        await sendMail({
          to: r.to,
          subject: `[SIONYX] ${r.kind === "org" ? "הודעת מפקח אל" : "עותק הודעה שנשלחה אל"} ${name}${canReply ? ` #t_${tid}` : ""}`,
          text,
          replyTo: canReply ? replyToFor(tid) : undefined,
        });
        state.supervisorCopiesSent++;
        retries.delete(id);
        log(`supervisor copy sent org=${orgId} key=${key} to=${r.kind}`);
      } catch (e) {
        state.lastError = describeErr(e);
        await claimRef.remove().catch(() => {});
        const n = (retries.get(id) || 0) + 1;
        retries.set(id, n);
        log(`supervisor copy failed (${n}/${MAX_SEND_ATTEMPTS}) org=${orgId} key=${key} to=${r.kind}: ${state.lastError}`);
        if (n < MAX_SEND_ATTEMPTS) setTimeout(() => handleMessage(orgId, key, m, since).catch(() => {}), 2 * 60 * 1000 * n);
      }
    }
  }

  return {handleMessage};
}

async function listOrgIds(admin) {
  const app = admin.app();
  const {access_token: token} = await app.options.credential.getAccessToken();
  const res = await fetch(`${app.options.databaseURL}/organizations.json?shallow=true`, {
    headers: {Authorization: `Bearer ${token}`},
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`org list HTTP ${res.status}`);
  return Object.keys((await res.json()) || {});
}

async function watchReplies(admin) {
  const db = admin.database();
  const out = makeOutgoing(admin);

  const sinceRef = db.ref("mailBridge/enabledSince");
  let enabledSince = (await sinceRef.once("value")).val();
  if (!enabledSince) {
    enabledSince = Date.now();
    await sinceRef.set(enabledSince);
    log("first start: replies older than now are never emailed");
  }
  const from = Math.max(Date.now() - BACKFILL_MS, enabledSince);

  // supervisor message copies have their own start marker: messages sent before this feature existed are never emailed
  const copySinceRef = db.ref("mailBridge/supervisorCopySince");
  let copySince = (await copySinceRef.once("value")).val();
  if (!copySince) {
    copySince = Date.now();
    await copySinceRef.set(copySince);
    log("supervisor copies: first start, older supervisor messages are never emailed");
  }
  const copyFrom = Math.max(Date.now() - BACKFILL_MS, copySince);
  const copies = makeSupervisorCopy(admin);

  const watched = new Set();
  const refresh = async () => {
    try {
      for (const orgId of await listOrgIds(admin)) {
        if (watched.has(orgId)) continue;
        watched.add(orgId);
        db.ref(`organizations/${orgId}/userReplies`).orderByChild("timestamp").startAt(from)
            .on("child_added", (snap) => {
              out.handleReply(orgId, snap.key, snap.val(), enabledSince).catch((e) => {
                state.lastError = describeErr(e);
                log("handleReply error", state.lastError);
              });
            }, (err) => log(`listener cancelled org=${orgId}: ${err.message}`));
        db.ref(`organizations/${orgId}/messages`).orderByChild("timestamp").startAt(copyFrom)
            .on("child_added", (snap) => {
              copies.handleMessage(orgId, snap.key, snap.val(), copySince).catch((e) => {
                state.lastError = describeErr(e);
                log("supervisor copy error", state.lastError);
              });
            }, (err) => log(`supervisor-copy listener cancelled org=${orgId}: ${err.message}`));
      }
      state.orgsWatched = watched.size;
    } catch (e) {
      state.lastError = describeErr(e);
      log("org refresh error", state.lastError);
    }
  };
  await refresh();
  setInterval(refresh, ORG_REFRESH_MS).unref();
}

// ───────────────────────── incoming: email reply -> kiosk ─────────────────────────

function makeIncoming(admin) {
  const db = admin.database();
  const unresolved = new Set(); // uids we could not route; left unread and not re-parsed every scan

  async function handleIncoming(source, opts = {}) {
    const parsed = await simpleParser(source);

    const auto = String(parsed.headers.get("auto-submitted") || "").toLowerCase();
    const prec = String(parsed.headers.get("precedence") || "").toLowerCase();
    if ((auto && auto !== "no") || /bulk|auto_reply|junk/.test(prec)) return {resolved: false, reason: "auto-reply"};

    const header = [parsed.to && parsed.to.text, parsed.cc && parsed.cc.text, String(parsed.headers.get("delivered-to") || "")].join(" ");
    // address tag (+t_<id>@) first; the subject tag (#t_<id>) covers the owner answering from the same mailbox that sends
    const m = header.match(TAG) || String(parsed.subject || "").match(SUBJECT_TAG);
    if (!m) return {resolved: false, reason: "no tag"};
    const thread = (await db.ref(`mailBridge/threads/${m[1].toLowerCase()}`).once("value")).val();
    if (!thread || !thread.orgId || !thread.userId) return {resolved: false, reason: "unknown thread"};

    // sender must be the org's inquiry address AND be verified by Gmail (anyone could otherwise guess/forward the address)
    const {email: allowed} = await inquiryEmailFor(db, thread.orgId);
    const from = ((parsed.from && parsed.from.value && parsed.from.value[0] && parsed.from.value[0].address) || "").toLowerCase();
    if (!allowed || from !== allowed) return {resolved: false, forbidden: true, reason: `sender ${from || "?"} is not the inquiry address`};
    const sentByMailbox = from === cfg.user.toLowerCase() && opts.labels && [...opts.labels].some((l) => String(l).toLowerCase() === "\\sent");
    const authLine = authResultsLine(parsed);
    // mail typed in this very mailbox (owner == sending account) carries no Gmail verdict at all; anything arriving
    // from outside always carries one (pass or fail), so "no verdict + sender is the mailbox" can only be local mail
    const localMail = from === cfg.user.toLowerCase() && !/mx\.google\.com/i.test(authLine);
    if (!sentByMailbox && !localMail && !isAuthenticated(authLine, from.split("@")[1])) {
      return {resolved: false, forbidden: true, reason: `sender ${from} not verified by Gmail (no passing DKIM/SPF/DMARC)`};
    }

    let text = extractReplyText(String(parsed.text || ""));
    if (!text) return {resolved: false, empty: true};
    if (text.length > 1000) text = text.slice(0, 997) + "...";

    await db.ref(`organizations/${thread.orgId}/messages`).push({
      fromAdminId: "email",
      fromName: "מנהל",
      toUserId: thread.userId,
      message: text,
      timestamp: Date.now(),
      read: false,
      viaEmail: true,
    });
    return {resolved: true, orgId: thread.orgId};
  }

  async function scan(client) {
    const lock = await client.getMailboxLock("INBOX");
    try {
      const all = await client.search({seen: false}, {uid: true});
      const fresh = (all || []).slice(-200).filter((uid) => !unresolved.has(uid));
      const candidates = [];
      const labelsByUid = new Map();
      if (fresh.length) {
        // Gmail IMAP SEARCH is unreliable for "plus" addresses, so read the cheap envelopes and filter here
        for await (const msg of client.fetch(fresh, {envelope: true, uid: true, labels: true}, {uid: true})) {
          labelsByUid.set(msg.uid, msg.labels);
          const addrs = [...((msg.envelope && msg.envelope.to) || []), ...((msg.envelope && msg.envelope.cc) || [])].map((a) => (a && a.address) || "");
          if (addrs.some((a) => TAGGED.test(a))) candidates.push(msg.uid);
          else unresolved.add(msg.uid); // unrelated mail: never look again (stays unread)
        }
      }
      for (const uid of candidates) {
        const msg = await client.fetchOne(uid, {source: true}, {uid: true});
        if (!msg || !msg.source) continue;
        const r = await handleIncoming(msg.source, {labels: labelsByUid.get(uid)});
        if (r.resolved) {
          await client.messageFlagsAdd(uid, ["\\Seen"], {uid: true});
          state.repliesReceived++;
          log(`reply delivered uid=${uid} org=${r.orgId}`);
        } else {
          unresolved.add(uid); // stays unread so it is not lost
          log(`reply uid=${uid} not routed: ${r.forbidden ? "REJECTED - " + r.reason : r.empty ? "empty text after removing the quote" : r.reason}`);
        }
      }
      state.imapLastScanAt = Date.now();
    } finally {
      lock.release();
    }
  }

  return {scan, handleIncoming};
}

let stopped = false;

async function runImap(admin) {
  if (!cfg.pass) {
    log("GMAIL_APP_PASSWORD not set - IMAP is off; replies are fetched from the Apps Script instead");
    return;
  }
  const inc = makeIncoming(admin);
  let backoff = 5000;
  while (!stopped) {
    const client = new ImapFlow({
      host: "imap.gmail.com", port: 993, secure: true, auth: {user: cfg.user, pass: cfg.pass}, logger: false,
    });
    client.on("error", (e) => {
      state.lastError = describeErr(e);
    });
    let scanning = false;
    const trigger = async () => {
      if (scanning) return;
      scanning = true;
      try {
        await withTimeout(inc.scan(client), SCAN_TIMEOUT_MS, "scan");
      } catch (e) {
        state.lastError = describeErr(e);
        log("scan error", state.lastError);
        if (/timed out/.test(state.lastError)) {
          try {
            client.close();
          } catch { /* already closed */ } // forces a clean reconnect
        }
      } finally {
        scanning = false;
      }
    };
    try {
      await client.connect();
      state.imapConnected = true;
      state.lastError = null;
      backoff = 5000;
      state.imapLastScanAt = Date.now();
      log("IMAP connected");
      client.on("exists", trigger);
      await trigger();
      await new Promise((resolve) => {
        const timer = setInterval(trigger, cfg.pollSeconds * 1000);
        const staleMs = Math.max(5 * 60 * 1000, 4 * cfg.pollSeconds * 1000);
        const watchdog = setInterval(() => {
          if (Date.now() - (state.imapLastScanAt || 0) > staleMs) {
            log("watchdog: no successful scan - reconnecting");
            try {
              client.close();
            } catch { /* already closed */ }
          }
        }, 60 * 1000);
        client.on("close", () => {
          clearInterval(timer);
          clearInterval(watchdog);
          resolve();
        });
      });
    } catch (e) {
      state.lastError = describeErr(e);
      log("IMAP error:", state.lastError);
    }
    state.imapConnected = false;
    try {
      await client.logout();
    } catch { /* already closed */ }
    if (stopped) break;
    log(`IMAP reconnecting in ${backoff / 1000}s`);
    await new Promise((r) => setTimeout(r, backoff));
    backoff = Math.min(backoff * 2, 120000);
  }
}

// ───────────────────────── incoming via Apps Script (no IMAP / no app password) ─────────────────────────
//
// The Apps Script (mail-relay.gs, pollReplies) runs as the mailbox owner, reads the replies in Gmail and POSTs
// {headers, text} to /mail/inbound. We rebuild a small RFC822 message and run it through the same checks as IMAP
// (tag -> thread, sender == inquiry address, Gmail DKIM/SPF/DMARC verdict, auto-reply filter, quote cutting).

const DROP_HEADERS = new Set(["content-type", "content-transfer-encoding", "mime-version", "content-disposition"]);

function buildSource(headerBlock, text) {
  const kept = [];
  let dropping = false;
  for (const line of String(headerBlock || "").replace(/\r\n/g, "\n").split("\n")) {
    if (/^[ \t]/.test(line)) {
      if (!dropping) kept.push(line); // folded continuation of the previous header
      continue;
    }
    dropping = DROP_HEADERS.has((line.split(":")[0] || "").trim().toLowerCase());
    if (!dropping && line) kept.push(line);
  }
  return kept.join("\r\n") + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + String(text || "");
}

let inboundHandler = null;

async function handleInbound(admin, payload) {
  if (!inboundHandler) inboundHandler = makeIncoming(admin);
  state.inboundCalls++;
  const headers = String((payload && payload.headers) || "").slice(0, 30000);
  const text = String((payload && payload.text) || "").slice(0, 30000);
  const r = await inboundHandler.handleIncoming(buildSource(headers, text), {});
  const reason = r.resolved ? null : (r.forbidden ? "REJECTED - " + r.reason : r.empty ? "empty text after removing the quote" : r.reason);
  state.lastInbound = {at: Date.now(), resolved: !!r.resolved, reason};
  if (r.resolved) state.repliesReceived++;
  log(r.resolved ? `reply delivered (apps script) org=${r.orgId}` : `reply from apps script not routed: ${reason}`);
  return {resolved: !!r.resolved, reason};
}

// The bridge asks the Apps Script web app for new replies (action "poll") and confirms the handled ones ("ack").
// This needs nothing but the relay that already sends mail: no IMAP, no app password, no script-side trigger.
async function pollScriptOnce(admin) {
  const data = await relayCall({action: "poll"});
  state.scriptPolls++;
  state.lastScriptPollAt = Date.now();
  const handled = [];
  for (const m of data.messages || []) {
    try {
      await handleInbound(admin, {headers: m.headers, text: m.text});
      handled.push(m.id); // delivered or definitively rejected: do not offer it again
    } catch (e) {
      state.lastError = describeErr(e); // transient (Firebase): leave it for the next poll
      log("poll: could not handle a reply, will retry:", state.lastError);
    }
  }
  if (handled.length) await relayCall({action: "ack", ids: handled});
  state.lastScriptPollError = null;
}

function startScriptPolling(admin) {
  if (!cfg.relayUrl || env.MAIL_SCRIPT_POLL === "off") return;
  const every = Math.max(30, num(env.MAIL_SCRIPT_POLL_SECONDS, 120)) * 1000;
  let busy = false;
  let lastLogged = "";
  const tick = async () => {
    if (busy || stopped) return;
    busy = true;
    try {
      await pollScriptOnce(admin);
    } catch (e) {
      state.lastScriptPollError = describeErr(e);
      if (state.lastScriptPollError !== lastLogged) { // log each distinct problem once, not every poll
        lastLogged = state.lastScriptPollError;
        log("script poll error:", lastLogged);
      }
    } finally {
      busy = false;
    }
  };
  setTimeout(tick, 5000).unref();
  setInterval(tick, every).unref();
  log(`polling Apps Script for replies every ${every / 1000}s`);
}

// ───────────────────────── entry point ─────────────────────────

function start(admin) {
  if (!cfg.user || !cfg.secret) {
    log("disabled (set GMAIL_USER and MAIL_HMAC_SECRET to enable)");
    return state;
  }
  if (!cfg.relayUrl && !cfg.pass) {
    log("disabled: need MAIL_RELAY_URL or GMAIL_APP_PASSWORD to send");
    return state;
  }
  state.enabled = true;
  state.sendMode = cfg.relayUrl ? "relay" : "smtp";
  watchReplies(admin).catch((e) => {
    state.lastError = describeErr(e);
    log("watchReplies failed", state.lastError);
  });
  runImap(admin).catch((e) => log("IMAP loop crashed", describeErr(e)));
  startScriptPolling(admin);
  log(`enabled (send via ${state.sendMode})`);
  return state;
}

module.exports = {start, state, handleInbound, extractReplyText, isAuthenticated, tidFor, copyRecipients, dropSupervisorCopyOnMirror, _internals: {makeIncoming, makeOutgoing, buildSource, pollScriptOnce}};
