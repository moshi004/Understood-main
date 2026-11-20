"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const registerBillingRoutes = require("../billing");
const {applyPayment, recurringAmount} = registerBillingRoutes;

// ── pure helpers ─────────────────────────────────────────────────────
test("applyPayment pays oldest invoice first and returns the surplus", () => {
  const invoices = {
    "2026-10": {month: "2026-10", amount: 200, paidAmount: 0, status: "unpaid"},
    "2026-11": {month: "2026-11", amount: 100, paidAmount: 0, status: "unpaid"},
  };
  const {updates, leftover} = applyPayment(invoices, 350, 1000, "nedarim-hk");
  assert.equal(updates["2026-10"].status, "paid");
  assert.equal(updates["2026-11"].status, "paid");
  assert.equal(leftover, 50);
});

test("applyPayment keeps a partly paid invoice open", () => {
  const {updates, leftover} = applyPayment({"2026-10": {month: "2026-10", amount: 200, paidAmount: 0, status: "unpaid"}}, 120, 1, "x");
  assert.equal(updates["2026-10"].paidAmount, 120);
  assert.equal(updates["2026-10"].status, undefined);
  assert.equal(leftover, 0);
});

test("applyPayment ignores paid and void invoices", () => {
  const {updates, leftover} = applyPayment({
    "2026-09": {month: "2026-09", amount: 50, paidAmount: 50, status: "paid"},
    "2026-10": {month: "2026-10", amount: 50, paidAmount: 0, status: "void"},
  }, 80, 1, "x");
  assert.deepEqual(updates, {});
  assert.equal(leftover, 80);
});

test("recurringAmount is a whole number, never below the minimum", () => {
  assert.equal(recurringAmount(10, {}, 200), 200);
  assert.equal(recurringAmount(205.3, {"2026-10": {month: "2026-10", amount: 120, status: "paid"}}, 200), 206);
  assert.equal(recurringAmount(0, {"2026-10": {month: "2026-10", amount: 340.5, status: "paid"}}, 200), 341);
});

// ── pricing end to end, against an in-memory Firebase ────────────────
function makeDb(initial) {
  const root = JSON.parse(JSON.stringify(initial));
  const parts = (p) => p.split("/").filter(Boolean);
  const get = (p) => parts(p).reduce((n, k) => (n == null ? undefined : n[k]), root);
  // Like the real Firebase: an undefined anywhere in a written value is an error.
  const noUndefined = (v) => {
    if (v === undefined) throw new Error("value argument contains undefined");
    if (v && typeof v === "object") Object.values(v).forEach(noUndefined);
  };
  const setAt = (p, v) => {
    if (v !== null) noUndefined(v);
    const ks = parts(p);
    let n = root;
    ks.slice(0, -1).forEach((k) => { if (typeof n[k] !== "object" || n[k] === null) n[k] = {}; n = n[k]; });
    if (v === null || v === undefined) delete n[ks[ks.length - 1]]; else n[ks[ks.length - 1]] = v;
  };
  const snap = (v) => ({val: () => (v === undefined ? null : JSON.parse(JSON.stringify(v))), exists: () => v !== undefined && v !== null});
  let pushId = 0;
  return {
    root,
    database: () => ({
      ref: (p = "") => ({
        once: async () => snap(get(p)),
        set: async (v) => setAt(p, v),
        remove: async () => setAt(p, null),
        push: async (v) => setAt(`${p}/k${++pushId}`, v),
        update: async (v) => {
          Object.entries(v).forEach(([k, val]) => setAt(p ? `${p}/${k}` : k, val));
        },
      }),
    }),
  };
}

function setup(orgs, extra = {}) {
  const store = makeDb({owners: {own: true}, organizations: orgs, ...extra});
  const routes = {};
  const app = {post: (path, h) => { routes[path] = h; }, use: () => {}};
  const admin = {
    database: store.database,
    auth: () => ({verifyIdToken: async () => ({uid: "own"})}),
    app: () => ({options: {}}),
  };
  registerBillingRoutes(app, {admin, verifyOwner: async () => "own"});
  const call = async (path, body) => {
    let out; let code = 200;
    const res = {status: (c) => { code = c; return res; }, json: (j) => { out = j; return res; }};
    await routes[path]({headers: {authorization: "Bearer t"}, body, query: {}, get: () => "h", socket: {}}, res);
    return {code, ...out};
  };
  return {store, call};
}

const DAYS = (ym, n) => Object.fromEntries(Array.from({length: n}, (_, i) => [`${ym}-${String(i + 1).padStart(2, "0")}`, true]));

test("a computer active most of the month is full price, one active day is half, none is free", async () => {
  const lastMonth = (() => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); })();
  const {call} = setup({
    acme: {metadata: {name: "Acme", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {
      a: {computerName: "A", usageDays: DAYS(lastMonth, 20)},
      b: {computerName: "B", usageDays: DAYS(lastMonth, 1)},
      c: {computerName: "C"},
    }},
  }, {billing: {config: {firstBillableMonth: lastMonth, minimumMonthly: 0, pricePerComputer: 10}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.success, true);
  const inv = r.invoices.find((i) => i.month === lastMonth);
  assert.ok(inv, "invoice for the closed month was issued");
  assert.equal(inv.amount, 15); // 10 + 5 + 0
  assert.equal(inv.breakdown.full, 1);
  assert.equal(inv.breakdown.half, 1);
  assert.equal(inv.breakdown.none, 1);
});

test("the monthly minimum applies when usage is small", async () => {
  const lastMonth = (() => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); })();
  const {call} = setup({
    acme: {metadata: {name: "Acme", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {a: {usageDays: DAYS(lastMonth, 20)}}},
  }, {billing: {config: {firstBillableMonth: lastMonth}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  const inv = r.invoices.find((i) => i.month === lastMonth);
  assert.equal(inv.amount, 200);
  assert.equal(inv.breakdown.minimumApplied, true);
});

test("an exempt org is never charged and never gated", async () => {
  const lastMonth = (() => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); })();
  const {call} = setup({
    free1: {metadata: {name: "Free", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {a: {usageDays: DAYS(lastMonth, 25)}}},
  }, {billing: {config: {firstBillableMonth: lastMonth}, orgs: {free1: {settings: {exempt: true}}}}});
  const r = await call("/billing/summary", {orgId: "free1"});
  assert.equal(r.status.state, "free");
  assert.equal(r.invoices.length, 0);
});

test("an org inside its trial gets no invoice for the month", async () => {
  const lastMonth = (() => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); })();
  const {call} = setup({
    fresh: {metadata: {name: "Fresh", createdAt: new Date().toISOString()}, users: {own: {isAdmin: true}}, computers: {a: {usageDays: DAYS(lastMonth, 25)}}},
  }, {billing: {config: {firstBillableMonth: lastMonth}}});
  const r = await call("/billing/summary", {orgId: "fresh"});
  assert.equal(r.invoices.length, 0);
  assert.equal(r.status.state, "ok");
});

test("manual block gates the org immediately, unblock releases it", async () => {
  const {call} = setup({acme: {metadata: {name: "Acme", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {}}},
      {billing: {config: {firstBillableMonth: "2999-01"}}});
  await call("/billing/ownerAction", {action: "block", orgId: "acme", params: {message: "x"}});
  assert.equal((await call("/billing/summary", {orgId: "acme"})).status.state, "blocked");
  await call("/billing/ownerAction", {action: "unblock", orgId: "acme"});
  assert.equal((await call("/billing/summary", {orgId: "acme"})).status.state, "ok");
});

test("a standing-order charge settles the invoice, keeps the surplus as credit and ignores a repeated transaction", async () => {
  const lastMonth = (() => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); })();
  const {store, call} = setup({
    acme: {metadata: {name: "Acme", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {a: {usageDays: DAYS(lastMonth, 20)}}},
  }, {billing: {config: {firstBillableMonth: lastMonth}, secret: {hkTokens: {acme: "tok"}}}});
  await call("/billing/summary", {orgId: "acme"}); // issues the 200 invoice (minimum)
  let hit;
  const registered = {};
  const app = {post: (p, h) => { registered[p] = h; }, use: () => {}};
  registerBillingRoutes(app, {admin: {database: store.database, auth: () => ({verifyIdToken: async () => ({uid: "own"})}), app: () => ({options: {}})}, verifyOwner: async () => "own"});
  const hook = async (tx, amount) => {
    const res = {status: () => res, json: (j) => { hit = j; return res; }};
    await registered["/billingCallback"]({headers: {}, query: {hk: "1", t: "tok"}, body: {Param2: "acme", TransactionId: tx, Status: "OK", Amount: String(amount)}, get: () => "h", socket: {}}, res);
    return hit;
  };
  assert.equal((await hook("T1", 230)).success, true);
  const bill = store.root.billing.orgs.acme;
  assert.equal(bill.invoices[lastMonth].status, "paid");
  assert.equal(bill.credit, 30);
  await hook("T1", 230); // same transaction again
  assert.equal(store.root.billing.orgs.acme.credit, 30, "not applied twice");
});

test("a standing-order callback with a wrong token is refused", async () => {
  const {store} = setup({acme: {metadata: {}, users: {}, computers: {}}}, {billing: {secret: {hkTokens: {acme: "tok"}}}});
  const registered = {};
  registerBillingRoutes({post: (p, h) => { registered[p] = h; }, use: () => {}}, {admin: {database: store.database, auth: () => ({}), app: () => ({options: {}})}, verifyOwner: async () => "own"});
  let code;
  const res = {status: (c) => { code = c; return res; }, json: () => res};
  await registered["/billingCallback"]({headers: {}, query: {hk: "1", t: "nope"}, body: {Param2: "acme", TransactionId: "T", Status: "OK", Amount: "10"}, get: () => "h", socket: {}}, res);
  assert.equal(code, 403);
});

// ── free switches ────────────────────────────────────────────────────
const prevMonth = () => { const d = new Date(); d.setUTCMonth(d.getUTCMonth() - 1, 1); return d.toISOString().slice(0, 7); };
const thisMonth = () => new Date().toISOString().slice(0, 7);
const ORG = (lastMonth) => ({acme: {metadata: {name: "Acme", createdAt: "2020-01-01T00:00:00Z"}, users: {own: {isAdmin: true}}, computers: {a: {usageDays: DAYS(lastMonth, 25)}}}});

test("free for everyone: no invoices, no gate, no contract, no payment", async () => {
  const lm = prevMonth();
  const {call} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm, freeForAll: true}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.status.state, "free");
  assert.equal(r.invoices.length, 0);
  assert.equal(r.exempt, true);
  assert.equal(r.contract.required, false);
  assert.equal(r.estimate.total, 0);
  const pay = await call("/billing/payConfig", {orgId: "acme", recurring: true});
  assert.equal(pay.code, 400);
});

test("turning free-for-all off bills from this month on, never back-bills the free period", async () => {
  const lm = prevMonth();
  const {call, store} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm, freeForAll: true}}});
  await call("/billing/summary", {orgId: "acme"});
  await call("/billing/ownerAction", {action: "saveConfig", params: {freeForAll: false}});
  assert.equal(store.root.billing.config.freeForAll, false);
  assert.equal(store.root.billing.config.firstBillableMonth, thisMonth());
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.invoices.length, 0, "last month (free) is not billed");
  assert.equal(r.status.state, "ok");
});

test("an org taken off exempt is billed from this month on only", async () => {
  const lm = prevMonth();
  const {call, store} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm}, orgs: {acme: {settings: {exempt: true}}}}});
  await call("/billing/ownerAction", {action: "saveSettings", orgId: "acme", params: {exempt: false}});
  assert.equal(store.root.billing.orgs.acme.settings.billFrom, thisMonth());
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.invoices.length, 0);
});

test("a zero-amount invoice is settled at once and never blocks the org", async () => {
  const lm = prevMonth();
  const {call} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm, pricePerComputer: 0, minimumMonthly: 0}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  const inv = r.invoices.find((i) => i.month === lm);
  assert.equal(inv.amount, 0);
  assert.equal(inv.status, "paid");
  assert.equal(r.status.state, "ok");
});

test("the free-for-all switch saves and logs without sending undefined to Firebase", async () => {
  const {call, store} = setup(ORG(prevMonth()));
  const r = await call("/billing/ownerAction", {action: "saveConfig", params: {freeForAll: true}});
  assert.equal(r.success, true);
  assert.equal(store.root.billing.config.freeForAll, true);
  const log = Object.values(store.root.billing.auditGlobal)[0];
  assert.equal(log.details.freeForAll, true);
});

test("free until a date: free now, no invoice for the free months, billed after", async () => {
  const lm = prevMonth();
  const {call} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm}, orgs: {acme: {settings: {freeUntil: Date.now() + 5 * 86400000}}}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.status.state, "free");
  assert.equal(r.invoices.length, 0);
  // date already passed: the org pays again, but last month (inside the free window) is still not billed
  const past = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm}, orgs: {acme: {settings: {freeUntil: Date.now() - 86400000, trialDays: 0}}}}});
  const r2 = await past.call("/billing/summary", {orgId: "acme"});
  assert.notEqual(r2.status.state, "free");
});

test("a free-until date in the past covers the months it spanned", async () => {
  const lm = prevMonth();
  const endOfThisMonthStart = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1);
  const {call} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm}, orgs: {acme: {settings: {freeUntil: endOfThisMonthStart, trialDays: 0}}}}});
  const r = await call("/billing/summary", {orgId: "acme"});
  assert.equal(r.invoices.length, 0, "last month ended before freeUntil");
});

test("per-org trial days override the global trial", async () => {
  const lm = prevMonth();
  const orgs = ORG(lm);
  orgs.acme.metadata.createdAt = new Date(Date.now() - 70 * 86400000).toISOString();
  const long = setup(JSON.parse(JSON.stringify(orgs)), {billing: {config: {firstBillableMonth: lm, trialDays: 5}, orgs: {acme: {settings: {trialDays: 400}}}}});
  assert.equal((await long.call("/billing/summary", {orgId: "acme"})).invoices.length, 0);
  const std = setup(JSON.parse(JSON.stringify(orgs)), {billing: {config: {firstBillableMonth: lm, trialDays: 5}}});
  assert.equal((await std.call("/billing/summary", {orgId: "acme"})).invoices.length, 1);
});

test("auto-block off (global or per org): overdue org only gets a warning", async () => {
  const lm = prevMonth();
  const inv = {[lm]: {month: lm, amount: 200, paidAmount: 0, status: "unpaid", issuedAt: 1, dueAt: 2}};
  const base = {firstBillableMonth: lm};
  const a = setup(ORG(lm), {billing: {config: base, orgs: {acme: {invoices: inv}}}});
  assert.equal((await a.call("/billing/summary", {orgId: "acme"})).status.state, "blocked");
  const b = setup(ORG(lm), {billing: {config: {...base, autoBlock: false}, orgs: {acme: {invoices: inv}}}});
  const rb = await b.call("/billing/summary", {orgId: "acme"});
  assert.equal(rb.status.state, "warning");
  assert.equal(rb.status.overdue, true);
  const c = setup(ORG(lm), {billing: {config: base, orgs: {acme: {invoices: inv, settings: {neverBlock: true}}}}});
  assert.equal((await c.call("/billing/summary", {orgId: "acme"})).status.state, "warning");
});

test("overview returns a revenue summary and the new settings save without undefined", async () => {
  const lm = prevMonth();
  const {call, store} = setup(ORG(lm), {billing: {config: {firstBillableMonth: lm}}});
  const s1 = await call("/billing/ownerAction", {action: "saveSettings", orgId: "acme", params: {trialDays: 12, neverBlock: true, freeUntil: Date.now() + 86400000}});
  assert.equal(s1.success, true);
  assert.equal(store.root.billing.orgs.acme.settings.trialDays, 12);
  const g = await call("/billing/ownerAction", {action: "saveConfig", params: {autoBlock: false, freeUntil: null}});
  assert.equal(g.success, true);
  assert.equal(store.root.billing.config.autoBlock, false);
  const o = await call("/billing/overview", {});
  assert.equal(o.success, true);
  assert.equal(o.summary.orgs, 1);
  assert.equal(o.summary.free, 1);
});
