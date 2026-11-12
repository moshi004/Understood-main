"use strict";
// Run: node --test test/supervisorCopy.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const {copyRecipients} = require("../mailReplies");

test("nothing is sent unless a switch or an address is set", () => {
  assert.deepEqual(copyRecipients({orgSwitchOn: false, orgEmail: "org@x.co", supMail: null}), []);
  assert.deepEqual(copyRecipients({orgSwitchOn: true, orgEmail: null, supMail: null}), []);
  assert.deepEqual(copyRecipients({orgSwitchOn: false, orgEmail: "org@x.co", supMail: {email: "s@x.co", enabled: false}}), []);
});

test("org copy needs the org switch AND an inquiry address", () => {
  assert.deepEqual(copyRecipients({orgSwitchOn: true, orgEmail: "org@x.co", supMail: null}), [{kind: "org", to: "org@x.co"}]);
});

test("supervisor copy only needs the supervisor's own enabled address", () => {
  assert.deepEqual(copyRecipients({orgSwitchOn: false, orgEmail: "org@x.co", supMail: {email: "S@X.co"}}), [{kind: "sup", to: "s@x.co"}]);
  assert.deepEqual(copyRecipients({orgSwitchOn: false, orgEmail: null, supMail: {email: "bad"}}), []);
});

test("both get a copy, but the same address is not mailed twice", () => {
  assert.equal(copyRecipients({orgSwitchOn: true, orgEmail: "a@x.co", supMail: {email: "b@x.co"}}).length, 2);
  assert.equal(copyRecipients({orgSwitchOn: true, orgEmail: "a@x.co", supMail: {email: "a@x.co"}}).length, 1);
});
