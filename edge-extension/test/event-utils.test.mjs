import assert from "node:assert/strict";
import test from "node:test";

import {
  createNavigationEvent,
  normalizeUrl,
  RecentEventDeduplicator
} from "../event-utils.mjs";

test("normalizes HTTP URLs and removes fragments", () => {
  assert.equal(
    normalizeUrl("https://example.test/path?q=ok#private"),
    "https://example.test/path?q=ok"
  );
});

test("removes embedded credentials and redacts sensitive query values", () => {
  assert.equal(
    normalizeUrl("https://user:secret@example.test/login?token=abc&next=home"),
    "https://example.test/login?token=%5BREDACTED%5D&next=home"
  );
});

test("rejects unsupported and malformed URLs", () => {
  assert.equal(normalizeUrl("edge://settings"), null);
  assert.equal(normalizeUrl("file:///C:/secret.txt"), null);
  assert.equal(normalizeUrl("not a URL"), null);
});

test("creates a versioned top-level navigation event", () => {
  const event = createNavigationEvent(
    {
      frameId: 0,
      tabId: 7,
      url: "https://example.test/",
      documentId: "doc-1",
      transitionType: "link",
      transitionQualifiers: ["server_redirect"]
    },
    "committed",
    {
      idFactory: () => "event-1",
      now: () => new Date("2026-07-10T08:14:22.491Z")
    }
  );

  assert.deepEqual(event, {
    schema_version: 1,
    event_type: "browser_navigation",
    event_id: "event-1",
    timestamp: "2026-07-10T08:14:22.491Z",
    browser: "edge",
    url: "https://example.test/",
    tab_id: 7,
    navigation_kind: "committed",
    transition_type: "link",
    transition_qualifiers: ["server_redirect"],
    source: "edge_extension",
    document_id: "doc-1"
  });
});

test("ignores iframe navigation", () => {
  assert.equal(
    createNavigationEvent({ frameId: 3, tabId: 7, url: "https://example.test/" }, "committed"),
    null
  );
});

test("deduplicates the same document inside the configured window", () => {
  const deduplicator = new RecentEventDeduplicator(2_000);
  const event = {
    tab_id: 1,
    navigation_kind: "committed",
    document_id: "doc-1",
    url: "https://example.test/"
  };

  assert.equal(deduplicator.isDuplicate(event, 1_000), false);
  assert.equal(deduplicator.isDuplicate(event, 2_500), true);
  assert.equal(deduplicator.isDuplicate(event, 3_100), false);
});
