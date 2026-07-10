const SENSITIVE_QUERY_PARAMETERS = new Set([
  "access_token",
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "code",
  "key",
  "password",
  "session",
  "session_id",
  "token"
]);

export const DUPLICATE_WINDOW_MS = 2_000;

export function normalizeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }

  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";

  for (const key of [...parsed.searchParams.keys()]) {
    if (SENSITIVE_QUERY_PARAMETERS.has(key.toLowerCase())) {
      parsed.searchParams.set(key, "[REDACTED]");
    }
  }

  return parsed.href;
}

export function createNavigationEvent(details, navigationKind, options = {}) {
  if (details.frameId !== 0) {
    return null;
  }

  const url = normalizeUrl(details.url);
  if (!url) {
    return null;
  }

  const now = options.now ?? (() => new Date());
  const idFactory = options.idFactory ?? (() => crypto.randomUUID());
  const event = {
    schema_version: 1,
    event_type: "browser_navigation",
    event_id: idFactory(),
    timestamp: now().toISOString(),
    browser: "edge",
    url,
    tab_id: details.tabId,
    navigation_kind: navigationKind,
    transition_type: details.transitionType ?? "unknown",
    transition_qualifiers: Array.isArray(details.transitionQualifiers)
      ? details.transitionQualifiers
      : [],
    source: "edge_extension"
  };

  if (typeof details.documentId === "string" && details.documentId.length > 0) {
    event.document_id = details.documentId;
  }

  return event;
}

export class RecentEventDeduplicator {
  constructor(windowMs = DUPLICATE_WINDOW_MS) {
    this.windowMs = windowMs;
    this.recent = new Map();
  }

  isDuplicate(event, timeMs = Date.now()) {
    const documentPart = event.document_id ?? event.url;
    const key = `${event.tab_id}:${event.navigation_kind}:${documentPart}`;
    const previous = this.recent.get(key);

    for (const [oldKey, observedAt] of this.recent) {
      if (timeMs - observedAt > this.windowMs) {
        this.recent.delete(oldKey);
      }
    }

    if (previous !== undefined && timeMs - previous <= this.windowMs) {
      return true;
    }

    this.recent.set(key, timeMs);
    return false;
  }
}
