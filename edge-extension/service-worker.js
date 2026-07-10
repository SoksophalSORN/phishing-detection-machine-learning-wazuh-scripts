import {
  createNavigationEvent,
  RecentEventDeduplicator
} from "./event-utils.mjs";

const NATIVE_HOST_NAME = "com.phishing_detection.navigation";
const QUEUE_KEY = "pending_navigation_events";
const COUNTERS_KEY = "navigation_counters";
const RETRY_ALARM = "native_host_retry";
const MAX_QUEUE_SIZE = 500;
const ACK_TIMEOUT_MS = 10_000;
const MAX_RECONNECT_DELAY_MS = 60_000;

const deduplicator = new RecentEventDeduplicator();

let port = null;
let pendingAcknowledgement = null;
let flushing = false;
let reconnectDelayMs = 1_000;
let operationChain = Promise.resolve();

// These listeners must remain at module top level. Edge can then wake the
// Manifest V3 service worker for the first navigation after a cold start.
chrome.webNavigation.onCommitted.addListener((details) => {
  void captureNavigation(details, "committed");
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  void captureNavigation(details, "history_state");
});

chrome.runtime.onStartup.addListener(() => {
  void scheduleFlush();
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(RETRY_ALARM, { periodInMinutes: 1 });
  void scheduleFlush();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RETRY_ALARM) {
    void scheduleFlush();
  }
});

async function captureNavigation(details, navigationKind) {
  const event = createNavigationEvent(details, navigationKind);
  if (!event) {
    return;
  }

  if (deduplicator.isDuplicate(event)) {
    await updateCounter("duplicates");
    return;
  }

  await enqueueEvent(event);
  await scheduleFlush();
}

function serializeOperation(operation) {
  const result = operationChain.then(operation, operation);
  operationChain = result.catch(() => undefined);
  return result;
}

function enqueueEvent(event) {
  return serializeOperation(async () => {
    const stored = await chrome.storage.local.get(QUEUE_KEY);
    const queue = Array.isArray(stored[QUEUE_KEY]) ? stored[QUEUE_KEY] : [];

    queue.push(event);
    if (queue.length > MAX_QUEUE_SIZE) {
      queue.splice(0, queue.length - MAX_QUEUE_SIZE);
      await updateCounter("dropped");
    }

    await chrome.storage.local.set({ [QUEUE_KEY]: queue });
    await updateCounter("observed");
  });
}

function scheduleFlush() {
  return serializeOperation(flushQueue);
}

async function flushQueue() {
  if (flushing) {
    return;
  }

  flushing = true;
  try {
    while (true) {
      const stored = await chrome.storage.local.get(QUEUE_KEY);
      const queue = Array.isArray(stored[QUEUE_KEY]) ? stored[QUEUE_KEY] : [];
      if (queue.length === 0) {
        return;
      }

      const event = queue[0];
      let acknowledgement;
      try {
        acknowledgement = await sendAndWaitForAcknowledgement(event);
      } catch (error) {
        console.warn("Native host delivery failed", error);
        await updateCounter("retries");
        scheduleReconnect();
        return;
      }

      if (!acknowledgement?.accepted || acknowledgement.event_id !== event.event_id) {
        console.warn("Native host rejected navigation event", acknowledgement);
        await updateCounter("rejected");
        // A permanently invalid event must not block the queue forever.
      } else {
        reconnectDelayMs = 1_000;
        await updateCounter("accepted");
      }

      const latest = await chrome.storage.local.get(QUEUE_KEY);
      const latestQueue = Array.isArray(latest[QUEUE_KEY]) ? latest[QUEUE_KEY] : [];
      if (latestQueue[0]?.event_id === event.event_id) {
        latestQueue.shift();
        await chrome.storage.local.set({ [QUEUE_KEY]: latestQueue });
      }
    }
  } finally {
    flushing = false;
  }
}

function ensurePort() {
  if (port) {
    return port;
  }

  port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  port.onMessage.addListener(handleNativeMessage);
  port.onDisconnect.addListener(handleNativeDisconnect);
  return port;
}

function sendAndWaitForAcknowledgement(event) {
  if (pendingAcknowledgement) {
    return Promise.reject(new Error("A native acknowledgement is already pending"));
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingAcknowledgement = null;
      reject(new Error("Native host acknowledgement timed out"));
      disconnectPort();
    }, ACK_TIMEOUT_MS);

    pendingAcknowledgement = {
      eventId: event.event_id,
      resolve,
      reject,
      timeout
    };

    try {
      ensurePort().postMessage(event);
    } catch (error) {
      clearTimeout(timeout);
      pendingAcknowledgement = null;
      reject(error);
      disconnectPort();
    }
  });
}

function handleNativeMessage(message) {
  if (!pendingAcknowledgement) {
    return;
  }

  if (message?.event_id !== pendingAcknowledgement.eventId) {
    return;
  }

  const pending = pendingAcknowledgement;
  pendingAcknowledgement = null;
  clearTimeout(pending.timeout);
  pending.resolve(message);
}

function handleNativeDisconnect() {
  const reason = chrome.runtime.lastError?.message ?? "Native host disconnected";
  port = null;

  if (pendingAcknowledgement) {
    const pending = pendingAcknowledgement;
    pendingAcknowledgement = null;
    clearTimeout(pending.timeout);
    pending.reject(new Error(reason));
  }
}

function disconnectPort() {
  if (!port) {
    return;
  }

  const currentPort = port;
  port = null;
  try {
    currentPort.disconnect();
  } catch {
    // The browser may already have closed the port.
  }
}

function scheduleReconnect() {
  const delay = reconnectDelayMs;
  reconnectDelayMs = Math.min(reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);
  setTimeout(() => void scheduleFlush(), delay);
}

async function updateCounter(name) {
  const stored = await chrome.storage.local.get(COUNTERS_KEY);
  const counters = stored[COUNTERS_KEY] ?? {};
  counters[name] = (counters[name] ?? 0) + 1;
  await chrome.storage.local.set({ [COUNTERS_KEY]: counters });
}

// Try any events left from a previous Edge/native-host shutdown.
void scheduleFlush();
