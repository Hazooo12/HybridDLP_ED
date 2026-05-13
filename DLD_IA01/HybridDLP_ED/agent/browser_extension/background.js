/**
 * DLP Browser Upload Monitor – Background Service Worker (v3)
 * =============================================================
 * Key fixes:
 * - Lazy-connect native host on first upload event (saves startup time)
 * - Keep service worker alive via chrome.alarms
 * - Better error logging visible in chrome://extensions → service worker console
 */

"use strict";

const NATIVE_HOST_ID = "com.dlp.browser_upload";
const RECONNECT_DELAY_MS = 2000;
const MAX_RECONNECT_ATTEMPTS = 20;
const KEEPALIVE_ALARM = "dlp_keepalive";

// ── State ─────────────────────────────────────────────────────────────────────
let nativePort = null;
let reconnectAttempts = 0;
let reconnectTimer = null;

// ── Keep service worker alive (Chrome MV3 kills SW after 30s idle) ────────────
if (typeof chrome?.alarms?.create === "function") {
  chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.4 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === KEEPALIVE_ALARM) {
      // Ping native host to keep connection alive + wake SW
      if (nativePort) {
        try { nativePort.postMessage({ type: "ping" }); } catch { nativePort = null; }
      }
    }
  });
} else {
  console.warn("[DLP] chrome.alarms permission missing. Please remove and re-add extension.");
}

// ── Native Messaging Connection ───────────────────────────────────────────────

function connectNativeHost() {
  if (nativePort) return;

  console.info("[DLP] Connecting to native host:", NATIVE_HOST_ID);

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_ID);
  } catch (err) {
    console.error("[DLP] connectNative() threw:", err.message || err);
    nativePort = null;
    scheduleReconnect();
    return;
  }

  reconnectAttempts = 0;
  console.info("[DLP] ✅ Native host connected");

  nativePort.onMessage.addListener((msg) => {
    console.debug("[DLP] Native host ACK:", JSON.stringify(msg));
  });

  nativePort.onDisconnect.addListener(() => {
    // chrome.runtime.lastError must be read synchronously here
    const errMsg = chrome.runtime.lastError?.message ?? "no error";
    console.warn("[DLP] ⚠️ Native host disconnected:", errMsg);
    nativePort = null;
    scheduleReconnect();
  });
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
    console.error("[DLP] ❌ Max reconnect attempts reached.");
    return;
  }
  reconnectAttempts++;
  console.info(`[DLP] Reconnecting in ${RECONNECT_DELAY_MS}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectNativeHost();
  }, RECONNECT_DELAY_MS);
}

function sendToNativeHost(payload) {
  if (!nativePort) {
    connectNativeHost();
    setTimeout(() => {
      if (nativePort) {
        try { nativePort.postMessage(payload); }
        catch (err) { console.error("[DLP] postMessage (delayed) error:", err); }
      } else {
        console.warn("[DLP] Native host not ready, event dropped:", payload.filename);
      }
    }, 800);
    return;
  }
  try {
    nativePort.postMessage(payload);
    console.info("[DLP] ✅ Forwarded to native host:", payload.filename, payload.trigger);
  } catch (err) {
    console.error("[DLP] postMessage error:", err);
    nativePort = null;
    scheduleReconnect();
  }
}

// ── Tab URL Resolution ────────────────────────────────────────────────────────

async function getTabInfo(tabId) {
  if (!tabId || tabId < 0) return { url: null };
  try {
    const tab = await chrome.tabs.get(tabId);
    return { url: tab.url || null };
  } catch {
    return { url: null };
  }
}

function extractDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// ── Confidence Scoring ────────────────────────────────────────────────────────

function scoreConfidence(ev) {
  let score = 0.5;
  if (ev.trigger === "file_input") score += 0.2;
  if (ev.trigger === "drag_drop")  score += 0.15;
  if (ev.trigger === "xhr" || ev.trigger === "fetch") score += 0.1;
  if (ev.filename) score += 0.1;
  if (ev.size > 0) score += 0.05;
  const sensitive = ["drive.google.com","dropbox.com","onedrive.live.com",
    "wetransfer.com","slack.com","teams.microsoft.com","mail.google.com",
    "chatgpt.com","claude.ai","mega.nz"];
  if (sensitive.some(d => (ev.destination || "").includes(d))) score += 0.15;
  return Math.min(1.0, Math.round(score * 1000) / 1000);
}

// ── Message Handler from Content Script ──────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "dlp_upload_event") return false;

  const tabId = sender?.tab?.id;
  console.info("[DLP] Upload event from content script:", message.trigger, message.filename, message.size);

  getTabInfo(tabId).then((tabInfo) => {
    const tabUrl = tabInfo.url || message.page_url || null;
    const destination = message.destination || extractDomain(tabUrl) || "unknown";

    const payload = {
      browser:           "chrome",
      tab_url:           tabUrl,
      destination:       destination,
      filename:          message.filename || null,
      size:              message.size || null,
      trigger:           message.trigger || "unknown",
      content_type:      message.content_type || null,
      timestamp:         new Date().toISOString(),
      extension_version: chrome.runtime.getManifest().version,
    };
    payload.confidence_score = scoreConfidence(payload);

    console.info("[DLP] Sending to native host:", JSON.stringify(payload));
    sendToNativeHost(payload);
    sendResponse({ status: "queued" });
  });

  return true;
});

// ── Startup ───────────────────────────────────────────────────────────────────

chrome.runtime.onStartup.addListener(() => {
  console.info("[DLP] onStartup – connecting native host");
  connectNativeHost();
});

chrome.runtime.onInstalled.addListener(() => {
  console.info("[DLP] onInstalled – connecting native host");
  connectNativeHost();
});

// Initial connection
connectNativeHost();

console.info("[DLP] Background service worker started. Extension ID:", chrome.runtime.id);
