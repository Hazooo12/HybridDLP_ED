/**
 * DLP Browser Upload Monitor – Content Script (v2)
 * ==================================================
 * Bắt upload events từ 4 nguồn:
 *
 *   1. File Input Watcher  – <input type="file"> .change
 *   2. Drag & Drop Watcher – drop event
 *   3. XHR Intercept       – FormData + Blob + ArrayBuffer (Google Drive dùng cái này)
 *   4. Fetch Intercept     – FormData + Blob
 *
 * Google Drive dùng Resumable Upload API: gửi file bytes dưới dạng
 * ArrayBuffer hoặc Blob qua PUT/POST XHR — KHÔNG dùng FormData.
 * Cần intercept cả blob/arraybuffer để bắt được.
 */

"use strict";

(function () {
  if (window.__dlp_content_v2_injected) return;
  window.__dlp_content_v2_injected = true;

  // ── Helpers ────────────────────────────────────────────────────────────────

  const LOG_PREFIX = "[DLP]";

  function sendUploadEvent(eventData) {
    try {
      chrome.runtime.sendMessage(
        { type: "dlp_upload_event", page_url: window.location.href, ...eventData },
        () => { void chrome.runtime.lastError; }
      );
    } catch (e) {
      // extension context may be invalidated on reload
    }
  }

  function extractFileInfo(file) {
    if (!file) return {};
    return { filename: file.name || null, size: file.size || null, content_type: file.type || null };
  }

  function extractDomain(url) {
    try { return new URL(url).hostname; } catch { return null; }
  }

  function currentDomain() {
    return extractDomain(window.location.href) || window.location.hostname;
  }

  // ── Dedup: avoid sending duplicate events within 3 seconds ────────────────
  const _recentKeys = new Map(); // key → ts
  function isDup(key) {
    const now = Date.now();
    const last = _recentKeys.get(key);
    if (last && now - last < 3000) return true;
    _recentKeys.set(key, now);
    // Cleanup old entries
    if (_recentKeys.size > 200) {
      for (const [k, t] of _recentKeys) {
        if (now - t > 10000) _recentKeys.delete(k);
      }
    }
    return false;
  }

  function emitDeduped(trigger, filename, size, destination) {
    const key = `${trigger}:${filename}:${size}:${destination}`;
    if (isDup(key)) return;
    console.info(LOG_PREFIX, "Upload detected:", trigger, filename, size, destination);
    sendUploadEvent({ trigger, filename, size, content_type: null, destination });
  }

  // ── 1. File Input Watcher ─────────────────────────────────────────────────

  function onFileInputChange(e) {
    const input = e.target;
    if (!input || input.type !== "file" || !input.files || !input.files.length) return;
    Array.from(input.files).forEach(f => {
      emitDeduped("file_input", f.name, f.size, currentDomain());
    });
  }

  const _fileObserver = new MutationObserver(mutations => {
    mutations.forEach(m => m.addedNodes.forEach(node => {
      if (node.nodeType !== 1) return;
      if (node.tagName === "INPUT" && node.type === "file")
        node.addEventListener("change", onFileInputChange);
      node.querySelectorAll?.("input[type='file']").forEach(inp =>
        inp.addEventListener("change", onFileInputChange)
      );
    }));
  });
  _fileObserver.observe(document.documentElement, { childList: true, subtree: true });
  document.querySelectorAll("input[type='file']").forEach(inp =>
    inp.addEventListener("change", onFileInputChange)
  );

  // ── 2. Drag & Drop Watcher ────────────────────────────────────────────────

  document.addEventListener("drop", e => {
    const files = e.dataTransfer?.files;
    if (!files || !files.length) return;
    Array.from(files).forEach(f => emitDeduped("drag_drop", f.name, f.size, currentDomain()));
  }, true);

  // ── 3. XHR Intercept ──────────────────────────────────────────────────────
  // Bắt FormData, Blob, AND ArrayBuffer (Google Drive dùng Blob/ArrayBuffer)

  const _pendingXHR = new WeakMap(); // xhr → { method, url, filename, size }

  const _OrigXHR = window.XMLHttpRequest;
  if (_OrigXHR) {
    class InterceptedXHR extends _OrigXHR {
      open(method, url, ...rest) {
        _pendingXHR.set(this, {
          method: (method || "").toUpperCase(),
          url: String(url || ""),
          filename: null,
          size: null,
        });
        return super.open(method, url, ...rest);
      }

      send(body) {
        const meta = _pendingXHR.get(this) || {};
        const method = meta.method || "";
        const url = meta.url || "";
        const dest = extractDomain(url) || currentDomain();

        if (["POST", "PUT", "PATCH"].includes(method)) {
          if (body instanceof FormData) {
            body.forEach(val => {
              if (val instanceof File && val.size > 0)
                emitDeduped("xhr", val.name, val.size, dest);
            });
          } else if (body instanceof Blob && body.size > 0) {
            // Google Drive resumable upload: POST/PUT with raw Blob
            // Try to get filename from URL query string (?name=...) or use "upload"
            const filename = _extractNameFromUrl(url) || "unknown_blob_upload";
            emitDeduped("xhr", filename, body.size, dest);
          } else if (body instanceof ArrayBuffer && body.byteLength > 0) {
            // Google Drive also sends ArrayBuffer chunks
            const filename = _extractNameFromUrl(url) || "unknown_arraybuffer_upload";
            emitDeduped("xhr", filename, body.byteLength, dest);
          }
        }
        return super.send(body);
      }
    }
    window.XMLHttpRequest = InterceptedXHR;
  }

  // ── 4. Fetch Intercept ────────────────────────────────────────────────────

  const _origFetch = window.fetch;
  if (_origFetch) {
    window.fetch = function (input, init) {
      const method = ((init?.method) || (input?.method) || "GET").toUpperCase();
      const url = typeof input === "string" ? input : (input?.url || "");
      const body = init?.body;
      const dest = extractDomain(url) || currentDomain();

      if (["POST", "PUT", "PATCH"].includes(method) && body) {
        if (body instanceof FormData) {
          body.forEach(val => {
            if (val instanceof File && val.size > 0)
              emitDeduped("fetch", val.name, val.size, dest);
          });
        } else if (body instanceof Blob && body.size > 0) {
          const filename = _extractNameFromUrl(url) || "unknown_blob_upload";
          emitDeduped("fetch", filename, body.size, dest);
        } else if (body instanceof ArrayBuffer && body.byteLength > 0) {
          const filename = _extractNameFromUrl(url) || "unknown_arraybuffer_upload";
          emitDeduped("fetch", filename, body.byteLength, dest);
        }
      }

      return _origFetch.apply(this, arguments);
    };
  }

  // ── URL name extractor (Google Drive embed filename in query) ─────────────

  function _extractNameFromUrl(url) {
    if (!url) return null;
    try {
      const u = new URL(url, window.location.href);
      // Google Drive: ?name=filename.xlsx or &title=filename
      return u.searchParams.get("name")
        || u.searchParams.get("title")
        || u.searchParams.get("filename")
        || null;
    } catch { return null; }
  }

  // ── Message from background (e.g. file name hint from tabs) ──────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "dlp_ping") {
      chrome.runtime.sendMessage({ type: "dlp_pong", url: window.location.href });
    }
  });

  console.debug(LOG_PREFIX, "Content script v2 initialized on", window.location.hostname);
})();
