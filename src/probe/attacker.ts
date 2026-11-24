/**
 * Attacker harness.
 *
 * Produces a real, hostile page on an origin the audited page does *not*
 * control, plus the page-side script that drives delivery. Real postMessage
 * delivery matters: a synthetic `window.dispatchEvent(new MessageEvent(...))`
 * would test a different code path than the one an actual attacker hits, and
 * would fabricate an `event.origin` the browser never produced.
 *
 * Two delivery channels cover the observable attack surface:
 *   iframe   — the target embedded in an attacker page (frame busting aside)
 *   popup    — the target opened with window.open, then messaged
 */
import type { Page, Frame } from 'playwright';

export interface AttackerHarness {
  /** Attacker page origin. */
  origin: string;
  pageUrl: string;
}

export function buildAttackerHtml(targetUrl: string, opts: { marker?: string } = {}): string {
  const escaped = JSON.stringify(targetUrl);
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>wma-harness</title></head>
<body>
<script>
(function () {
  var TARGET = ${escaped};
  var frame = null;
  var popup = null;
  var received = [];
  window.addEventListener('message', function (e) {
    try {
      received.push({ origin: e.origin, data: e.data });
      if (received.length > 200) received.shift();
    } catch (err) {}
  });
  window.__wmaHarness = {
    embed: function () {
      // Recreate when the cached frame is gone or no longer in the document:
      // probes that hit a navigation sink leave a dead iframe behind.
      if (frame && frame.parentNode && frame.parentNode.nodeType === 1) return true;
      if (frame && frame.parentNode) frame.parentNode.removeChild(frame);
      frame = document.createElement('iframe');
      frame.id = 'wma-target-iframe';
      frame.name = 'wmaTarget';
      frame.style.cssText = 'width:900px;height:700px;border:0';
      frame.src = TARGET;
      document.body.appendChild(frame);
      return true;
    },
    frameReady: function () {
      try { return !!(frame && frame.contentWindow); } catch (e) { return false; }
    },
    sendToFrame: function (message, targetOrigin) {
      if (!frame || !frame.contentWindow) return 'no-frame';
      try {
        frame.contentWindow.postMessage(message, targetOrigin || '*');
        return 'ok';
      } catch (e) {
        return 'error:' + (e && e.name);
      }
    },
    open: function () {
      if (popup && !popup.closed && (function(){ try { return true; } catch(e){ return false; } })()) {
        try { popup.location.href; } catch (e) { popup = null; }
      }
      if (popup && !popup.closed) return true;
      popup = window.open(TARGET, 'wmaPopup', 'width=900,height=700');
      return !!popup;
    },
    sendToPopup: function (message, targetOrigin) {
      if (!popup || popup.closed) return 'no-popup';
      try {
        popup.postMessage(message, targetOrigin || '*');
        return 'ok';
      } catch (e) {
        return 'error:' + (e && e.name);
      }
    },
    received: function () { return received.slice(); }
  };
})();
</script>
</body></html>`;
}

/** Install the harness page content on an arbitrary origin via routing. */
export async function installHarness(page: Page, targetUrl: string): Promise<void> {
  await page.setContent(buildAttackerHtml(targetUrl), { waitUntil: 'domcontentloaded' });
}

export interface DeliveryResult {
  channel: 'iframe' | 'popup';
  sent: boolean;
  error?: string;
  /** Frame handle for the target document, when deliverable. */
  targetFrame?: Frame;
  targetPage?: Page;
}

/**
 * Embed the target in the attacker page and return the frame that hosts it.
 */
export async function deliverViaIframe(
  attacker: Page,
  opts: { settleMs?: number } = {}
): Promise<DeliveryResult> {
  await attacker.evaluate(() => (window as any).__wmaHarness.embed());
  const settle = opts.settleMs ?? 1200;
  const deadline = Date.now() + settle;
  let frame: Frame | undefined;
  while (Date.now() < deadline) {
    frame = attacker.frames().find((f) => {
      const u = f.url();
      return u && u !== 'about:blank' && !u.startsWith('data:');
    });
    if (frame) break;
    await attacker.waitForTimeout(100);
  }
  if (!frame) return { channel: 'iframe', sent: false, error: 'target frame never loaded' };
  await frame.waitForLoadState('domcontentloaded').catch(() => {});
  return { channel: 'iframe', sent: true, targetFrame: frame };
}

export async function sendToFrame(attacker: Page, message: any, targetOrigin = '*'): Promise<DeliveryResult> {
  const r = await attacker.evaluate(
    ([m, o]) => (window as any).__wmaHarness.sendToFrame(m, o),
    [message, targetOrigin] as const
  );
  return { channel: 'iframe', sent: r === 'ok', error: r === 'ok' ? undefined : String(r) };
}

export async function sendToPopup(attacker: Page, message: any, targetOrigin = '*'): Promise<DeliveryResult> {
  const r = await attacker.evaluate(
    ([m, o]) => (window as any).__wmaHarness.sendToPopup(m, o),
    [message, targetOrigin] as const
  );
  return { channel: 'popup', sent: r === 'ok', error: r === 'ok' ? undefined : String(r) };
}

export async function messagesReceived(attacker: Page): Promise<{ origin: string; data: any }[]> {
  return attacker.evaluate(() => (window as any).__wmaHarness.received());
}
