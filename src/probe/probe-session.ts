/**
 * Probe execution.
 *
 * For each candidate listener we deliver attacker-origin messages built from the
 * inferred schema and observe what the page actually does with them. The verdict
 * is behavioural, not textual: a handler counts as exploited only when it both
 * (a) ran for a message whose `event.origin` is the attacker's and (b) produced
 * an attributable effect — a dangerous sink, a script-execution canary, a
 * navigated/opened window, or an outbound request carrying the payload.
 *
 * That combination is what distinguishes "an origin check exists" from "an
 * origin check exists and actually gates the dangerous path".
 */
import { chromium, type Browser, type BrowserContext, type Frame, type Page, type Route } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { instrumentationSource, extractSourceMappingUrl } from '../browser/page-model.js';
import { buildAttackerHtml } from './attacker.js';
import type { CandidateTarget, ProbeMessage, ListenerAnalysis, EffectRecord, MessageAttempt } from './types.js';
export type { EffectRecord, MessageAttempt } from './types.js';

const MARKER_RE = /^__WMA[0-9a-f]{6,20}__$/;

export function newMarker(): string {
  return '__WMA' + crypto.randomBytes(5).toString('hex') + '__';
}

export interface ProbeSessionOptions {
  targetUrl: string;
  attackerOrigin: string;
  /** Additional attacker origins to serve the harness on (bypass origins). */
  attackerOrigins?: string[];
  /** Serve the target from disk instead of the network. */
  serveDir?: string;
  headless?: boolean;
  timeoutMs?: number;
  debug?: boolean;
  ignoreHTTPSErrors?: boolean;
  headers?: Record<string, string>;
  httpCredentials?: { username: string; password: string };
  cookies?: any[];
  /** Capture screenshots and HTML snapshots for confirmed findings. */
  evidenceDir?: string;
  /** Maximum number of (listener, message) pairs to try. */
  maxProbes?: number;
  /** Per-message settle time. */
  settleMs?: number;
  /** Channel(s) to try. */
  channels?: ('iframe' | 'popup')[];
}

export interface ListenerProbeResult {
  target: CandidateTarget;
  analysis: ListenerAnalysis;
  attempts: MessageAttempt[];
  /** Strongest observed outcome across attempts. */
  outcome: 'exploited' | 'acted' | 'invoked-only' | 'not-invoked' | 'blocked' | 'inconclusive';
  evidence: {
    effects: EffectRecord[];
    snippets: string[];
    screenshots?: string[];
    consoleLines?: string[];
    network?: { url: string; method: string; body?: string }[];
    domDiff?: string;
  };
  notes: string[];
}

interface RuntimeSnapshot {
  sinkSeq: number;
  outSeq: number;
  domSerial: string;
  href: string;
  title: string;
  bodyLength: number;
}

export class ProbeSession {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private attacker: Page | null = null;
  private targetFrame: Frame | null = null;
  private targetPopup: Page | null = null;
  private opts: ProbeSessionOptions;
  private consoleLines: string[] = [];
  private networkLog: { url: string; method: string; body?: string }[] = [];
  private popupPages: Page[] = [];
  private servedAttackerOrigins = new Set<string>();
  private currentAttackerOrigin = '';
  private debug: (...a: any[]) => void;

  constructor(opts: ProbeSessionOptions) {
    this.opts = opts;
    this.debug = opts.debug ? (...a: any[]) => console.error('[probe]', ...a) : () => {};
  }

  get attackerPage(): Page {
    if (!this.attacker) throw new Error('session not started');
    return this.attacker;
  }

  get attackerOriginInUse(): string {
    return this.currentAttackerOrigin || this.opts.attackerOrigin;
  }

  private matchesAttackerOrigin(u: string): boolean {
    for (const o of this.servedAttackerOrigins) {
      if (u === o || u.startsWith(o + '/') || u.startsWith(o + '?') || u.startsWith(o + '#')) return true;
    }
    return false;
  }

  /**
   * Switch the page that hosts the attack to a different origin. Needed because
   * a bypass origin must actually satisfy the target's check, so each weak
   * predicate gets its own origin.
   */
  async switchAttackerOrigin(origin: string, channel: 'iframe' | 'popup'): Promise<boolean> {
    if (origin === this.currentAttackerOrigin) return true;
    this.servedAttackerOrigins.add(origin);
    try {
      await this.attacker!.goto(origin + '/harness', { waitUntil: 'domcontentloaded', timeout: this.opts.timeoutMs ?? 20000 });
      this.currentAttackerOrigin = origin;
      this.popupPages = [];
      if (channel === 'iframe') {
        this.targetFrame = null;
        await this.attacker!.evaluate(() => (window as any).__wmaHarness.embed());
        this.targetFrame = await this.waitForTargetFrame();
        await this.targetFrame.waitForLoadState('domcontentloaded').catch(() => {});
      } else {
        if (this.targetPopup && !this.targetPopup.isClosed()) await this.targetPopup.close().catch(() => {});
        this.targetPopup = null;
        await this.attacker!.evaluate(() => (window as any).__wmaHarness.open());
        this.targetPopup = await this.waitForPopup();
      }
      return true;
    } catch (e) {
      this.debug('switchAttackerOrigin failed', e);
      return false;
    }
  }

  get frame(): Frame {
    if (!this.targetFrame) throw new Error('target frame unavailable');
    return this.targetFrame;
  }

  async start(channel: 'iframe' | 'popup' = 'iframe'): Promise<void> {
    const timeout = this.opts.timeoutMs ?? 20000;
    this.browser = await chromium.launch({
      headless: this.opts.headless ?? true,
      args: ['--disable-features=IsolateOrigins,site-per-process', '--disable-background-timer-throttling'],
    });
    this.context = await this.browser.newContext({
      ignoreHTTPSErrors: this.opts.ignoreHTTPSErrors ?? true,
      extraHTTPHeaders: this.opts.headers,
      httpCredentials: this.opts.httpCredentials,
      viewport: { width: 1280, height: 900 },
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/159.0.0.0 Safari/537.36',
    });
    this.context.setDefaultTimeout(timeout);
    this.context.setDefaultNavigationTimeout(timeout);

    if (this.opts.cookies?.length) {
      await this.context.addCookies(this.opts.cookies).catch((e) => this.debug('cookies failed', e));
    }

    const attackerOrigins = new Set<string>([this.opts.attackerOrigin, ...(this.opts.attackerOrigins || [])]);
    this.servedAttackerOrigins = attackerOrigins;
    const attackerOrigin = this.opts.attackerOrigin;
    const targetOrigin = safeOrigin(this.opts.targetUrl);
    const serveRoot = this.opts.serveDir ? path.resolve(this.opts.serveDir) : null;

    await this.context.route('**/*', async (route: Route) => {
      const req = route.request();
      const u = req.url();
      try {
        if (this.matchesAttackerOrigin(u)) {
          return route.fulfill({
            status: 200,
            contentType: 'text/html; charset=utf-8',
            body: buildAttackerHtml(this.opts.targetUrl),
          });
        }
        if (serveRoot && u.startsWith(targetOrigin)) {
          const rel = decodeURIComponent(new URL(u).pathname).replace(/^\/+/, '') || 'index.html';
          let filePath = path.resolve(serveRoot, rel);
          if (!filePath.startsWith(serveRoot)) return route.fulfill({ status: 403, body: 'forbidden' });
          if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
            if (!path.extname(rel)) {
              const idx = path.join(serveRoot, 'index.html');
              if (fs.existsSync(idx)) filePath = idx;
              else return route.fulfill({ status: 404, body: 'not found' });
            } else {
              return route.fulfill({ status: 404, body: 'not found' });
            }
          }
          const ext = path.extname(filePath).toLowerCase();
          const types: Record<string, string> = {
            '.html': 'text/html; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.mjs': 'application/javascript; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.json': 'application/json; charset=utf-8',
            '.map': 'application/json; charset=utf-8',
            '.svg': 'image/svg+xml',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.ico': 'image/x-icon',
            '.woff2': 'font/woff2',
          };
          return route.fulfill({
            status: 200,
            contentType: types[ext] || 'application/octet-stream',
            body: fs.readFileSync(filePath),
          });
        }
        // Cross-origin third-party assets: let them resolve (or fail) naturally.
        return route.continue();
      } catch (e) {
        return route.abort().catch(() => {});
      }
    });

    await this.context.addInitScript({ content: instrumentationSource() });

    this.context.on('page', (p) => {
      if (p === this.attacker) return;
      this.popupPages.push(p);
    });

    this.attacker = await this.context.newPage();
    this.attacker.on('console', (m) => {
      if (this.consoleLines.length < 400) this.consoleLines.push('[' + m.type() + '] ' + m.text());
    });
    this.attacker.on('pageerror', (e) => {
      if (this.consoleLines.length < 400) this.consoleLines.push('[pageerror] ' + e.message);
    });
    this.context.on('request', (r) => {
      if (this.networkLog.length > 500) return;
      const u = r.url();
      if (this.matchesAttackerOrigin(u)) {
        this.networkLog.push({ url: u, method: r.method(), body: r.postData() || undefined });
      }
    });

    await this.attacker.goto(attackerOrigin + '/harness', { waitUntil: 'domcontentloaded' });
    this.currentAttackerOrigin = attackerOrigin;

    if (channel === 'iframe') {
      await this.attacker.evaluate(() => (window as any).__wmaHarness.embed());
      this.targetFrame = await this.waitForTargetFrame();
    } else {
      await this.attacker.evaluate(() => (window as any).__wmaHarness.open());
      const popup = await this.waitForPopup();
      this.targetPopup = popup;
    }
  }

  private async waitForTargetFrame(): Promise<Frame> {
    const targetOrigin = safeOrigin(this.opts.targetUrl);
    const deadline = Date.now() + (this.opts.timeoutMs ?? 20000);
    while (Date.now() < deadline) {
      for (const f of this.attacker!.frames()) {
        if (f === this.attacker!.mainFrame()) continue;
        if (f.url().startsWith(targetOrigin)) return f;
      }
      await this.attacker!.waitForTimeout(100);
    }
    // Fallback: any non-about:blank subframe
    const any = this.attacker!.frames().find((f) => f !== this.attacker!.mainFrame() && !f.url().startsWith('about:'));
    if (any) return any;
    throw new Error('target frame did not load: ' + this.opts.targetUrl);
  }

  private async waitForPopup(): Promise<Page> {
    const targetOrigin = safeOrigin(this.opts.targetUrl);
    const deadline = Date.now() + (this.opts.timeoutMs ?? 20000);
    while (Date.now() < deadline) {
      for (const p of this.popupPages) {
        if (p.url().startsWith(targetOrigin) || p.url() === 'about:blank') return p;
      }
      await this.attacker!.waitForTimeout(100);
    }
    throw new Error('popup did not open: ' + this.opts.targetUrl);
  }

  /** Re-embed/re-open after a probe navigated the target away. */
  private async frameIsLive(frame: Frame): Promise<boolean> {
    try {
      return await frame.evaluate(() => !!(window as any).__WMA__);
    } catch {
      return false;
    }
  }

  async ensureTarget(channel: 'iframe' | 'popup'): Promise<boolean> {
    const targetOrigin = safeOrigin(this.opts.targetUrl);
    if (channel === 'iframe') {
      if (
        this.targetFrame &&
        !this.targetFrame.isDetached() &&
        this.targetFrame.url().startsWith(targetOrigin) &&
        (await this.frameIsLive(this.targetFrame))
      ) {
        return true;
      }
      // The document navigated away (a `location` sink) or died. Recreate the
      // iframe from scratch rather than trusting the stale one.
      for (let attempt = 0; attempt < 2; attempt++) {
        await this.attacker!.evaluate(() => {
          const h = (window as any).__wmaHarness;
          const f = document.getElementById('wma-target-iframe');
          if (f && f.parentNode) f.parentNode.removeChild(f);
          h.embed();
        }).catch(() => {});
        const frame = await this.waitForTargetFrame().catch(() => null as any);
        if (frame && frame.url().startsWith(targetOrigin)) {
          this.targetFrame = frame;
          await frame.waitForLoadState('domcontentloaded').catch(() => {});
          // Let the target's scripts register listeners again.
          await this.attacker!.waitForTimeout(200);
          return true;
        }
        this.targetFrame = frame;
        await this.attacker!.waitForTimeout(150);
      }
      return false;
    }
    if (this.targetPopup && !this.targetPopup.isClosed() && this.targetPopup.url().startsWith(targetOrigin)) return true;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (this.targetPopup && !this.targetPopup.isClosed()) await this.targetPopup.close().catch(() => {});
      await this.attacker!.evaluate(() => (window as any).__wmaHarness.open()).catch(() => {});
      const popup = await this.waitForPopup().catch(() => null as any);
      if (popup && popup.url().startsWith(targetOrigin)) {
        this.targetPopup = popup;
        await this.attacker!.waitForTimeout(200);
        return true;
      }
      this.targetPopup = popup;
      await this.attacker!.waitForTimeout(150);
    }
    return false;
  }

  activeTargetFrame(channel: 'iframe' | 'popup'): Frame | null {
    if (channel === 'iframe') return this.targetFrame;
    return this.targetPopup ? this.targetPopup.mainFrame() : null;
  }

  /** The frame's current URL, readable even if it has become cross-origin. */
  frameUrl(channel: 'iframe' | 'popup'): string {
    try {
      if (channel === 'iframe') return this.targetFrame ? this.targetFrame.url() : '';
      return this.targetPopup && !this.targetPopup.isClosed() ? this.targetPopup.url() : '';
    } catch {
      return '';
    }
  }

  async snapshot(channel: 'iframe' | 'popup'): Promise<RuntimeSnapshot | null> {
    const frame = this.activeTargetFrame(channel);
    if (!frame) return null;
    try {
      return await frame.evaluate(() => {
        const api = (window as any).__WMA__;
        const body = document.body ? document.body.innerHTML : '';
        return {
          sinkSeq: api ? api.sinkSeq() : 0,
          outSeq: api ? api.outboundSeq() : 0,
          domSerial: document.documentElement ? document.documentElement.outerHTML.length + ':' + body.length : '0',
          bodyLength: body.length,
          href: location.href,
          title: document.title,
        };
      });
    } catch (e) {
      this.debug('snapshot failed', e);
      return null;
    }
  }

  async send(
    channel: 'iframe' | 'popup',
    message: any,
    targetOrigin = '*'
  ): Promise<{ ok: boolean; error?: string }> {
    if (channel === 'iframe') {
      const r = await this.attacker!.evaluate(
        ([m, o]) => (window as any).__wmaHarness.sendToFrame(m, o),
        [message, targetOrigin] as const
      );
      return { ok: r === 'ok', error: r === 'ok' ? undefined : String(r) };
    }
    const r = await this.attacker!.evaluate(
      ([m, o]) => (window as any).__wmaHarness.sendToPopup(m, o),
      [message, targetOrigin] as const
    );
    return { ok: r === 'ok', error: r === 'ok' ? undefined : String(r) };
  }

  async collectEffects(channel: 'iframe' | 'popup', since: RuntimeSnapshot | null, marker: string): Promise<EffectRecord[]> {
    const frame = this.activeTargetFrame(channel);
    const effects: EffectRecord[] = [];
    if (!frame) return effects;
    let post: any = null;
    try {
      post = await frame.evaluate(
        ([sinkSeq, outSeq, mk]) => {
          const api = (window as any).__WMA__;
          if (!api) return null;
          const hits = typeof api.hits === 'function' ? api.hits() : [];
          return {
            sinks: api.sinksSince(sinkSeq).filter((s: any) => !s.driver),
            outbound: api.outboundSince(outSeq),
            invocations: api.invocations(),
            hits,
            body: document.body ? document.body.innerHTML : '',
            href: location.href,
            title: document.title,
            markerPresent: document.documentElement ? document.documentElement.outerHTML.indexOf(mk) !== -1 : false,
          };
        },
        [since?.sinkSeq ?? 0, since?.outSeq ?? 0, marker] as const
      );
    } catch (e) {
      this.debug('effect collection failed', e);
      return effects;
    }
    if (!post) return effects;

    for (const s of post.sinks) {
      const d = s.detail || {};
      const text = JSON.stringify(d);
      const attackerControlled = !!d.marker || text.indexOf(marker) !== -1 || (typeof d.html === 'string' && d.html.indexOf(marker) !== -1);
      effects.push({ kind: 'sink', detail: { kind: s.kind, detail: d }, lid: s.lid, inv: s.inv ? String(s.inv) : null, attackerControlled });
    }
    for (const o of post.outbound) {
      const text = JSON.stringify(o.detail || {});
      effects.push({
        kind: 'outbound',
        detail: o.detail,
        lid: o.lid,
        inv: o.inv ? String(o.inv) : null,
        attackerControlled: text.indexOf(marker) !== -1,
      });
    }
    for (const h of post.hits) {
      if (typeof h.token === 'string' && h.token.indexOf(marker) !== -1) {
        effects.push({ kind: 'canary', detail: h, attackerControlled: true });
      }
    }
    // Any execution of our marker through a script context counts even when the
    // sink hook missed the assignment (e.g. through a framework's DOM builder).
    if (post.markerPresent && !effects.some((e) => e.kind === 'canary')) {
      effects.push({ kind: 'dom', detail: { markerInDom: true }, attackerControlled: true });
    }
    if (since) {
      const currentUrl = this.frameUrl(channel);
      if (currentUrl && currentUrl !== since.href && !currentUrl.startsWith('about:')) {
        // The document navigated, so it no longer carries our instrumentation.
        // We cannot read the URL's contents from the page, but a navigation away
        // from the target origin during an attacker message is itself the effect;
        // whether it was attacker-directed is decided by the caller from the
        // message that caused it.
        effects.push({
          kind: 'navigation',
          detail: { from: since.href, to: currentUrl },
          attackerControlled: false,
        });
      } else if (post.body !== undefined && since.bodyLength !== undefined) {
        const delta = Math.abs(post.body.length - since.bodyLength);
        if (delta > 0 && delta < 200000) {
          effects.push({ kind: 'dom', detail: { bodyDelta: delta }, attackerControlled: post.markerPresent });
        }
      }
    }
    // New popups opened by the target during this attempt. Our own harness page
    // and the target document itself are not popups the target opened.
    if (this.popupPages.length) {
      const targetOrigin = safeOrigin(this.opts.targetUrl);
      for (const p of this.popupPages) {
        const u = p.url();
        if (u.startsWith(this.opts.attackerOrigin)) continue;
        if (u.startsWith(targetOrigin) && p === this.targetPopup) continue;
        if (u === 'about:blank') continue;
        effects.push({ kind: 'popup', detail: { url: u }, attackerControlled: u.indexOf(marker) !== -1 });
      }
      this.popupPages = [];
    }
    return effects;
  }

  /** Register the marker as a global function in the target document. */
  async installCanary(channel: 'iframe' | 'popup', marker: string): Promise<void> {
    const frame = this.activeTargetFrame(channel);
    if (!frame) return;
    try {
      await frame.evaluate((m) => {
        const api = (window as any).__WMA__;
        if (api && typeof api.defineCanary === 'function') {
          api.defineCanary(m);
        } else {
          (window as any)[m] = function () {
            if ((window as any).__WMA_HIT__) (window as any).__WMA_HIT__(m);
          };
        }
      }, marker);
    } catch (e) {
      this.debug('installCanary failed', e);
    }
  }

  async targetInvocationSummary(channel: 'iframe' | 'popup'): Promise<any[]> {
    const frame = this.activeTargetFrame(channel);
    if (!frame) return [];
    try {
      return await frame.evaluate(() => {
        const api = (window as any).__WMA__;
        if (!api) return [];
        return api.invocations().map((i: any) => ({
          id: i.id,
          lid: i.lid,
          originRead: i.originRead,
          sourceRead: i.sourceRead,
          dataRead: i.dataRead,
          originValue: i.originValue,
          threw: i.threw,
          durationMs: i.durationMs,
          paths: Object.keys(i.paths || {}),
          compares: i.compareSamples || [],
          originCompares: i.originCompares || [],
        }));
      });
    } catch {
      return [];
    }
  }

  async captureEvidence(channel: 'iframe' | 'popup', label: string): Promise<{ screenshot?: string }> {
    if (!this.opts.evidenceDir) return {};
    try {
      fs.mkdirSync(this.opts.evidenceDir, { recursive: true });
      const file = path.join(this.opts.evidenceDir, safeFileName(label) + '.png');
      if (channel === 'iframe' && this.attacker) {
        await this.attacker.screenshot({ path: file, fullPage: false });
      } else if (this.targetPopup) {
        await this.targetPopup.screenshot({ path: file });
      }
      return { screenshot: file };
    } catch (e) {
      this.debug('screenshot failed', e);
      return {};
    }
  }

  consoleSnapshot(): string[] {
    return this.consoleLines.slice();
  }

  networkSnapshot(): { url: string; method: string; body?: string }[] {
    return this.networkLog.slice();
  }

  async close(): Promise<void> {
    await this.browser?.close().catch(() => {});
    this.browser = null;
    this.context = null;
    this.attacker = null;
    this.targetFrame = null;
    this.targetPopup = null;
  }

  async reloadTarget(channel: 'iframe' | 'popup'): Promise<void> {
    if (channel === 'iframe') {
      await this.attacker!.evaluate(() => {
        const f = document.getElementById('wma-target-iframe');
        if (f && f.parentNode) f.parentNode.removeChild(f);
        (window as any).__wmaHarness && (window as any).__wmaHarness.embed();
      });
      this.targetFrame = await this.waitForTargetFrame();
      await this.targetFrame.waitForLoadState('domcontentloaded').catch(() => {});
      await this.attacker!.waitForTimeout(400);
    } else {
      if (this.targetPopup && !this.targetPopup.isClosed()) await this.targetPopup.close().catch(() => {});
      this.popupPages = [];
      await this.attacker!.evaluate(() => (window as any).__wmaHarness.open());
      this.targetPopup = await this.waitForPopup();
      await this.attacker!.waitForTimeout(400);
    }
  }
}

export function safeOrigin(u: string): string {
  try {
    return new URL(u).origin;
  } catch {
    return '';
  }
}

function safeFileName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 120);
}
