/**
 * Page acquisition: launches a Chromium context with an origin-mapping routing
 * layer so that arbitrary sites (target + attacker) can be served locally while
 * keeping real, distinct browser origins. Everything the rest of the tool needs
 * about "what is on the page" comes from here.
 */
import { chromium, type Browser, type BrowserContext, type Page, type Route, type Frame } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUnit, scanHtml, type SourceUnit, type StaticScanResult } from '../analysis/static-scan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ASSET_DIR = path.resolve(__dirname, '../../assets');

export interface PageModelOptions {
  /** URL to audit. */
  url: string;
  /** Extra origins treated as same-site/trusted for schema generation. */
  trustedOrigins?: string[];
  /** Headless (default true). */
  headless?: boolean;
  /** Navigation / settle timeout. */
  timeoutMs?: number;
  /** Bypass TLS errors for self-signed targets. */
  ignoreHTTPSErrors?: boolean;
  /** Local fixture directory served for the target origin (offline mode). */
  serveDir?: string;
  /** Request headers forwarded to the target. */
  headers?: Record<string, string>;
  /** Cookie jar entries applied before navigation. */
  cookies?: { name: string; value: string; url?: string; domain?: string; path?: string }[];
  /** Basic auth. */
  httpCredentials?: { username: string; password: string };
  /** Keep the browser open for interactive probing. */
  keepOpen?: boolean;
  /** Verbose driver logging. */
  debug?: boolean;
}

export interface FetchedScript {
  url: string;
  code: string;
  inline: boolean;
  /** Document that contained it (for inline scripts). */
  documentUrl: string;
  /** Response had a sourceMappingURL and we fetched it. */
  mapUrl?: string;
  mapJson?: any;
}

export interface RuntimeFrame {
  frameId: number;
  url: string;
  origin: string;
  name: string;
  isTop: boolean;
  parentId: number | null;
}

export interface CapturedListener {
  /** Composite id: frame index + in-frame lid. */
  id: string;
  frameId: number;
  lid: string;
  type: string;
  target: string;
  capture: boolean;
  once: boolean;
  objectListener: boolean;
  origin: string;
  registeredAt: number;
  stack: { fn: string; url: string; line: number | null; col: number | null }[];
  source: string;
  invocations: number;
  removed: boolean;
  frameUrl: string;
  frameOrigin: string;
  isTop: boolean;
}

export interface PageModel {
  url: string;
  finalUrl: string;
  origin: string;
  title: string;
  frames: RuntimeFrame[];
  listeners: CapturedListener[];
  scripts: FetchedScript[];
  staticScan: StaticScanResult[];
  html: string;
  responseStatus: number | null;
  domMarkerCount: number;
  /** Timings for reporting. */
  timing: { navMs: number; settleMs: number; scanMs: number };
  /** Diagnostics from the instrumentation itself. */
  instrumentErrors: { frameUrl: string; errors: any[]; hooks?: string[] }[];
  /** All origins observed to be same-page/embedded, for schema defaults. */
  embeddedOrigins: string[];
  /** Security headers seen on the top-level document. */
  headers: Record<string, string>;
}

const INIT_BUNDLE = (() => {
  try {
    const core = fs.readFileSync(path.join(ASSET_DIR, 'wma-core.js'), 'utf8');
    const sinks = fs.readFileSync(path.join(ASSET_DIR, 'wma-sinks.js'), 'utf8');
    return core + '\n' + sinks;
  } catch {
    return '';
  }
})();

const INIT_SOURCE_URL = '\n//# sourceURL=wma-inject.js\n';

export function instrumentationSource(): string {
  if (!INIT_BUNDLE) throw new Error('instrumentation bundle missing under assets/');
  // The sourceURL must be the last line of the script, so it is appended to the
  // whole bundle at use time. It gives our own frames a recognisable url, which
  // is what lets stack filtering discard instrumentation noise reliably.
  return INIT_BUNDLE + INIT_SOURCE_URL;
}

function isSameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function looksMinified(code: string): boolean {
  if (code.length < 2000) return false;
  const lines = code.split('\n');
  if (lines.length > code.length / 120) return false;
  const avg = code.length / Math.max(lines.length, 1);
  return avg > 200;
}

/**
 * Launch a browser context and load the target, capturing every script and
 * every message listener that registers while the page settles.
 */
export async function acquirePageModel(opts: PageModelOptions): Promise<{
  browser: Browser;
  context: BrowserContext;
  page: Page;
  model: PageModel;
  close: () => Promise<void>;
}> {
  const timeout = opts.timeoutMs ?? 20000;
  const debug = opts.debug ? (...a: any[]) => console.error('[driver]', ...a) : () => {};

  const launchArgs = [
    '--host-resolver-rules=MAP * 127.0.0.1',
    '--disable-features=IsolateOrigins,site-per-process',
  ];
  const browser = await chromium.launch({ headless: opts.headless ?? true, args: launchArgs });
  const context = await browser.newContext({
    ignoreHTTPSErrors: opts.ignoreHTTPSErrors ?? true,
    extraHTTPHeaders: opts.headers,
    httpCredentials: opts.httpCredentials,
    viewport: { width: 1280, height: 900 },
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/159.0.0.0 Safari/537.36',
  });
  context.setDefaultTimeout(timeout);
  context.setDefaultNavigationTimeout(timeout);

  if (opts.cookies?.length) {
    try {
      const urls = new Set<string>();
      for (const c of opts.cookies) if (c.url) urls.add(c.url);
      await context.addCookies(opts.cookies as any);
    } catch (e) {
      debug('cookie injection failed', e);
    }
  }

  const scripts: FetchedScript[] = [];
  const scriptUrlsSeen = new Set<string>();
  const targetOrigin = (() => {
    try {
      return new URL(opts.url).origin;
    } catch {
      return '';
    }
  })();

  // Serve local fixtures for the target origin when requested; never intercept
  // cross-origin third-party requests we do not own (they are allowed to fail).
  if (opts.serveDir) {
    const root = path.resolve(opts.serveDir);
    await context.route('**/*', async (route: Route) => {
      const req = route.request();
      const u = req.url();
      if (!u.startsWith(targetOrigin)) return route.continue();
      const rel = decodeURIComponent(new URL(u).pathname).replace(/^\/+/, '') || 'index.html';
      const filePath = path.resolve(root, rel);
      if (!filePath.startsWith(root)) return route.fulfill({ status: 403, body: 'forbidden' });
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
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
          '.ico': 'image/x-icon',
        };
        return route.fulfill({
          status: 200,
          contentType: types[ext] || 'application/octet-stream',
          body: fs.readFileSync(filePath),
        });
      }
      if (rel === 'index.html' || !path.extname(rel)) {
        const idx = path.join(root, 'index.html');
        if (fs.existsSync(idx)) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: fs.readFileSync(idx) });
      }
      return route.fulfill({ status: 404, body: 'not found' });
    });
  }

  // Capture scripts from network, so we see exactly what the browser executed.
  context.on('response', async (response) => {
    try {
      const req = response.request();
      if (req.resourceType() !== 'script') return;
      const url = req.url();
      if (scriptUrlsSeen.has(url)) return;
      scriptUrlsSeen.add(url);
      const headers = response.headers();
      const ct = headers['content-type'] || '';
      if (ct && !/javascript|ecmascript|json/i.test(ct)) return;
      const body = await response.body().catch(() => null);
      if (!body) return;
      const code = body.toString('utf8');
      if (!code) return;
      const mapUrl = extractSourceMappingUrl(code, url);
      let mapJson: any = undefined;
      if (mapUrl) {
        mapJson = resolveSourceMap(mapUrl, opts.serveDir) || undefined;
        if (!mapJson) {
          try {
            const res = await context.request.get(mapUrl);
            if (res.ok()) mapJson = await res.json().catch(() => undefined);
          } catch {
            /* map is optional */
          }
        }
      }
      scripts.push({ url, code, inline: false, documentUrl: pageMainFrameUrl() || opts.url, mapUrl: mapUrl || undefined, mapJson });
    } catch (e) {
      debug('script capture failed', e);
    }
  });

  function pageMainFrameUrl(): string | null {
    try {
      return page.mainFrame().url();
    } catch {
      return null;
    }
  }

  context.on('requestfailed', (r) => {
    if (debug && r.resourceType() === 'script') debug('script failed', r.url(), r.failure()?.errorText);
  });

  await context.addInitScript({ content: instrumentationSource() });

  const page = await context.newPage();
  page.on('dialog', async (d) => {
    debug('dismissing dialog', d.type(), d.message());
    await d.dismiss().catch(() => {});
  });
  page.on('pageerror', (e) => debug('pageerror', e.message));

  const navStart = Date.now();
  let response: any = null;
  try {
    response = await page.goto(opts.url, { waitUntil: 'domcontentloaded', timeout });
  } catch (e: any) {
    debug('navigation failed', e.message);
  }
  const navMs = Date.now() - navStart;

  const settleStart = Date.now();
  await page.waitForLoadState('load', { timeout: Math.min(timeout, 15000) }).catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  // Give deferred listeners (widget bootstraps) a chance to register.
  await page.waitForTimeout(600);
  const settleMs = Date.now() - settleStart;

  const scanStart = Date.now();
  const frames = await collectFrames(page);
  const listeners = await collectListeners(page, frames);
  const html = await page.content().catch(() => '');
  const headers = response ? (await response.allHeaders().catch(() => ({}))) : {};

  // Inline scripts from the DOM (network capture misses them).
  const inlineUnits: FetchedScript[] = [];
  try {
    const inline = await page.evaluate(() => {
      const out: { code: string; url: string }[] = [];
      const scripts = Array.from(document.querySelectorAll('script'));
      scripts.forEach((s, i) => {
        if (s.src) return;
        const code = s.textContent || '';
        // Keep every inline script that could participate in message handling:
        // either it mentions messaging directly, or it configures a library that
        // does (a callback the library invokes with message fields).
        if (!/\bmessage\b|onmessage|\bpostMessage|onCommand|addEventListener|WebView|bridge|receive/i.test(code)) return;
        out.push({ code, url: location.href + '#inline-' + i });
      });
      return out;
    });
    for (const i of inline) inlineUnits.push({ url: i.url, code: i.code, inline: true, documentUrl: page.url() });
  } catch {
    /* page may have navigated */
  }

  // Merge network + inline scripts, dedupe by content hash.
  const seen = new Set<string>();
  const allScripts: FetchedScript[] = [];
  for (const s of [...scripts, ...inlineUnits]) {
    const key = hash(s.code);
    if (seen.has(key)) continue;
    seen.add(key);
    allScripts.push(s);
  }

  const staticScan: StaticScanResult[] = [];
  for (const s of allScripts) {
    const unit: SourceUnit = { url: s.url, code: s.code, inline: s.inline, minified: looksMinified(s.code) };
    try {
      staticScan.push(scanUnit(unit));
    } catch (e) {
      staticScan.push({ unitUrl: s.url, listeners: [], parseErrors: [{ message: String(e) }], candidateOrigins: [], dynamicRegistrations: 0 });
    }
  }
  // HTML-level inline attributes.
  if (html) {
    const htmlScan = scanHtml(html, page.url());
    if (htmlScan.attributeListeners.length) {
      staticScan.push({
        unitUrl: page.url(),
        listeners: htmlScan.attributeListeners,
        parseErrors: [],
        candidateOrigins: [],
        dynamicRegistrations: 0,
      });
    }
  }

  // DOM marker scan: data attributes carrying an audit marker set by a previous
  // probe (used to detect persistence/reflection).
  const domMarkerCount = await page
    .evaluate(() => document.querySelectorAll('[data-wma], [data-wma-x]').length)
    .catch(() => 0);

  const instrumentErrors: PageModel['instrumentErrors'] = [];
  for (let i = 0; i < frames.length; i++) {
    const f = page.frames()[i];
    if (!f) continue;
    try {
      const info = await f.evaluate(() => {
        const api = (window as any).__WMA__;
        if (!api) return null;
        return { errors: api.errors(), hooks: typeof api.installedHooks === 'function' ? api.installedHooks() : [] };
      });
      if (info && (info.errors.length || !info.hooks?.includes('html'))) {
        instrumentErrors.push({ frameUrl: f.url(), errors: info.errors, hooks: info.hooks });
      }
    } catch {
      /* detached frame */
    }
  }

  const embeddedOrigins = Array.from(
    new Set(frames.filter((f) => !isSameOrigin(f.url, opts.url)).map((f) => f.origin).filter(Boolean))
  );

  const scanMs = Date.now() - scanStart;

  const model: PageModel = {
    url: opts.url,
    finalUrl: page.url(),
    origin: targetOrigin,
    title: await page.title().catch(() => ''),
    frames,
    listeners,
    scripts: allScripts,
    staticScan,
    html,
    responseStatus: response ? response.status() : null,
    domMarkerCount,
    timing: { navMs, settleMs, scanMs },
    instrumentErrors,
    embeddedOrigins,
    headers: lowerKeys(headers),
  };

  const close = async () => {
    if (!opts.keepOpen) await browser.close().catch(() => {});
  };

  return { browser, context, page, model, close };
}

async function collectFrames(page: Page): Promise<RuntimeFrame[]> {
  const frames = page.frames();
  const out: RuntimeFrame[] = [];
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i]!;
    let info: any = null;
    try {
      info = await f.evaluate(() => {
        const api = (window as any).__WMA__;
        if (api?.frameInfo) return api.frameInfo();
        return { href: location.href, origin: location.origin, isTop: window.top === window, name: window.name };
      });
    } catch {
      out.push({ frameId: i, url: f.url(), origin: safeOrigin(f.url()), name: '', isTop: false, parentId: -1 });
      continue;
    }
    out.push({
      frameId: i,
      url: info.href || f.url(),
      origin: info.origin || safeOrigin(f.url()),
      name: info.name || '',
      isTop: !!info.isTop,
      parentId: f.parentFrame() ? frames.indexOf(f.parentFrame()!) : null,
    });
  }
  return out;
}

async function collectListeners(page: Page, frames: RuntimeFrame[]): Promise<CapturedListener[]> {
  const out: CapturedListener[] = [];
  const pwFrames = page.frames();
  for (const frame of frames) {
    const pf = pwFrames[frame.frameId];
    if (!pf) continue;
    let list: any[] = [];
    try {
      list = await pf.evaluate(() => {
        const api = (window as any).__WMA__;
        return api ? api.listeners() : [];
      });
    } catch {
      continue;
    }
    for (const l of list) {
      out.push({
        id: `f${frame.frameId}:${l.lid}`,
        frameId: frame.frameId,
        lid: l.lid,
        type: l.type,
        target: l.target,
        capture: !!l.capture,
        once: !!l.once,
        objectListener: !!l.objectListener,
        origin: l.origin,
        registeredAt: l.registeredAt,
        stack: l.stack || [],
        source: l.source || '',
        invocations: l.invocations || 0,
        removed: !!l.removed,
        frameUrl: frame.url,
        frameOrigin: frame.origin,
        isTop: frame.isTop,
      });
    }
  }
  return out;
}

export async function collectFrameListeners(page: Page): Promise<CapturedListener[]> {
  const frames = await collectFrames(page);
  return collectListeners(page, frames);
}

/**
 * Resolve a source map that lives next to the target when the target is served
 * from disk. context.request bypasses the route layer, so an offline fixture's
 * map would otherwise be unreachable.
 */
function resolveSourceMap(mapUrl: string, serveDir?: string): any | null {
  if (!serveDir) return null;
  try {
    const root = path.resolve(serveDir);
    const rel = decodeURIComponent(new URL(mapUrl).pathname).replace(/^\/+/, '');
    const filePath = path.resolve(root, rel);
    if (!filePath.startsWith(root)) return null;
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch {
    /* malformed map */
  }
  return null;
}

export function extractSourceMappingUrl(code: string, baseUrl: string): string | null {
  const m = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(code.slice(-4096));
  if (!m) return null;
  try {
    return new URL(m[1]!, baseUrl).toString();
  } catch {
    return null;
  }
}

function lowerKeys(o: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o || {})) out[k.toLowerCase()] = v;
  return out;
}

function safeOrigin(u: string): string {
  try {
    return new URL(u).origin;
  } catch {
    return '';
  }
}

function hash(s: string): string {
  let h1 = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h1 ^= s.charCodeAt(i);
    h1 = Math.imul(h1, 0x01000193);
  }
  return (h1 >>> 0).toString(16) + ':' + s.length.toString(16);
}
