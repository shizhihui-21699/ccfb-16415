/**
 * Report writers: console, JSON, SARIF 2.1.0 (for CI/code scanning) and a
 * self-contained HTML report.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { Finding, ScanReport, Severity } from './types.js';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface WriteOptions {
  outDir?: string;
  formats?: ('json' | 'sarif' | 'html' | 'md')[];
  /** Base name for output files. */
  baseName?: string;
  /** Pretty console summary (default true). */
  console?: boolean;
  /** Include source snippets in machine formats. */
  includeSnippets?: boolean;
}

export interface WriteResult {
  files: string[];
}

export async function writeReports(report: ScanReport, opts: WriteOptions = {}): Promise<WriteResult> {
  const formats = opts.formats || ['json', 'html', 'sarif', 'md'];
  const outDir = path.resolve(opts.outDir || 'wma-report');
  fs.mkdirSync(outDir, { recursive: true });
  const base = opts.baseName || 'report';
  const files: string[] = [];

  if (formats.includes('json')) {
    const f = path.join(outDir, base + '.json');
    fs.writeFileSync(f, JSON.stringify(report, null, 2));
    files.push(f);
  }
  if (formats.includes('sarif')) {
    const f = path.join(outDir, base + '.sarif');
    fs.writeFileSync(f, JSON.stringify(toSarif(report), null, 2));
    files.push(f);
  }
  if (formats.includes('html')) {
    const f = path.join(outDir, base + '.html');
    fs.writeFileSync(f, renderHtml(report, { includeSnippets: opts.includeSnippets !== false }));
    files.push(f);
  }
  if (formats.includes('md')) {
    const f = path.join(outDir, base + '.md');
    fs.writeFileSync(f, renderMarkdown(report));
    files.push(f);
  }
  if (opts.console !== false) {
    process.stdout.write(renderConsole(report) + '\n');
  }
  return { files };
}

// ------------------------------------------------------------------ console

export function renderConsole(report: ScanReport): string {
  const lines: string[] = [];
  const s = report.stats;
  const c = s.bySeverity;
  lines.push('');
  lines.push(`  postmsg-audit — ${report.options.url}`);
  lines.push(`  ${report.page.title ? '"' + report.page.title + '" · ' : ''}${s.frames} frame(s) · ${s.listenersDiscovered} message listener(s) · ${s.durationMs} ms`);
  lines.push('');
  const counts = SEV_ORDER.map((sev) => `${severityColor(sev)}${c[sev] || 0}\x1b[0m ${sev}`).join('  ');
  lines.push(`  ${counts}`);
  lines.push('');

  if (!report.findings.length) {
    lines.push('  No message listeners found.');
    return lines.join('\n');
  }

  for (const f of report.findings) {
    const tag = severityTag(f.severity);
    lines.push(`  ${tag} ${f.title}`);
    lines.push(`        ${f.id} · ${f.verdict} · guard=${f.validation.verdict} · origin=${f.delivery.attackerOrigin || report.options.attackerOrigin} via ${f.delivery.channel}`);
    if (f.handler.original) lines.push(`        at ${f.handler.original.url}:${f.handler.original.line} (source-mapped)`);
    else lines.push(`        at ${f.handler.location.url}:${f.handler.location.line ?? '?'}`);
    if (f.impact.canaryExecuted) lines.push(`        ✔ script execution confirmed in the browser`);
    else if (f.impact.attackerControlled) lines.push(`        ✔ attacker-controlled effect observed`);
    if (f.validation.weaknesses.length) {
      for (const w of f.validation.weaknesses.slice(0, 2)) lines.push(`        ! ${w}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function severityTag(sev: Severity): string {
  const color: Record<Severity, string> = { critical: '\x1b[41;97m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[90m' };
  const label: Record<Severity, string> = { critical: 'CRIT ', high: 'HIGH ', medium: 'MED  ', low: 'LOW  ', info: 'INFO ' };
  return `${color[sev]}${label[sev]}\x1b[0m`;
}
function severityColor(sev: Severity): string {
  return { critical: '\x1b[31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[90m' }[sev];
}

// -------------------------------------------------------------------- sarif

export function toSarif(report: ScanReport): any {
  const rules = new Map<string, any>();
  const results: any[] = [];

  for (const f of report.findings) {
    if (f.verdict === 'not-a-finding' || f.severity === 'info') continue;
    const ruleId = 'WMA/' + f.validation.verdict + (f.impact.canaryExecuted ? '+xss' : '');
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: `postMessage-${f.validation.verdict}`,
        shortDescription: { text: describeRule(f.validation.verdict) },
        fullDescription: { text: f.remediation.summary },
        helpUri: 'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns',
        properties: { tags: ['security', 'postMessage', 'cross-origin'] },
      });
    }
    const loc0 = f.handler.original || f.handler.location;
    const uri = loc0.url;
    const isFile = /^https?:/.test(uri) ? uri : uri;
    results.push({
      ruleId,
      level: sarifLevel(f.severity),
      message: {
        text: `${f.title}\n\n${f.summary}\n\n${f.impact.narrative}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: isFile },
            region: {
              startLine: Math.max(1, (loc0.line as number) || 1),
              startColumn: Math.max(1, ((loc0 as any).column || 0) + 1),
            },
          },
        },
      ],
      partialFingerprints: {
        'wmaHandler/v1': `${f.handler.name}:${f.validation.verdict}:${uri}`,
      },
      properties: {
        severity: f.severity,
        verdict: f.verdict,
        canaryExecuted: f.impact.canaryExecuted,
        originChecked: f.validation.verdict,
      },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'postmsg-audit',
            informationUri: 'https://owasp.org/www-community/attacks/Cross-origin_scripting',
            version: report.version,
            rules: Array.from(rules.values()),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.generatedAt,
            workingDirectory: { uri: report.options.url },
          },
        ],
        results,
      },
    ],
  };
}

function sarifLevel(sev: Severity): 'error' | 'warning' | 'note' {
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'medium') return 'warning';
  return 'note';
}

function describeRule(verdict: string): string {
  const m: Record<string, string> = {
    none: 'Message handler accepts messages from any origin',
    weak: 'Origin validation is bypassable (substring/prefix/regex)',
    'deny-list': 'Deny-list origin validation allows unknown origins',
    'data-based': 'Handler authenticates message data instead of origin',
    'source-based': 'Handler trusts window identity instead of origin',
    'post-check': 'Origin validation runs after the sensitive action',
    unknown: 'Origin validation could not be verified',
    strong: 'Exact origin allow-list enforced',
    'same-origin': 'Same-origin check enforced',
  };
  return m[verdict] || 'Cross-window message handling issue';
}

// --------------------------------------------------------------------- html

export function renderHtml(report: ScanReport, opts: { includeSnippets?: boolean } = {}): string {
  const includeSnippets = opts.includeSnippets !== false;
  const esc = (s: any) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
  const c = report.stats.bySeverity;

  const findingHtml = report.findings
    .map((f, i) => {
      const srcLines = f.handler.sourceLines
        ? f.handler.sourceLines
            .map((l) => `<span class="ln">${l.line}</span>${esc(l.text)}`)
            .join('\n')
        : esc(f.handler.sourceSnippet);
      const attempts = (f.proof?.attempts || [])
        .filter((a) => a.delivered)
        .slice(0, 4)
        .map(
          (a) => `
            <details class="attempt">
              <summary>${esc(snippetJson(a.message))} <span class="muted">(${a.invoked} handler invocation${a.invoked === 1 ? '' : 's'})</span></summary>
              <ul>${a.effects.map((e) => `<li><b>${esc(e.kind)}</b>${e.attackerControlled ? ' <span class="attacker">attacker-controlled</span>' : ''} — ${esc(e.detail)}</li>`).join('') || '<li class="muted">no effect observed</li>'}</ul>
            </details>`
        )
        .join('');

      return `
      <article class="finding sev-${f.severity}" id="${esc(f.id)}">
        <header>
          <span class="sev">${f.severity.toUpperCase()}</span>
          <h3>${esc(f.title)}</h3>
          <span class="badge">${esc(f.validation.verdict)}</span>
          <span class="badge">${esc(f.verdict)}</span>
          <span class="badge conf-${f.confidence}">confidence: ${f.confidence}</span>
        </header>
        <div class="grid">
          <div>
            <p>${esc(f.summary)}</p>
            <p class="narrative">${esc(f.impact.narrative)}</p>
            <h4>Where</h4>
            <code>${esc(f.handler.location.url)}:${esc(f.handler.location.line ?? '?')}</code>
            ${f.handler.original ? `<div class="muted">source-mapped → ${esc(f.handler.original.url)}:${esc(f.handler.original.line)}</div>` : ''}
            <div class="muted">listener: ${esc(f.handler.registration)} on ${esc(f.handler.target)}, handler <b>${esc(f.handler.name)}</b>, frame ${f.handler.isTop ? 'top' : 'nested'}</div>
            ${includeSnippets ? `<h4>Handler</h4><pre class="code">${srcLines}</pre>` : ''}
          </div>
          <div>
            <h4>Validation</h4>
            <p class="evidence"><code>${esc(f.validation.evidence)}</code></p>
            ${f.validation.weaknesses.map((w) => `<p class="weak">⚠ ${esc(w)}</p>`).join('')}
            ${f.validation.allowedOrigins.length ? `<p>Accepted origins: ${f.validation.allowedOrigins.map((o) => `<code>${esc(o)}</code>`).join(', ')}</p>` : ''}
            <h4>Observed in the browser</h4>
            <ul class="effects">
              ${f.impact.observedEffects.slice(0, 8).map((e) => `<li><b>${esc(e.kind)}</b>${e.attackerControlled ? ' <span class="attacker">attacker-controlled</span>' : ''} ${esc(effectText(e))}</li>`).join('') || '<li class="muted">no effect recorded</li>'}
            </ul>
            ${attempts ? `<h4>Reproducing messages</h4>${attempts}` : ''}
            <h4>Remediation</h4>
            <p>${esc(f.remediation.summary)}</p>
            <pre class="code small">${esc(f.remediation.codeFix)}</pre>
            ${f.proof?.screenshot ? `<img class="shot" src="${esc(f.proof.screenshot)}" alt="screenshot">` : ''}
          </div>
        </div>
      </article>`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>postMessage Audit — ${esc(report.options.url)}</title>
<style>
  :root{--bg:#0f1115;--panel:#171a21;--fg:#e6e8ec;--muted:#8b93a1;--line:#2a2f3a;--crit:#e5484d;--high:#f76808;--med:#e5a800;--low:#3b82f6;--ok:#30a46c;--code:#0b0d11}
  @media (prefers-color-scheme: light){:root{--bg:#f7f8fa;--panel:#fff;--fg:#1a1d23;--muted:#5b6371;--line:#e3e6eb;--code:#f2f4f7}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  main{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
  h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 12px}h3{font-size:15px;margin:0;flex:1}h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px}
  .sub{color:var(--muted);margin:0 0 20px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:20px 0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .card .n{font-size:26px;font-weight:600}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  .finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:10px;padding:16px 18px;margin:14px 0}
  .finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}
  .finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}.finding.sev-info{border-left-color:var(--muted)}
  .finding header{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
  .sev{font-weight:700;font-size:11px;letter-spacing:.06em;padding:2px 8px;border-radius:6px;background:var(--line)}
  .sev-critical .sev{background:var(--crit);color:#fff}.sev-high .sev{background:var(--high);color:#fff}
  .sev-medium .sev{background:var(--med);color:#20160a}.sev-low .sev{background:var(--low);color:#fff}
  .badge{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:1px 9px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
  @media(max-width:860px){.grid{grid-template-columns:1fr}}
  code{background:var(--code);padding:1px 6px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-word}
  pre.code{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12px;line-height:1.5;max-height:340px}
  pre.code.small{max-height:200px}
  pre.code .ln{color:var(--muted);display:inline-block;width:34px;user-select:none;text-align:right;margin-right:10px}
  .muted{color:var(--muted)}
  .weak{color:var(--med);margin:4px 0}
  .attacker{color:var(--crit);font-weight:600}
  .effects li{margin:3px 0}
  .attempt{margin:6px 0;border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--code)}
  .attempt summary{cursor:pointer;font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
  .attempt ul{margin:8px 0 0;padding-left:18px;font-size:12.5px}
  .shot{max-width:100%;border:1px solid var(--line);border-radius:8px;margin-top:10px}
  details.policy{margin:8px 0}
  .foot{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
</style></head>
<body><main>
  <h1>Cross-window Message Audit</h1>
  <p class="sub">${esc(report.options.url)} · ${esc(report.page.title)} · generated ${esc(report.generatedAt)}</p>
  <div class="cards">
    <div class="card"><div class="n">${report.stats.listenersDiscovered}</div><div class="l">listeners</div></div>
    <div class="card"><div class="n">${report.stats.frames}</div><div class="l">frames</div></div>
    <div class="card"><div class="n">${report.stats.confirmed}</div><div class="l">confirmed exploits</div></div>
    <div class="card"><div class="n" style="color:var(--crit)">${c.critical || 0}</div><div class="l">critical</div></div>
    <div class="card"><div class="n" style="color:var(--high)">${c.high || 0}</div><div class="l">high</div></div>
    <div class="card"><div class="n" style="color:var(--med)">${c.medium || 0}</div><div class="l">medium</div></div>
    <div class="card"><div class="n" style="color:var(--low)">${c.low || 0}</div><div class="l">low</div></div>
    <div class="card"><div class="n">${report.stats.durationMs}ms</div><div class="l">scan time</div></div>
  </div>
  <details class="policy"><summary class="muted">Page & security headers</summary>
    <ul class="muted">
      <li>origin: <code>${esc(report.page.origin)}</code></li>
      <li>frames: ${report.page.frames.map((f) => `<code>${esc(f.origin)}</code>${f.isTop ? ' (top)' : ''}`).join(', ')}</li>
      <li>Content-Security-Policy: <code>${esc(report.page.headers.csp || '(none)')}</code></li>
      <li>X-Frame-Options: <code>${esc(report.page.headers.xfo || '(none)')}</code></li>
      <li>Cross-Origin-Opener-Policy: <code>${esc(report.page.headers.coop || '(none)')}</code></li>
    </ul>
  </details>
  <h2>Findings</h2>
  ${findingHtml || '<p class="muted">No message listeners were found.</p>'}
  <div class="foot">
    Attack delivered from <code>${esc(report.options.attackerOrigin)}</code> through real iframe/popup postMessage.
    ${report.options.analyzeOnly ? 'Analysis-only run: exploitation not attempted.' : ''}
    Verify each finding before relying on it; handlers behind a schema the scanner could not reconstruct are labelled with lower confidence.
  </div>
</main></body></html>`;
}

function effectText(e: any): string {
  const d = e.detail || {};
  return String(d.kind || d.token || d.channel || d.to || d.bodyDelta || JSON.stringify(d)).slice(0, 300);
}

function snippetJson(v: any): string {
  try {
    const s = JSON.stringify(v);
    return s.length > 220 ? s.slice(0, 220) + '…' : s;
  } catch {
    return String(v);
  }
}

// --------------------------------------------------------------- markdown

export function renderMarkdown(report: ScanReport): string {
  const l: string[] = [];
  l.push(`# Cross-window message audit — ${report.options.url}`);
  l.push('');
  l.push(`Scanned ${report.stats.listenersDiscovered} listener(s) across ${report.stats.frames} frame(s) in ${report.stats.durationMs} ms.`);
  l.push('');
  const c = report.stats.bySeverity;
  l.push(`| Critical | High | Medium | Low | Info |`);
  l.push(`|---|---|---|---|---|`);
  l.push(`| ${c.critical || 0} | ${c.high || 0} | ${c.medium || 0} | ${c.low || 0} | ${c.info || 0} |`);
  l.push('');
  for (const f of report.findings) {
    l.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
    l.push('');
    l.push(`- **id**: ${f.id}  `);
    l.push(`- **verdict**: ${f.verdict} (guard: ${f.validation.verdict}, confidence ${f.confidence})`);
    const loc = f.handler.original || f.handler.location;
    l.push(`- **where**: \`${loc.url}:${loc.line ?? '?'}\``);
    l.push('');
    l.push(f.summary);
    l.push('');
    l.push(`> ${f.impact.narrative}`);
    l.push('');
    if (f.validation.evidence) l.push('```js\n' + f.validation.evidence + '\n```');
    for (const w of f.validation.weaknesses) l.push(`- ⚠ ${w}`);
    l.push('');
    l.push('**Remediation.** ' + f.remediation.summary);
    l.push('');
    l.push('```js\n' + f.remediation.codeFix + '\n```');
    l.push('');
  }
  return l.join('\n');
}
