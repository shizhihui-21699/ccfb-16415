#!/usr/bin/env node
/**
 * postmsg-audit — CLI.
 */
import { runScan, type ScanOptions } from './scan.js';
import { writeReports } from './report/writers.js';

export async function main(argv: string[]): Promise<number> {
  const program = new Command('postmsg-audit')
    .description(
      'Detect and verify cross-window message (postMessage) vulnerabilities by delivering real cross-origin messages in Chromium.'
    )
    .argument('<url>', 'page URL to audit')
    .option('-o, --out <dir>', 'output directory for reports', 'wma-report')
    .option('--format <list>', 'comma-separated: json,sarif,html,md', 'json,html,sarif,md')
    .option('--attacker-origin <origin>', 'origin used to host the attacker page', 'https://attacker.wma-test.invalid')
    .option('--serve-dir <dir>', 'serve the target origin from this directory')
    .option('--analyze-only', 'skip live exploitation; report analysis only', false)
    .option('--channels <list>', 'delivery channels: iframe,popup', 'iframe,popup')
    .option('--messages <n>', 'message budget per listener', '14')
    .option('--max-targets <n>', 'cap number of listeners verified')
    .option('--min-severity <sev>', 'minimum severity to report', 'low')
    .option('--header <k:v>', 'extra request header (repeatable)', collect, [])
    .option('--cookie <k=v>', 'cookie to set (repeatable)', collect, [])
    .option('--basic-auth <user:pass>', 'HTTP basic credentials')
    .option('--evidence', 'capture screenshots of confirmed findings', false)
    .option('--show <what>', 'open a report: html', undefined)
    .option('--headed', 'run the browser with a visible window', false)
    .option('--debug', 'verbose driver logging', false)
    .option('--json', 'print the report JSON to stdout', false)
    .option('--quiet', 'suppress the console summary', false)
    .option('--fail-on <sev>', 'exit non-zero if a finding at/above this severity exists');

  const parsed = program.parse(argv);
  const opts = parsed.opts;
  const url = parsed.args[0];

  if (!url) {
    process.stderr.write(program.helpText());
    return 2;
  }

  const headers: Record<string, string> = {};
  for (const h of opts.header as string[]) {
    const i = h.indexOf(':');
    if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }
  const cookies = (opts.cookie as string[]).map((c) => {
    const i = c.indexOf('=');
    return { name: c.slice(0, i), value: c.slice(i + 1), url };
  });

  let httpCredentials: { username: string; password: string } | undefined;
  if (opts.basicAuth) {
    const [u, ...rest] = String(opts.basicAuth).split(':');
    httpCredentials = { username: u!, password: rest.join(':') };
  }

  const scanOpts: ScanOptions = {
    url,
    serveDir: opts.serveDir,
    attackerOrigin: opts.attackerOrigin,
    analyzeOnly: !!opts.analyzeOnly,
    channels: String(opts.channels)
      .split(',')
      .map((s) => s.trim())
      .filter((s): s is 'iframe' | 'popup' => s === 'iframe' || s === 'popup'),
    messagesPerTarget: Number(opts.messages),
    maxTargets: opts.maxTargets ? Number(opts.maxTargets) : undefined,
    minSeverity: opts.minSeverity as any,
    headers: Object.keys(headers).length ? headers : undefined,
    cookies: cookies.length ? cookies : undefined,
    httpCredentials,
    headless: !opts.headed,
    debug: !!opts.debug,
    evidenceDir: opts.evidence ? String(opts.out) + '/evidence' : undefined,
    onProgress: opts.quiet || opts.json ? undefined : (msg) => process.stderr.write('  · ' + msg + '\n'),
  };

  let report;
  try {
    report = await runScan(scanOpts);
  } catch (e: any) {
    process.stderr.write('scan failed: ' + (e?.stack || e?.message || e) + '\n');
    return 3;
  }

  const formats = String(opts.format)
    .split(',')
    .map((s) => s.trim())
    .filter((s): s is 'json' | 'sarif' | 'html' | 'md' => ['json', 'sarif', 'html', 'md'].includes(s));

  await writeReports(report, {
    outDir: opts.out,
    formats,
    console: !opts.quiet && !opts.json,
  });

  if (opts.json) process.stdout.write(JSON.stringify(report, null, 2) + '\n');

  if (opts.show === 'html') {
    const p = require('node:path').resolve(opts.out, 'report.html');
    process.stderr.write(`\nOpen ${p}\n`);
  }

  if (opts.failOn) {
    const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const threshold = rank[opts.failOn] || 0;
    const hit = report.findings.some((f) => (rank[f.severity] || 0) >= threshold && f.verdict !== 'not-a-finding');
    return hit ? 1 : 0;
  }
  return 0;
}

function collect(v: string, acc: string[]): string[] {
  acc.push(v);
  return acc;
}

// Tiny argument parser (no external dependency).
class Command {
  private _desc = '';
  private _args: { name: string; desc: string }[] = [];
  private _opts: {
    flags: string[];
    display: string;
    key: string;
    desc: string;
    def?: any;
    takesValue: boolean;
    collect?: boolean;
  }[] = [];
  constructor(public name: string) {}
  description(d: string): this {
    this._desc = d;
    return this;
  }
  argument(name: string, desc: string): this {
    this._args.push({ name, desc });
    return this;
  }
  option(flags: string, desc: string, defOrCollect?: any, maybeCollect?: any): this {
    const m = /--([a-z0-9-]+)/i.exec(flags);
    const key = m ? camel(m[1]!) : flags;
    const takesValue = /<[^>]+>/.test(flags);
    const collector = typeof defOrCollect === 'function' ? defOrCollect : maybeCollect;
    const def = typeof defOrCollect === 'function' ? (collector && takesValue ? [] : undefined) : defOrCollect;
    const flagList = flags
      .replace(/<[^>]+>/g, '')
      .split(/[\s,]+/)
      .filter((f) => f.startsWith('-'));
    this._opts.push({ flags: flagList, display: flags, key, desc, def, takesValue, collect: !!collector });
    return this;
  }
  parse(argv: string[]): { args: string[]; opts: Record<string, any> } {
    const args: string[] = [];
    const opts: Record<string, any> = {};
    for (const o of this._opts) opts[o.key] = o.collect ? [] : o.def;
    const byFlag = new Map<string, (typeof this._opts)[number]>();
    for (const o of this._opts) for (const f of o.flags) byFlag.set(f, o);

    for (let i = 0; i < argv.length; i++) {
      const tok = argv[i]!;
      if (tok.startsWith('--')) {
        const [flag, inline] = tok.split('=');
        const o = byFlag.get(flag!);
        if (!o) continue;
        if (o.takesValue) {
          const val = inline !== undefined ? inline : argv[++i];
          if (o.collect) (opts[o.key] as string[]).push(String(val));
          else opts[o.key] = val;
        } else {
          opts[o.key] = true;
        }
      } else if (tok.startsWith('-') && tok.length === 2) {
        const o = byFlag.get(tok);
        if (!o) continue;
        if (o.takesValue) {
          const val = argv[++i];
          if (o.collect) (opts[o.key] as string[]).push(String(val));
          else opts[o.key] = val;
        } else opts[o.key] = true;
      } else {
        args.push(tok);
      }
    }
    return { args, opts };
  }
  helpText(): string {
    const lines = [`Usage: ${this.name} [options] ${this._args.map((a) => a.name).join(' ')}`, '', this._desc, '', 'Options:'];
    for (const o of this._opts) {
      lines.push(`  ${o.display.padEnd(38)} ${o.desc}${o.def !== undefined && !o.collect ? ' (default: ' + o.def + ')' : ''}`);
    }
    return lines.join('\n') + '\n';
  }
}

function camel(s: string): string {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

// ESM entry
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('cli.ts') || process.argv[1]?.endsWith('cli.js')) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
