/**
 * Scan orchestration: acquire the page, assemble candidates, verify them, and
 * produce findings with severity and remediation.
 */
import { acquirePageModel, type PageModel, type PageModelOptions } from './browser/page-model.js';
import { SourceMapRegistry } from './analysis/source-maps.js';
import { assembleCandidates } from './probe/candidates.js';
import { ExploitVerifier, type VerifyOptions } from './probe/verify.js';
import { recordToFinding } from './report/severity.js';
import type { Finding, ScanReport, ScanStats } from './report/types.js';
import type { CandidateTarget, ListenerProbeResult } from './probe/types.js';

export interface ScanOptions extends PageModelOptions {
  /** Attacker origin to use. Defaults to a reserved test origin. */
  attackerOrigin?: string;
  /** Only report findings at or above this severity. */
  minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Skip live exploitation and report analysis only. */
  analyzeOnly?: boolean;
  /** Channels to attempt. */
  channels?: ('iframe' | 'popup')[];
  /** Per-listener message budget. */
  messagesPerTarget?: number;
  /** Where to write screenshots, if enabled. */
  evidenceDir?: string;
  /** Emit progress lines. */
  onProgress?: (msg: string, data?: any) => void;
  /** Cap the number of listeners verified (highest-risk first). */
  maxTargets?: number;
}

const DEFAULT_ATTACKER = 'https://attacker.wma-test.invalid';

export async function runScan(opts: ScanOptions): Promise<ScanReport> {
  const startedAt = Date.now();
  const progress = opts.onProgress || (() => {});
  const attackerOrigin = opts.attackerOrigin || DEFAULT_ATTACKER;

  progress('acquiring page model', { url: opts.url });
  const acquisition = await acquirePageModel(opts);
  const model = acquisition.model;
  await acquisition.close();

  progress('resolving source maps', {});
  const maps = new SourceMapRegistry();
  await maps.load(model.scripts).catch(() => {});

  progress('assembling candidate listeners', { listeners: model.listeners.length });
  const candidates = assembleCandidates(model, { maps, debug: opts.debug ? console.error : undefined });

  const ranked = rankCandidates(candidates);
  const toVerify = opts.maxTargets ? ranked.slice(0, opts.maxTargets) : ranked;

  const findings: Finding[] = [];
  const probeResults: ListenerProbeResult[] = [];

  if (!opts.analyzeOnly && toVerify.length) {
    const channels: ('iframe' | 'popup')[] = opts.channels || ['iframe', 'popup'];
    const verifier = new ExploitVerifier({
      targetUrl: model.finalUrl || opts.url,
      attackerOrigin,
      serveDir: opts.serveDir,
      headless: opts.headless ?? true,
      timeoutMs: opts.timeoutMs,
      debug: opts.debug,
      ignoreHTTPSErrors: opts.ignoreHTTPSErrors,
      headers: opts.headers,
      httpCredentials: opts.httpCredentials,
      cookies: opts.cookies,
      evidenceDir: opts.evidenceDir,
      settleMs: 140,
      messagesPerTarget: opts.messagesPerTarget ?? 14,
      tryTrustedOrigins: true,
      onProgress: progress,
    });
    try {
      // One finding per target: try channels in order and keep the strongest
      // outcome, so an iframe attempt and a popup attempt do not duplicate.
      for (const target of toVerify) {
        progress(`probing ${target.id} ${target.handlerName} (${target.semantics.guardVerdict})`, { target: target.id });
        let best: ListenerProbeResult | null = null;
        for (const channel of channels) {
          progress(`  via ${channel}`, { target: target.id, channel });
          let result: ListenerProbeResult;
          try {
            result = await verifier.probeTarget(target, channel);
          } catch (e: any) {
            progress('probe failed', { target: target.id, error: String(e?.message || e) });
            result = {
              target,
              analysis: {
                targetId: target.id,
                verdict: target.semantics.guardVerdict,
                allowedOrigins: target.semantics.allowedOrigins,
                weaknesses: target.semantics.weaknesses,
                evidence: target.semantics.evidence,
                runtimeNotes: ['probe error: ' + String(e?.message || e)],
              },
              attempts: [],
              outcome: 'inconclusive',
              evidence: { effects: [], snippets: [] },
              notes: ['probe error: ' + String(e?.message || e)],
            };
          }
          result.attempts = result.attempts.map((a) => ({ ...a, channel: a.channel || channel }));
          best = pickStronger(best, result);
          if (best.outcome === 'exploited') break;
        }
        if (best) {
          probeResults.push(best);
          findings.push(recordToFinding(best, model));
        }
      }
    } finally {
      await verifier.close().catch(() => {});
    }
  } else {
    // Analysis-only: build findings without live verification.
    for (const target of toVerify) {
      const pseudo: ListenerProbeResult = {
        target,
        analysis: {
          targetId: target.id,
          verdict: target.semantics.guardVerdict,
          allowedOrigins: target.semantics.allowedOrigins,
          weaknesses: target.semantics.weaknesses,
          evidence: target.semantics.evidence,
          runtimeNotes: [],
        },
        attempts: [],
        outcome: target.semantics.guardVerdict === 'strong' || target.semantics.guardVerdict === 'same-origin' ? 'blocked' : 'inconclusive',
        evidence: { effects: [], snippets: [] },
        notes: ['analysis only; exploitation not attempted'],
      };
      probeResults.push(pseudo);
      findings.push(recordToFinding(pseudo, model));
    }
  }

  const filtered = findings
    .filter((f) => severityRank(f.severity) >= severityRank(opts.minSeverity || 'info'))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.targetId.localeCompare(b.targetId));

  const stats: ScanStats = {
    url: opts.url,
    finalUrl: model.finalUrl,
    attackerOrigin,
    startedAt,
    durationMs: Date.now() - startedAt,
    frames: model.frames.length,
    listenersDiscovered: model.listeners.length,
    candidates: candidates.length,
    verified: probeResults.length,
    confirmed: filtered.filter((f) => f.verdict === 'exploited').length,
    bySeverity: countBySeverity(filtered),
    navigation: model.timing,
    sessions: acquisition.model.timing,
  };

  return {
    tool: 'postmsg-audit',
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    options: {
      url: opts.url,
      attackerOrigin,
      analyzeOnly: !!opts.analyzeOnly,
      channels: opts.channels || ['iframe', 'popup'],
    },
    stats,
    page: {
      origin: model.origin,
      title: model.title,
      frames: model.frames,
      headers: {
        csp: model.headers['content-security-policy'],
        xfo: model.headers['x-frame-options'],
        coop: model.headers['cross-origin-opener-policy'],
        coep: model.headers['cross-origin-embedder-policy'],
      },
    },
    findings: filtered,
    diagnostics: {
      instrumentErrors: model.instrumentErrors,
      staticParseErrors: model.staticScan
        .filter((s) => s.parseErrors.length)
        .map((s) => ({ unit: s.unitUrl, errors: s.parseErrors })),
      embeddedOrigins: model.embeddedOrigins,
    },
  };
}

const OUTCOME_RANK: Record<string, number> = {
  exploited: 5,
  acted: 4,
  'invoked-only': 3,
  inconclusive: 2,
  'not-invoked': 1,
  blocked: 0,
};

function pickStronger(a: ListenerProbeResult | null, b: ListenerProbeResult): ListenerProbeResult {
  if (!a) return b;
  if ((OUTCOME_RANK[b.outcome] ?? 0) > (OUTCOME_RANK[a.outcome] ?? 0)) {
    // Keep the earlier attempts for context while taking the better verdict.
    return { ...b, attempts: [...a.attempts, ...b.attempts], notes: [...a.notes, ...b.notes] };
  }
  return { ...a, notes: [...a.notes, ...b.notes.filter((n) => !a.notes.includes(n))] };
}

export function rankCandidates(candidates: CandidateTarget[]): CandidateTarget[] {
  const score = (c: CandidateTarget): number => {
    let s = 0;
    const v = c.semantics.guardVerdict;
    if (v === 'none') s += 100;
    else if (v === 'data-based' || v === 'source-based') s += 80;
    else if (v === 'weak') s += 70;
    else if (v === 'deny-list') s += 60;
    else if (v === 'post-check') s += 55;
    else if (v === 'unknown') s += 40;
    else if (v === 'same-origin') s += 5;
    else if (v === 'strong') s += 2;
    if (c.semantics.hasStaticSink) s += 30;
    if (c.semantics.sinks.some((k) => k === 'eval' || k === 'html:innerHTML' || k === 'html:insertAdjacentHTML')) s += 20;
    if (c.isTop) s += 5;
    return s;
  };
  return [...candidates].sort((a, b) => score(b) - score(a));
}

export function severityRank(s: string): number {
  return ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<string, number>)[s] || 0;
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] || 0) + 1;
  return out;
}
