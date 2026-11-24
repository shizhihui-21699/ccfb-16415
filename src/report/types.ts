/** Report data model shared by the scanner, the CLI writers and the HTML report. */
import type { ListenerProbeResult, MessageAttempt, EffectRecord } from '../probe/types.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingVerdict =
  | 'exploited'
  | 'vulnerable-unconfirmed'
  | 'weak-validation'
  | 'information'
  | 'not-a-finding';

export interface Finding {
  id: string;
  targetId: string;
  title: string;
  severity: Severity;
  verdict: FindingVerdict;
  outcome: ListenerProbeResult['outcome'];
  /** One paragraph a developer can act on. */
  summary: string;
  /** Which message channel and origin produced it. */
  delivery: {
    channel: 'iframe' | 'popup' | 'none';
    attackerOrigin: string;
    messagesSent: number;
    invoked: boolean;
  };
  handler: {
    name: string;
    registration: string;
    target: string;
    frameUrl: string;
    isTop: boolean;
    /** Best available source location. */
    location: { url: string; line: number | null; column: number | null };
    original?: { url: string; line: number; column: number; name?: string };
    sourceSnippet: string;
    sourceLines?: { line: number; text: string }[];
  };
  validation: {
    verdict: string;
    evidence: string;
    allowedOrigins: string[];
    weaknesses: string[];
    readsOrigin: boolean;
    readsSource: boolean;
    readsData: boolean;
  };
  impact: {
    sinks: string[];
    /** Effects actually observed in the browser. */
    observedEffects: EffectRecord[];
    canaryExecuted: boolean;
    attackerControlled: boolean;
    /** Plain-language exploitation description. */
    narrative: string;
  };
  proof?: {
    /** Messages that triggered it, in order of usefulness. */
    attempts: { message: any; delivered: boolean; effects: summarizedEffect[]; invoked: number; senderOrigin?: string }[];
    snippets: string[];
    screenshot?: string;
    consoleLines?: string[];
    network?: { url: string; method: string; body?: string }[];
  };
  remediation: {
    summary: string;
    codeFix: string;
    references: string[];
  };
  notes: string[];
  confidence: 'high' | 'medium' | 'low';
}

export interface summarizedEffect {
  kind: string;
  attackerControlled: boolean;
  detail: string;
}

export interface ScanStats {
  url: string;
  finalUrl: string;
  attackerOrigin: string;
  startedAt: number;
  durationMs: number;
  frames: number;
  listenersDiscovered: number;
  candidates: number;
  verified: number;
  confirmed: number;
  bySeverity: Record<string, number>;
  navigation: { navMs: number; settleMs: number; scanMs: number };
  sessions: { navMs: number; settleMs: number; scanMs: number };
}

export interface ScanReport {
  tool: string;
  version: string;
  generatedAt: string;
  options: { url: string; attackerOrigin: string; analyzeOnly: boolean; channels: string[] };
  stats: ScanStats;
  page: {
    origin: string;
    title: string;
    frames: { frameId: number; url: string; origin: string; isTop: boolean; name: string }[];
    headers: { csp?: string; xfo?: string; coop?: string; coep?: string };
  };
  findings: Finding[];
  diagnostics: {
    instrumentErrors: { frameUrl: string; errors: any[]; hooks?: string[] }[];
    staticParseErrors: { unit: string; errors: { message: string; line?: number }[] }[];
    embeddedOrigins: string[];
  };
}
