/** Shared types for candidate targets, probe plans and findings. */
import type { OriginPredicate } from '../analysis/origin-check.js';
import type { MessageSchema } from '../analysis/message-schema.js';

export interface CandidateTarget {
  /** Stable id for cross-referencing. */
  id: string;
  frameId: number;
  lid: string;
  frameUrl: string;
  frameOrigin: string;
  isTop: boolean;
  /** Runtime registration kind. */
  registration: string;
  target: string;
  /** Best-effort function name from the stack. */
  handlerName: string;
  /** Where the listener was registered (stack frame). */
  location: { url: string; line: number | null; column: number | null };
  /** Handler source as captured at runtime. */
  source: string;
  /** Matched static listener, if any. */
  staticId?: string;
  /** Deobfuscated/mapped position, when a source map was available. */
  original?: { url: string; line: number; column: number; name?: string };
  schema: MessageSchema;
  semantics: ListenerSemantics;
  /** The exact predicate object, for bypass synthesis. */
  predicate?: OriginPredicate | null;
  /** Origin-comparison operands observed at runtime. */
  runtimeOriginCompares?: { method: string; operand: string }[];
}

export interface ListenerSemantics {
  guardVerdict: string;
  allowedOrigins: string[];
  weaknesses: string[];
  evidence: string;
  readsOrigin: boolean;
  readsSource: boolean;
  readsData: boolean;
  sinks: string[];
  postCheck: boolean;
  wildcardOutbound: boolean;
  dataFields: string[];
  /** Distinguishes a listener that is a pure relay from one that acts. */
  hasStaticSink: boolean;
}

export interface ListenerAnalysis {
  targetId: string;
  verdict: string;
  allowedOrigins: string[];
  weaknesses: string[];
  evidence: string;
  /** Extra notes from runtime observation. */
  runtimeNotes: string[];
  predicate?: OriginPredicate | null;
}

export interface ProbeMessage {
  value: any;
  label: string;
  origin: 'attacker' | 'harness-trusted' | 'marker';
  /** For trusted-origin probes, the origin string to spoof. */
  fakeOrigin?: string;
}

export interface ListenerProbeResult {
  target: CandidateTarget;
  analysis: ListenerAnalysis;
  attempts: MessageAttempt[];
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

export interface EffectRecord {
  kind: 'sink' | 'canary' | 'dom' | 'navigation' | 'popup' | 'outbound' | 'error' | 'reply';
  detail: any;
  lid?: string | null;
  inv?: string | null;
  attackerControlled?: boolean;
}

export interface MessageAttempt {
  message: any;
  targetOrigin: string;
  channel: 'iframe' | 'popup';
  schemaSource: string;
  delivered: boolean;
  deliveryError?: string;
  invoked: {
    lid: string;
    id: number;
    originRead: boolean;
    sourceRead: boolean;
    dataRead: boolean;
    dataPaths: string[];
    threw: string | null;
    durationMs: number;
    activeGuard?: string | null;
  }[];
  effects: EffectRecord[];
  acted: boolean;
  /** Origin the harness delivered from. */
  senderOrigin?: string;
  error?: string;
}
