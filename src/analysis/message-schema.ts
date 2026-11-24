/**
 * Message-schema inference.
 *
 * Handlers usually need a specific shape before they act: `if (msg.type ===
 * 'pay') { if (msg.payload.amount > 0) { … } }`. A probe that sends a single
 * fixed object will bounce off every handler that checks a discriminator, which
 * is why naive scanners under-report. This module reconstructs, per handler,
 * the set of conditions the data must satisfy — from the static AST, from the
 * runtime property reads recorded by the instrumentation, and from the values
 * the page itself sends outbound (which reveal the real protocol).
 */
import { parse } from 'acorn';
import * as walk from 'acorn-walk';
import type { CapturedListener } from '../browser/page-model.js';

export type FieldConstraint =
  | { kind: 'equals'; value: string | number | boolean | null }
  | { kind: 'one-of'; values: (string | number | boolean)[] }
  | { kind: 'regex'; pattern: string; flags: string; examples: string[] }
  | { kind: 'present' }
  | { kind: 'truthy' }
  | { kind: 'numeric'; op: '>' | '>=' | '<' | '<='; value: number }
  | { kind: 'not-equals'; value: string | number | boolean | null }
  | { kind: 'prefix'; value: string };

export interface FieldSpec {
  path: string; // dotted path relative to event.data, e.g. "payload.amount"
  constraints: FieldConstraint[];
  /** Where this knowledge came from. */
  sources: ('static' | 'runtime' | 'observed')[];
  /** Confidence that including this field is necessary (0..1). */
  confidence: number;
}

export interface MessageSchema {
  /** Base object templates; each is a complete candidate message. */
  templates: Record<string, any>[];
  /** All fields seen, with their constraints. */
  fields: FieldSpec[];
  /** Discriminator values that unlock deeper branches. */
  discriminators: { path: string; values: any[] }[];
  /** Values the page itself sends to peers (protocol samples). */
  protocolSamples: any[];
  /** Free-form notes for the report. */
  notes: string[];
  /** Whether the handler appears to require any structured data at all. */
  structured: boolean;
  /** Flattened leaf field names, for payload injection heuristics. */
  dataFields?: string[];
}

const MARKER_FIELD_HINTS = ['type', 'action', 'event', 'cmd', 'command', 'method', 'kind', 'op', 'name', 'topic', 'channel', 'msg', 'messageType', 'eventName', 'event_name', 'requestType', 'id'];

function isDiscriminatorName(name: string): boolean {
  return MARKER_FIELD_HINTS.some((h) => h.toLowerCase() === name.toLowerCase());
}

function propPath(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  return null;
}

/**
 * Dotted path of a member expression relative to a data root. Roots are dotted
 * prefixes such as `e.data` (or a bare param when the handler is `m => m.type`),
 * so the result never includes the root itself.
 */
function dataPath(node: any, dataRoots: Set<string>): string | null {
  const parts: string[] = [];
  let cur = node;
  while (cur && cur.type === 'MemberExpression') {
    const p = propPath(cur.property);
    if (p == null) return null;
    parts.unshift(p);
    cur = cur.object;
  }
  if (!cur || cur.type !== 'Identifier') return null;
  const full = [cur.name, ...parts].join('.');
  // longest matching root wins
  let best: string | null = null;
  for (const r of dataRoots) {
    if (full === r) return '';
    if (full.startsWith(r + '.') && (!best || r.length > best.length)) best = r;
  }
  if (!best) return null;
  return full.slice(best.length + 1);
}

function literalOf(node: any): { known: boolean; value?: any; regex?: { pattern: string; flags: string } } {
  if (!node) return { known: false };
  if (node.type === 'Literal') {
    if (node.regex) return { known: true, regex: node.regex };
    return { known: true, value: node.value };
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return { known: true, value: node.quasis.map((q: any) => q.value.cooked).join('') };
  }
  if (node.type === 'UnaryExpression' && node.operator === '-' && node.argument?.type === 'Literal') {
    return { known: true, value: -node.argument.value };
  }
  return { known: false };
}

function looksLikeOrigin(v: any): boolean {
  return typeof v === 'string' && /^https?:\/\/[^/?#]+$/i.test(v);
}

/**
 * Build a schema for a listener from its handler source.
 */
/** Strip wrappers that do not change which object an expression refers to. */
function unwrapDataExpr(node: any, depth = 0): any {
  if (!node || depth > 4) return node;
  if (node.type === 'LogicalExpression') {
    // `e.data || {}` / `e.data && e.data.x` — the left operand is the data ref
    return unwrapDataExpr(node.left, depth + 1) || unwrapDataExpr(node.right, depth + 1);
  }
  if (node.type === 'ConditionalExpression') return node.consequent;
  if (node.type === 'ChainExpression') return unwrapDataExpr(node.expression, depth + 1);
  return node;
}

export function inferStaticSchema(source: string, paramNames: string[] = []): MessageSchema {
  const schema: MessageSchema = {
    templates: [],
    fields: [],
    discriminators: [],
    protocolSamples: [],
    notes: [],
    structured: false,
  };
  if (!source) return schema;

  let fn: any;
  try {
    fn = parseHandlerFn(source);
  } catch (e: any) {
    schema.notes.push('handler unparsable for schema inference: ' + String(e.message || e));
    return schema;
  }
  const body = fn.type === 'Program' ? fn : fn.body;

  const params = (fn.params || []).map((p: any) => p?.left?.name || p?.name).filter(Boolean);

  // Determine the data root(s). If the handler reads `<param>.data`, that member
  // expression is the root; otherwise the parameter itself carries the message
  // (e.g. `m => m.type`).
  const dataRoots = new Set<string>();
  const usesDotData = new Set<string>();
  walk.simple(body, {
    MemberExpression(n: any) {
      if (propPath(n.property) === 'data' && n.object?.type === 'Identifier') usesDotData.add(n.object.name);
    },
  });
  for (const p of params) {
    if (usesDotData.has(p)) dataRoots.add(p + '.data');
    else dataRoots.add(p);
  }
  // Local aliases: const d = e.data; const m = e.data.msg;
  walk.simple(body, {
    VariableDeclarator(n: any) {
      if (n.id?.type !== 'Identifier' || !n.init) return;
      const init = unwrapDataExpr(n.init);
      const p = dataPath(init, dataRoots);
      if (p) dataRoots.add(n.id.name);
      // const d = e.data / e.data || {}
      if (init?.type === 'MemberExpression' && propPath(init.property) === 'data' && init.object?.type === 'Identifier') {
        dataRoots.add(n.id.name);
      }
      // const m = d.msg  (alias of an alias)
      if (init?.type === 'MemberExpression') {
        const base = init.object?.type === 'Identifier' ? init.object.name : null;
        if (base && dataRoots.has(base) && init.object?.type === 'Identifier') dataRoots.add(base);
      }
    },
  });
  if (!dataRoots.size) return schema;

  // Literal tables: `const OK = ['a','b']` so allow-lists resolve by name.
  const varLiterals = new Map<string, any[]>();
  walk.simple(body, {
    VariableDeclarator(n: any) {
      if (n.id?.type !== 'Identifier' || !n.init) return;
      const arr = literalArray(n.init);
      if (arr) varLiterals.set(n.id.name, arr);
      const lv = literalOf(n.init);
      if (lv.known && typeof lv.value === 'string') varLiterals.set(n.id.name, [lv.value]);
    },
  });

  const fieldMap = new Map<string, FieldSpec>();

  function ensure(path: string, source: 'static' | 'runtime' | 'observed', conf: number): FieldSpec {
    let f = fieldMap.get(path);
    if (!f) {
      f = { path, constraints: [], sources: [], confidence: conf };
      fieldMap.set(path, f);
    }
    if (!f.sources.includes(source)) f.sources.push(source);
    f.confidence = Math.max(f.confidence, conf);
    return f;
  }

  function ensureTruthy(path: string) {
    const f = ensure(path, 'static', 0.8);
    if (!f.constraints.some((c) => c.kind === 'truthy')) f.constraints.push({ kind: 'truthy' });
    schema.structured = true;
  }

  function addConstraint(path: string, c: FieldConstraint, conf = 0.8) {
    const f = ensure(path, 'static', conf);
    // dedupe semantically identical constraints
    const key = JSON.stringify(c);
    if (!f.constraints.some((x) => JSON.stringify(x) === key)) f.constraints.push(c);
    schema.structured = true;
  }

  /**
   * `pol` is true when the condition must be TRUE for the handler to continue
   * (the normal case) and false when the statement is a reject-guard, where the
   * branch that returns is the one that failed the check. Constraints are
   * recorded against the positive form either way.
   */
  function visitCondition(test: any, pol: boolean = true) {
    if (!test) return;
    switch (test.type) {
      case 'LogicalExpression': {
        if (test.operator === '&&' && pol) {
          visitCondition(test.left, pol);
          visitCondition(test.right, pol);
        } else if (test.operator === '||' && !pol) {
          // Reject guard `if (a || b) return;`: continuing requires !a && !b.
          visitCondition(test.left, false);
          visitCondition(test.right, false);
        } else if (test.operator === '||' && pol) {
          // `a || b` is satisfied by either; constraints are not conjunctive.
          visitCondition(test.left, pol);
          visitCondition(test.right, pol);
        }
        return;
      }
      case 'UnaryExpression':
        if (test.operator === '!') visitCondition(test.argument, !pol);
        return;
      case 'Identifier': {
        // A bare data alias used as a condition (`if (!d) return`) is presence.
        const p = dataPath(test, dataRoots);
        if (p) ensureTruthy(p);
        return;
      }
      case 'MemberExpression': {
        // `if (d.verified)` / `if (!d.verified)` — the field must be truthy.
        const p = dataPath(test, dataRoots);
        if (p) ensureTruthy(p);
        return;
      }
      case 'BinaryExpression': {
        const op = test.operator;
        const leftPath = dataPath(test.left, dataRoots);
        const rightPath = dataPath(test.right, dataRoots);
        const effOp = pol ? op : invertOp(op);
        if (leftPath && !rightPath) {
          const lit = literalOf(test.right);
          applyBinary(leftPath, effOp, lit, test.right);
        } else if (rightPath && !leftPath) {
          const lit = literalOf(test.left);
          applyBinary(rightPath, flipOp(effOp), lit, test.left);
        }
        return;
      }
      case 'CallExpression': {
        // msg.type.indexOf('x') !== -1  /  msg.cmd.startsWith('a')  /
        // RE.test(msg.type)  /  ALLOWED.includes(msg.type)
        const callee = test.callee;
        if (callee?.type !== 'MemberExpression') return;
        const method = propPath(callee.property);
        const args: any[] = test.arguments || [];
        if (!method) return;

        // (a) the receiver is a message field: field.startsWith(...) etc.
        const recvPath = dataPath(callee.object, dataRoots);
        if (recvPath && method) {
          const argLits = args.map(literalOf).filter((x) => x.known);
          if (method === 'startsWith' && argLits[0]?.value != null) {
            addConstraint(recvPath, { kind: 'prefix', value: String(argLits[0].value) });
          } else if (method === 'includes' && argLits[0]?.value != null) {
            addConstraint(recvPath, { kind: 'regex', pattern: escapeRe(String(argLits[0].value)), flags: '', examples: [String(argLits[0].value)] }, 0.5);
          }
        }

        // (b) an argument is a message field: RE.test(field) / ALLOWED.includes(field)
        const argPath = args.map((a) => dataPath(a, dataRoots)).find(Boolean) || null;
        if (argPath) {
          if (method === 'test' || method === 'exec') {
            const r = literalOf(callee.object);
            if (r.regex) {
              addConstraint(argPath, { kind: 'regex', pattern: r.regex.pattern, flags: r.regex.flags, examples: examplesFromRegex(r.regex.pattern) });
            }
          }
          if (method === 'includes' || method === 'indexOf') {
            const arr = resolveLiteralArray(callee.object);
            if (arr) addConstraint(argPath, { kind: 'one-of', values: arr });
          }
        }
        return;
      }
      default:
        return;
    }
  }

  function applyBinary(path: string, op: string, lit: { known: boolean; value?: any }, other: any) {
    if (!path) return;
    if (lit.known) {
      const v = lit.value;
      switch (op) {
        case '===':
        case '==':
          addConstraint(path, { kind: 'equals', value: v });
          if (isDiscriminatorName(path.split('.').pop() || '')) addDiscriminator(path, v);
          return;
        case '!==':
        case '!=':
          addConstraint(path, { kind: 'not-equals', value: v });
          return;
        case '>':
        case '>=':
        case '<':
        case '<=':
          if (typeof v === 'number') addConstraint(path, { kind: 'numeric', op: op as any, value: v });
          return;
        default:
          return;
      }
    }
    // comparisons against a variable: record presence only
    if (['===', '==', '!==', '!='].includes(op)) {
      // might be `msg.type === TYPE_CONST`; the runtime reads fill in the value
      ensure(path, 'static', 0.5).constraints.push({ kind: 'present' });
    }
  }

  function flipOp(op: string): string {
    const map: Record<string, string> = { '>': '<', '>=': '<=', '<': '>', '<=': '>=', '===': '===', '!==': '!==', '==': '==', '!=': '!=' };
    return map[op] || op;
  }

  /** Swap the sense of a comparison (for reject-guard polarity). */
  function invertOp(op: string): string {
    const map: Record<string, string> = {
      '===': '!==',
      '!==': '===',
      '==': '!=',
      '!=': '==',
      '>': '<=',
      '>=': '<',
      '<': '>=',
      '<=': '>',
    };
    return map[op] || op;
  }

  function resolveLiteralArray(node: any): any[] | null {
    const direct = literalArray(node);
    if (direct) return direct;
    const name = node?.type === 'Identifier' ? node.name : null;
    if (name && varLiterals.has(name)) return varLiterals.get(name)!;
    return null;
  }

  function addDiscriminator(path: string, value: any) {
    let d = schema.discriminators.find((x) => x.path === path);
    if (!d) {
      d = { path, values: [] };
      schema.discriminators.push(d);
    }
    if (!d.values.some((v) => v === value)) d.values.push(value);
  }

  const rejects = (stmt: any): boolean => {
    if (!stmt) return false;
    if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement' || stmt.type === 'ContinueStatement' || stmt.type === 'BreakStatement') return true;
    if (stmt.type === 'BlockStatement') return stmt.body.some(rejects);
    if (stmt.type === 'IfStatement') return rejects(stmt.consequent) || rejects(stmt.alternate);
    return false;
  };

  walk.simple(body, {
    IfStatement(n: any) {
      // `if (bad) return;` means the *negation* holds for the code that follows.
      const thenRejects = rejects(n.consequent);
      const elseRejects = rejects(n.alternate);
      const pol = thenRejects && !elseRejects ? false : true;
      visitCondition(n.test, pol);
    },
    ConditionalExpression(n: any) {
      visitCondition(n.test, true);
    },
    SwitchStatement(n: any) {
      // switch (msg.type) { case 'a': … }
      const disc = dataPath(n.discriminant, dataRoots);
      if (!disc) return;
      const values: any[] = [];
      for (const c of n.cases) {
        if (!c.test) continue;
        const lit = literalOf(c.test);
        if (lit.known) values.push(lit.value);
      }
      if (values.length) {
        addConstraint(disc, { kind: 'one-of', values });
        for (const v of values) addDiscriminator(disc, v);
      }
    },
    AssignmentExpression(n: any) {
      // msg.type = 'x' assignments after validation are not needed.
    },
  });

  // Nested body access implies the parent must be an object. Leaf reads are
  // low confidence on their own, but a leaf that is consumed (concatenated,
  // passed to a call, or assigned into the DOM) is concretely used by the
  // handler, so it gets a usable default in the base template.
  walk.simple(body, {
    MemberExpression(n: any) {
      const p = dataPath(n, dataRoots);
      if (!p) return;
      const segs = p.split('.');
      for (let i = 1; i < segs.length; i++) {
        ensure(segs.slice(0, i).join('.'), 'static', 0.55);
      }
      ensure(p, 'static', 0.3);
    },
    BinaryExpression(n: any) {
      // 'Amount: ' + msg.amount  (the operand may be wrapped: (msg.x || ''))
      if (n.operator !== '+') return;
      for (const side of [n.left, n.right]) {
        const p = dataPath(side, dataRoots);
        if (p) {
          ensure(p, 'static', 0.75);
          continue;
        }
        walk.simple(side, {
          MemberExpression(m: any) {
            const inner = dataPath(m, dataRoots);
            if (inner) ensure(inner, 'static', 0.75);
          },
        });
      }
    },
    AssignmentExpression(n: any) {
      const p = dataPath(n.right, dataRoots);
      if (p && n.left?.type === 'MemberExpression') ensure(p, 'static', 0.7);
    },
    CallExpression(n: any) {
      for (const a of n.arguments || []) {
        const p = dataPath(a, dataRoots);
        if (p) ensure(p, 'static', 0.65);
      }
    },
  });

  schema.fields = Array.from(fieldMap.values()).filter((f) => !isOriginLikeField(f.path));
  return schema;
}

function literalArray(node: any): any[] | null {
  if (!node) return null;
  if (node.type === 'ArrayExpression') {
    const out: any[] = [];
    for (const el of node.elements) {
      const l = literalOf(el);
      if (!l.known) return null;
      out.push(l.value);
    }
    return out;
  }
  if (node.type === 'NewExpression' && propPath(node.callee) === 'Set' && node.arguments?.[0]) return literalArray(node.arguments[0]);
  return null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Produce plausible strings matching common validator regexes. */
function examplesFromRegex(pattern: string): string[] {
  const out: string[] = [];
  const simple = /^\^([A-Za-z0-9_-]+)\$?$/.exec(pattern);
  if (simple) out.push(simple[1]!);
  const alt = /\((?:([A-Za-z0-9_-]+)\|)+([A-Za-z0-9_-]+)\)/.exec(pattern);
  if (alt) {
    const parts = pattern.match(/\(([^()]+)\)/);
    if (parts) out.push(...parts[1]!.split('|').slice(0, 6));
  }
  return out;
}

function parseHandlerFn(source: string): any {
  const attempts = [source, '(' + source + ')'];
  for (const code of attempts) {
    try {
      const program = parse(code, { ecmaVersion: 'latest', allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true });
      const isFn = (n: any) => n && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression');
      for (const stmt of program.body) {
        if (isFn(stmt)) return stmt;
        if (stmt.type === 'ExpressionStatement' && isFn(stmt.expression)) return stmt.expression;
      }
    } catch {
      /* try next */
    }
  }
  throw new Error('unparsable handler');
}

/**
 * Merge static constraints with runtime observations (property paths read at
 * runtime, and the actual values the handler compared against).
 */
export function mergeRuntimeSchema(
  schema: MessageSchema,
  runtimePaths: Record<string, { n: number; sample?: any }>,
  compareSamples: { path: string; method: string; args: any[] }[]
): MessageSchema {
  const fieldMap = new Map<string, FieldSpec>();
  for (const f of schema.fields) fieldMap.set(f.path, f);
  function ensure(path: string): FieldSpec {
    let f = fieldMap.get(path);
    if (!f) {
      f = { path, constraints: [], sources: [], confidence: 0.4 };
      fieldMap.set(path, f);
    }
    if (!f.sources.includes('runtime')) f.sources.push('runtime');
    return f;
  }
  for (const [rawPath, info] of Object.entries(runtimePaths || {})) {
    const path = rawPath.replace(/^\./, '');
    if (!path || path === '*' || path.endsWith('.*') || path === '[[keys]]') {
      if (path === '*' || path === '[[keys]]') {
        // whole-object iteration means a free-form object is accepted
        schema.notes.push('handler enumerates all keys of the message data');
      }
      continue;
    }
    const f = ensure(path);
    f.confidence = Math.max(f.confidence, 0.6);
    if (info.sample && info.sample.t === 'string') f.confidence = Math.max(f.confidence, 0.7);
  }
  for (const c of compareSamples || []) {
    const path = (c.path || '').replace(/^\./, '');
    if (!path) continue;
    const arg = c.args?.[0];
    if (!arg) continue;
    if (arg.t === 'string') {
      const f = ensure(path);
      if (c.method === 'startsWith') f.constraints.push({ kind: 'prefix', value: arg.v });
      else if (c.method === 'includes' || c.method === 'indexOf') f.constraints.push({ kind: 'regex', pattern: escapeRe(String(arg.v)), flags: '', examples: [String(arg.v)] });
      else if (c.method === 'endsWith') f.constraints.push({ kind: 'regex', pattern: escapeRe(String(arg.v)) + '$', flags: '', examples: [String(arg.v)] });
    }
  }
  schema.fields = Array.from(fieldMap.values()).filter((f) => !isOriginLikeField(f.path));
  return schema;
}

function isOriginLikeField(path: string): boolean {
  // A bare top-level `origin` field on message data is attacker-controlled and
  // irrelevant to the schema (it is never a real authenticity signal).
  return path === 'origin';
}

/** Fill a schema into concrete candidate messages. */
export function materializeTemplates(schema: MessageSchema, extraSamples: any[] = [], max = 24): Record<string, any>[] {
  const templates: Record<string, any>[] = [];

  function setPath(obj: Record<string, any>, path: string, value: any) {
    const segs = path.split('.');
    let cur = obj;
    for (let i = 0; i < segs.length - 1; i++) {
      const s = segs[i]!;
      if (typeof cur[s] !== 'object' || cur[s] === null) cur[s] = {};
      cur = cur[s];
    }
    cur[segs[segs.length - 1]!] = value;
  }

  function valueFor(f: FieldSpec): any {
    const truthy = f.constraints.find((x) => x.kind === 'truthy');
    if (truthy) return true;
    const c = f.constraints.find((x) => x.kind === 'equals' || x.kind === 'one-of');
    if (c) {
      if (c.kind === 'equals') return c.value;
      return c.values[0];
    }
    const prefix = f.constraints.find((x) => x.kind === 'prefix');
    if (prefix) return (prefix as any).value + '1';
    const re = f.constraints.find((x) => x.kind === 'regex');
    if (re && (re as any).examples?.length) return (re as any).examples[0];
    const num = f.constraints.find((x) => x.kind === 'numeric');
    if (num) {
      const v = (num as any).value;
      return (num as any).op === '>' ? v + 1 : (num as any).op === '>=' ? v : (num as any).op === '<' ? v - 1 : v;
    }
    return defaultValueForPath(f.path);
  }

  function defaultValueForPath(path: string): any {
    const leaf = path.split('.').pop()!.toLowerCase();
    if (/(url|uri|href|link|src)$/.test(leaf)) return 'https://example.com/';
    if (/(id|uuid|guid)$/.test(leaf)) return 'wma-id-1';
    if (/(count|amount|qty|quantity|index|num|size|width|height|price|total|value|len|length)$/.test(leaf)) return 1;
    if (/(^|_)(is|has|can|should|enable|disabled|visible|open)/.test(leaf)) return true;
    if (/(token|secret|key|signature|sig|nonce)$/.test(leaf)) return 'wma-token';
    if (/(html|markup|content|body|text|message|msg|title|label|name|data|payload)$/.test(leaf)) return 'wma';
    return 'wma';
  }

  // Base template: all fields at their constraint-derived values. Shallow
  // paths are written first so a nested field can refine them.
  const base: Record<string, any> = {};
  const ordered = [...schema.fields].sort((a, b) => a.path.split('.').length - b.path.split('.').length);
  for (const f of ordered) {
    if (f.confidence < 0.5) continue;
    // A parent that a confidenced child needs must stay an object.
    const hasChildren = schema.fields.some((o) => o.path.startsWith(f.path + '.') && o.confidence >= 0.35);
    if (hasChildren) {
      const segs = f.path.split('.');
      let cur = base;
      for (let i = 0; i < segs.length; i++) {
        if (cur[segs[i]!] === undefined || typeof cur[segs[i]!] !== 'object' || cur[segs[i]!] === null) {
          cur[segs[i]!] = {};
        }
        cur = cur[segs[i]!];
      }
      continue;
    }
    const v = valueFor(f);
    if (v !== undefined) setPath(base, f.path, v);
  }
  if (Object.keys(base).length || schema.structured) templates.push(base);

  // Variants: one template per value that unlocks a branch or satisfies a
  // one-of constraint (allow-lists, switch cases, discriminators).
  const variantValues = new Map<string, any[]>();
  for (const d of schema.discriminators) variantValues.set(d.path, d.values.slice(0, 8));
  for (const f of schema.fields) {
    const oo = f.constraints.find((c) => c.kind === 'one-of');
    if (oo && oo.kind === 'one-of') {
      const merged = new Set<any>([...(variantValues.get(f.path) || []), ...oo.values]);
      variantValues.set(f.path, Array.from(merged).slice(0, 8));
    }
  }
  for (const [path, values] of variantValues) {
    for (const v of values) {
      const t = deepClone(base);
      setPath(t, path, v);
      templates.push(t);
    }
  }

  // Observed protocol samples (messages the page itself sends).
  for (const s of extraSamples) {
    if (s && typeof s === 'object') templates.push(deepClone(s));
  }

  // A few generic attack probes that do not depend on inferred fields.
  for (const g of genericMessages()) templates.push(g);

  // Deduplicate.
  const seen = new Set<string>();
  const out: Record<string, any>[] = [];
  for (const t of templates) {
    const k = stableStringify(t);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(t);
    if (out.length >= max) break;
  }
  return out;
}

export function genericMessages(): Record<string, any>[] {
  const common = ['message', 'ping', 'init', 'ready', 'load', 'get', 'set', 'open', 'close', 'pay', 'login', 'auth', 'token', 'navigate', 'resize', 'config', 'action', 'event'];
  const out: Record<string, any>[] = [];
  for (const t of common.slice(0, 8)) {
    out.push({ type: t });
    out.push({ action: t });
    out.push({ cmd: t });
    out.push({ event: t });
  }
  out.push({});
  out.push({ type: 'message', data: {} });
  out.push({ type: 'message', payload: {} });
  return out;
}

function deepClone<T>(v: T): T {
  try {
    return JSON.parse(JSON.stringify(v));
  } catch {
    return v;
  }
}

export function stableStringify(v: any): string {
  const seen = new WeakSet();
  return JSON.stringify(v, function (_k, val) {
    if (val && typeof val === 'object') {
      if (seen.has(val)) return '[c]';
      seen.add(val);
      if (!Array.isArray(val)) {
        return Object.keys(val)
          .sort()
          .reduce((o: any, k) => {
            o[k] = val[k];
            return o;
          }, {});
      }
    }
    return val;
  });
}

/** Build a schema for a captured listener, using static + runtime sources. */
export function buildSchema(listener: CapturedListener, runtime?: { paths?: Record<string, any>; compares?: any[] }): MessageSchema {
  const paramNames: string[] = [];
  const schema = inferStaticSchema(listener.source, paramNames);
  if (runtime) mergeRuntimeSchema(schema, runtime.paths || {}, runtime.compares || []);
  return schema;
}
