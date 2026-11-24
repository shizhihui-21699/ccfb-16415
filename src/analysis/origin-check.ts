/**
 * Semantic analysis of origin/source validation inside a message handler.
 *
 * The hard part of this problem is that most handlers *do* contain something
 * that looks like an origin check. This module grades those checks instead of
 * merely detecting them:
 *
 *   strong      exact allow-list of absolute origins, correctly enforced
 *   same-origin origin === location.origin
 *   weak        substring / prefix / suffix / unanchored-regex matching that an
 *               attacker-controlled origin can satisfy or slip past
 *   deny-list   blocks a fixed bad origin, allows everything else
 *   data-based  validates a field of event.data (forgeable) instead of origin
 *   source-based validates event.source identity (does not establish origin)
 *   post-check  validation happens after the sensitive action
 *   none        touches the event without any origin-derived condition
 *   unknown     delegates to a helper that could not be resolved
 *
 * The result also carries the concrete `allowedOrigins` set and a list of
 * human-readable weaknesses used to build the final report and the probe plan.
 */
import { parse } from 'acorn';
import * as walk from 'acorn-walk';

export type GuardVerdict =
  | 'strong'
  | 'same-origin'
  | 'weak'
  | 'deny-list'
  | 'data-based'
  | 'source-based'
  | 'post-check'
  | 'none'
  | 'unknown';

export interface OriginPredicate {
  verdict: GuardVerdict;
  /** Absolute origins that pass, when the predicate is enumerable. */
  allowedOrigins: string[];
  /** Absolute origins explicitly excluded by a deny-list predicate. */
  excludedOrigins?: string[];
  /** Resolved string operands (needle/prefix/suffix/pattern) the check used. */
  operands?: string[];
  /** Method name for string-test predicates: startsWith | indexOf | ... */
  method?: string;
  /** Why a non-strong predicate is weak; empty for strong verdicts. */
  weaknesses: string[];
  /** Expression text that produced this predicate. */
  evidence: string;
  /** Location in the analysed handler source, when known. */
  start?: number;
  end?: number;
}

export interface HandlerSemantics {
  /** True when the handler reads event.origin at all. */
  readsOrigin: boolean;
  readsSource: boolean;
  readsData: boolean;
  /** Guard that protects the handler's effects, or null when unguarded. */
  guard: OriginPredicate | null;
  /** All origin-derived predicates encountered (guards and non-guards). */
  predicates: OriginPredicate[];
  /** Static sink positions and kinds present in the handler body. */
  staticSinks: { kind: string; at: number; guarded: boolean }[];
  /** A guard that exists but runs after a sink. */
  postCheck: boolean;
  /** reply postMessage(..., '*') or similar reflected transmission. */
  wildcardOutbound: boolean;
  /** Field names referenced from event.data — used to seed the probe schema. */
  dataFields: string[];
  /** Values compared against origin, including weak and deny-list ones. */
  originLiterals: string[];
  /** Named helper functions the guard delegates to. */
  delegatedHelpers: string[];
  /** Parse/recovery diagnostics. */
  notes: string[];
}

export interface AnalyzeOptions {
  /** Handler parameter names that alias the MessageEvent. */
  paramNames?: string[];
  /** Parameter names that alias the origin string (helper functions). */
  originParams?: string[];
  /** Script-level constants (name -> string value) from the enclosing scope. */
  consts?: Record<string, string>;
  /** Script-level array/Set constants (name -> string values). */
  constArrays?: Record<string, string[]>;
  /** Script-level regex constants (name -> pattern/flags). */
  constRegexes?: Record<string, { pattern: string; flags: string }>;
  /**
   * Operands observed at runtime for origin string comparisons, e.g.
   * [{method:'startsWith', operand:'https://host.example'}]. Used when the
   * operand is a runtime value that static analysis cannot resolve.
   */
  runtimeOriginCompares?: { method: string; operand: string }[];
  /** Resolves a helper identifier to its source (for recursive guarding). */
  resolveHelper?: (name: string) => string | null;
  maxDepth?: number;
  /** Current recursion depth (internal). */
  depth?: number;
}

interface Ctx {
  /** expressions that denote the event object */
  eventAliases: Set<string>;
  /** expressions that denote the origin string */
  originAliases: Set<string>;
  sourceAliases: Set<string>;
  dataAliases: Set<string>;
  /** variable name -> literal array of origins, from local assignments */
  arrayLiterals: Map<string, string[]>;
  /** variable name -> single origin literal */
  scalarLiterals: Map<string, string[]>;
  /** variable name -> source text of its initialiser, for enum-like constants */
  constNodes: Map<string, any>;
  /** variable name -> regex literal */
  regexLiterals: Map<string, { pattern: string; flags: string }>;
  notes: string[];
  resolveHelper?: (name: string) => string | null;
  depth: number;
  maxDepth: number;
}

const ABS_ORIGIN = /^https?:\/\/[^/?#\s"'`]+$/i;

function text(code: string, node: any, max = 300): string {
  return code
    .slice(node.start, Math.min(node.end, node.start + max))
    .replace(/\s+/g, ' ')
    .trim();
}

function propName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  return null;
}

/** Turn a MemberExpression / Identifier AST node into a dotted path string. */
function pathOf(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    if (node.computed) {
      if (node.property.type === 'Literal') {
        const base = pathOf(node.object);
        return base == null ? null : `${base}[${JSON.stringify(node.property.value)}]`;
      }
      return null;
    }
    const base = pathOf(node.object);
    const p = propName(node.property);
    return base == null || p == null ? null : `${base}.${p}`;
  }
  if (node.type === 'ChainExpression') return pathOf(node.expression);
  if (
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'FunctionDeclaration'
  ) {
    return null;
  }
  return null;
}

function literalValue(node: any): { known: boolean; value?: any } {
  if (!node) return { known: false };
  if (node.type === 'Literal') {
    if (node.regex) return { known: true, value: { regex: node.regex.pattern, flags: node.regex.flags } };
    return { known: true, value: node.value };
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return { known: true, value: node.quasis.map((q: any) => q.value.cooked).join('') };
  }
  if (node.type === 'UnaryExpression' && node.operator === '-' && node.argument.type === 'Literal') {
    return { known: true, value: -node.argument.value };
  }
  return { known: false };
}

function strArray(node: any): string[] | null {
  // ["a","b"] or new Set(["a"]) or 'a,b'.split(',')
  if (!node) return null;
  if (node.type === 'ArrayExpression') {
    const out: string[] = [];
    for (const el of node.elements) {
      if (!el) return null;
      const lv = literalValue(el);
      if (!lv.known || typeof lv.value !== 'string') return null;
      out.push(lv.value);
    }
    return out;
  }
  if (node.type === 'NewExpression' && propName(node.callee) === 'Set' && node.arguments[0]) {
    return strArray(node.arguments[0]);
  }
  if (
    node.type === 'CallExpression' &&
    node.callee?.type === 'MemberExpression' &&
    propName(node.callee.property) === 'split' &&
    node.callee.object?.type === 'Literal' &&
    typeof node.callee.object.value === 'string'
  ) {
    const sep = node.arguments[0] && literalValue(node.arguments[0]);
    const sepStr = sep && sep.known && typeof sep.value === 'string' ? sep.value : ',';
    return node.callee.object.value.split(sepStr).map((s: string) => s.trim()).filter(Boolean);
  }
  return null;
}

/** Classify one boolean expression in terms of origin semantics. */
function classify(
  expr: any,
  code: string,
  ctx: Ctx
): { predicate: OriginPredicate | null; negated?: OriginPredicate | null } {
  const r = classifyInner(expr, code, ctx);
  if (r.predicate && r.predicate.start === undefined && expr) {
    r.predicate.start = expr.start;
    r.predicate.end = expr.end;
  }
  return r;
}

function classifyInner(
  expr: any,
  code: string,
  ctx: Ctx
): { predicate: OriginPredicate | null; negated?: OriginPredicate | null } {
  if (!expr) return { predicate: null };

  // unwrap
  if (expr.type === 'ChainExpression') return classify(expr.expression, code, ctx);
  if (expr.type === 'ParenthesizedExpression') return classify(expr.expression, code, ctx);
  if (expr.type === 'SequenceExpression') {
    return classify(expr.expressions[expr.expressions.length - 1], code, ctx);
  }

  if (expr.type === 'UnaryExpression' && expr.operator === '!') {
    const inner = classify(expr.argument, code, ctx);
    if (inner.predicate) {
      const neg = negate(inner.predicate, text(code, expr));
      return { predicate: neg, negated: inner.predicate };
    }
    return { predicate: null };
  }

  if (expr.type === 'LogicalExpression') {
    const l = classify(expr.left, code, ctx).predicate;
    const r = classify(expr.right, code, ctx).predicate;
    if (expr.operator === '&&') {
      // both must hold: take the conjunction (weakest link)
      if (l && r) return { predicate: combine(l, r, 'and') };
      return { predicate: l || r };
    }
    // || : alternative branches, cannot conjoin soundly.
    if (l || r) {
      // Only report a disjunctive *origin* condition; a disjunction of data
      // checks (e.g. `!ev.data || ev.data.cmd !== 'x'`) is a data guard and must
      // not be mistaken for origin validation.
      const hasOriginSide = (p: OriginPredicate | null) =>
        !!p && ['strong', 'same-origin', 'weak', 'deny-list', 'post-check'].includes(p.verdict);
      if (hasOriginSide(l) || hasOriginSide(r)) {
        return {
          predicate: {
            verdict: 'unknown',
            allowedOrigins: [],
            weaknesses: [`disjunctive origin condition cannot be verified statically: ${text(code, expr, 200)}`],
            evidence: text(code, expr),
          },
        };
      }
      // Surface a data-based predicate only when both sides are data-derived.
      if (l?.verdict === 'data-based' || r?.verdict === 'data-based') return { predicate: l || r };
      return { predicate: null };
    }
    return { predicate: null };
  }

  if (expr.type === 'BinaryExpression') {
    return { predicate: binaryPredicate(expr, code, ctx) };
  }

  if (expr.type === 'CallExpression') {
    return { predicate: callPredicate(expr, code, ctx) };
  }

  return { predicate: null };
}

function originExprOf(node: any, ctx: Ctx): boolean {
  const p = pathOf(node);
  if (!p) return false;
  if (ctx.originAliases.has(p)) return true;
  // e.origin / event.origin / anything.origin where base aliases event
  const m = /^(.+)\.origin$/.exec(p);
  if (m) {
    const base = m[1];
    if (ctx.eventAliases.has(base)) return true;
    if (/^(window\.)?(location|document\.location)$/.test(base)) return false; // own origin
    if (/^e(vent)?$/.test(base)) return true;
  }
  return p === 'origin' || p === 'evt.origin' || p === 'ev.origin' || p === 'msg.origin';
}

function sourceExprOf(node: any, ctx: Ctx): boolean {
  const p = pathOf(node);
  if (!p) return false;
  if (ctx.sourceAliases.has(p)) return true;
  const m = /^(.+)\.source$/.exec(p);
  return !!(m && (ctx.eventAliases.has(m[1]) || /^e(vent)?$/.test(m[1])));
}

function ownOrigin(node: any): boolean {
  const p = pathOf(node);
  return !!p && /^(window\.)?location\.origin$|^document\.location\.origin$|^self\.origin$|^location\.host$/.test(p);
}

function dataExprOf(node: any, ctx: Ctx): boolean {
  const p = pathOf(node);
  if (!p) return false;
  if (ctx.dataAliases.has(p)) return true;
  const m = /^(.+)\.data(\.|$)/.exec(p);
  return !!(m && (ctx.eventAliases.has(m[1]) || /^e(vent)?$/.test(m[1])));
}

function mk(
  verdict: GuardVerdict,
  evidence: string,
  allowed: string[] = [],
  weaknesses: string[] = [],
  extra?: { excludedOrigins?: string[]; start?: number; end?: number; operands?: string[]; method?: string }
): OriginPredicate {
  return { verdict, allowedOrigins: allowed, weaknesses, evidence, ...(extra || {}) };
}

function binaryPredicate(expr: any, code: string, ctx: Ctx): OriginPredicate | null {
  const op = expr.operator; // === !== == != < <= > >=
  const left = expr.left;
  const right = expr.right;

  const leftIsOrigin = originExprOf(left, ctx);
  const rightIsOrigin = originExprOf(right, ctx);
  const leftIsSource = sourceExprOf(left, ctx);
  const rightIsSource = sourceExprOf(right, ctx);
  const leftIsData = dataExprOf(left, ctx);
  const rightIsData = dataExprOf(right, ctx);
  const ev = text(code, expr);

  if (leftIsSource || rightIsSource) {
    return mk('source-based', ev, [], [
      'validates event.source identity; any window the attacker can open or frame also passes',
    ]);
  }
  if ((leftIsOrigin || rightIsOrigin) && op in { '===': 1, '==': 1, '!==': 1, '!=': 1 }) {
    const other = leftIsOrigin ? right : left;
    const nested = classify(other, code, ctx).predicate;
    if (nested && nested.verdict !== 'none') return nested; // e.g. helper(e.origin) === true
    let lv = literalValue(other);
    if (!lv.known) {
      // Comparing against a constant (`e.origin !== WIDGET_ORIGIN`) is the
      // normal shape in minified/enum-style code.
      const resolved = resolveConstString(other, ctx, 0);
      if (resolved != null) lv = { known: true, value: resolved };
    }
    if (lv.known && typeof lv.value === 'string') {
      const v = lv.value;
      const eq = op === '===' || op === '==';
      const star = v === '*';
      if (star) {
        return mk('weak', ev, [], ['compares origin against "*", which never matches a real origin']);
      }
      if (!ABS_ORIGIN.test(v)) {
        // comparing against a host, path, or substring is not an origin match
        if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/i.test(v)) {
          return mk('weak', ev, [], [
            `compares origin against host string "${v}" without scheme; a matching origin cannot be enumerated reliably`,
          ]);
        }
        return mk('weak', ev, [], [`compared value "${v}" is not an absolute origin`]);
      }
      if (eq) {
        return mk('strong', ev, [normalizeOrigin(v)], [], { start: expr.start, end: expr.end });
      }
      // !== "x" -> not an allow-list by itself unless used as a reject guard;
      // represent as an exclusion and let guard assembly interpret it.
      return mk('deny-list', ev, [], [`only rejects a single origin "${v}"; every other origin passes`], {
        excludedOrigins: [normalizeOrigin(v)],
        start: expr.start,
        end: expr.end,
      });
    }
    if (ownOrigin(other)) {
      // origin === location.origin
      return mk('same-origin', ev, [], []);
    }
    if (lv.known) {
      return mk('weak', ev, [], ['origin compared against a non-string value']);
    }
    return mk('unknown', ev, [], ['origin compared against a value that could not be resolved statically']);
  }

  if (leftIsData || rightIsData) {
    return mk('data-based', ev, [], [
      'validates a value taken from message data; the sender controls it, so it does not authenticate the origin',
    ]);
  }

  // list.indexOf(origin) === -1  /  list.includes(origin) === true  /  origin.indexOf(x) !== -1
  // (the origin may sit inside a call rather than as a bare operand)
  const membership = [left, right].find((n: any) => n && n.type === 'CallExpression');
  if (membership && membership.callee?.type === 'MemberExpression') {
    const mMethod = propName(membership.callee.property);
    const mArgs = membership.arguments || [];
    const listCall = ['indexOf', 'includes', 'lastIndexOf', 'has'].includes(mMethod || '');
    if (listCall) {
      const argIsOrigin = mArgs.some((a: any) => originExprOf(a, ctx));
      const recvIsOrigin = originExprOf(membership.callee.object, ctx);
      // Membership means the origin is the *argument* to a list method
      // (`list.includes(origin)`). When the origin is the receiver
      // (`origin.indexOf(x)`), it is a string-position test and belongs to the
      // callPredicate path below, not here.
      if (argIsOrigin && !recvIsOrigin) {
        // Resolve the receiving list to an enumerable origin set when possible.
        const listNode = membership.callee.object;
        let list: string[] | null = null;
        const direct = strArray(listNode);
        if (direct) list = direct;
        else {
          const p = pathOf(listNode);
          if (p && ctx.arrayLiterals.has(p)) list = ctx.arrayLiterals.get(p)!;
          else if (p && ctx.scalarLiterals.has(p)) list = ctx.scalarLiterals.get(p)!;
        }
        const other = membership === left ? right : left;
        const olv = literalValue(other);
        // indexOf(...) === -1 means "not found"; !== -1 means "found".
        const foundSense =
          (op === '!==' || op === '!=') && olv.known && olv.value === -1
            ? true
            : (op === '===' || op === '==') && olv.known && olv.value === -1
              ? false
              : (op === '>=' || op === '>') && olv.known && typeof olv.value === 'number' && olv.value < 0
                ? true
                : null;
        if (list) {
          const bad = list.filter((x) => !ABS_ORIGIN.test(x));
          if (list.length === 0) return mk('weak', ev, [], ['allow-list is empty at the comparison site']);
          if (bad.length) return mk('weak', ev, [], [`allow-list contains entries that are not absolute origins: ${bad.slice(0, 4).join(', ')}`]);
          if (foundSense === false) {
            // this branch is the reject path; represented as a deny of the list
            return mk('deny-list', ev, [], [`the reject branch excludes ${list.join(', ')}`], {
              excludedOrigins: list.map(normalizeOrigin),
              operands: list.map(normalizeOrigin),
            });
          }
          return mk('strong', ev, list.map(normalizeOrigin), [], { operands: list.map(normalizeOrigin) });
        }
      }
    }
  }

  // origin.indexOf('x') === -1 / origin.indexOf('x') >= 0 / origin.search(re) !== -1
  const callSide = [left, right].find(
    (n: any) =>
      n?.type === 'CallExpression' &&
      n.callee?.type === 'MemberExpression' &&
      ['indexOf', 'search', 'lastIndexOf', 'includes'].includes(propName(n.callee.property) || '') &&
      originExprOf(n.callee.object, ctx)
  );
  if (callSide) {
    const other = callSide === left ? right : left;
    const lv = literalValue(other);
    const inner = callPredicate(callSide, code, ctx);
    if (inner) {
      if (lv.known && typeof lv.value === 'number') {
        const foundComparison =
          (op === '===' || op === '==') && lv.value === -1
            ? 'not-found'
            : (op === '!==' || op === '!=') && lv.value === -1
              ? 'found'
              : (op === '>=' || op === '>') && lv.value < 0
                ? 'found'
                : (op === '<') && lv.value >= 0
                  ? 'not-found'
                  : null;
        // 'not-found' in a reject position becomes 'found' after negation, so
        // report the call's own weakness consistently either way.
        void foundComparison;
      }
      return inner;
    }
  }

  return null;
}

function callPredicate(expr: any, code: string, ctx: Ctx): OriginPredicate | null {
  const callee = expr.callee;
  const name = callee?.type === 'MemberExpression' ? propName(callee.property) : callee?.name;
  const args = expr.arguments || [];
  const ev = text(code, expr);
  const recv = callee?.type === 'MemberExpression' ? callee.object : null;

  // origin.startsWith / endsWith / indexOf / includes / match / search / localeCompare
  if (recv && (originExprOf(recv, ctx) || dataExprOf(recv, ctx))) {
    const isData = dataExprOf(recv, ctx);
    const lv0 = args[0] ? literalValue(args[0]) : { known: false };
    const resolvedArg = lv0.known && typeof lv0.value === 'string' ? lv0.value : resolveConstString(args[0], ctx, 0);
    const arg = resolvedArg;
    if (isData) {
      return mk('data-based', ev, [], ['string test applied to message data, not to event.origin']);
    }
    switch (name) {
      case 'startsWith':
        if (arg != null) {
          return mk('weak', ev, [], [`origin.startsWith("${arg}") accepts look-alike origins such as "${arg}.attacker.tld"`], {
            operands: [arg],
            method: 'startsWith',
          });
        }
        return mk('unknown', ev, [], ['startsWith with a non-literal prefix']);
      case 'endsWith':
        if (arg != null) {
          return mk('weak', ev, [], [
            `origin.endsWith("${arg}") accepts any origin whose host ends with that text (e.g. "https://x${arg}" when no dot is included)`,
          ], { operands: [arg], method: 'endsWith' });
        }
        return mk('unknown', ev, [], ['endsWith with a non-literal suffix']);
      case 'includes':
      case 'indexOf':
      case 'lastIndexOf':
        if (arg != null) {
          return mk('weak', ev, [], [
            `origin.${name}("${arg}") is a substring test; "${arg}.attacker.tld" and "https://attacker.tld/?${arg}" style origins are not excluded`,
          ], { operands: [arg], method: name });
        }
        return mk('unknown', ev, [], [name + ' with a non-literal argument']);
      case 'match':
      case 'search':
        if (arg != null) return regexPredicate(String(arg), ev);
        return mk('unknown', ev, [], [name + ' with a non-literal pattern']);
      case 'toLowerCase':
      case 'trim':
      case 'toString':
        return classify(expr, code, ctx).predicate;
      case 'split':
      case 'charAt':
      case 'slice':
      case 'substr':
      case 'substring':
        return mk('weak', ev, [], [`origin is transformed with ${name}() before comparison, which is not a sound allow-list`]);
      default:
        return null;
    }
  }

  // regex.test(origin)
  if ((name === 'test' || name === 'exec') && args[0] && originExprOf(args[0], ctx)) {
    const reNode = recv;
    if (reNode) {
      if (reNode.type === 'Literal' && reNode.regex) return regexPredicate(reNode.regex.pattern, ev);
      const v = reNode.type === 'NewExpression' ? reNode.arguments?.[0] : null;
      const lv = v ? literalValue(v) : { known: false };
      if (lv.known && typeof lv.value === 'string') return regexPredicate(lv.value, ev);
      // a variable holding a RegExp: consult the regex constant table
      const p = pathOf(reNode);
      if (p && ctx.regexLiterals.has(p)) {
        const r = ctx.regexLiterals.get(p)!;
        return { ...regexPredicate(r.pattern, ev), operands: [r.pattern], method: 'regex' };
      }
      if (p && ctx.scalarLiterals.has(p)) return regexPredicate(ctx.scalarLiterals.get(p)![0], ev);
    }
    return mk('unknown', ev, [], ['regular expression held in an unresolved variable']);
  }

  // allowList.includes(origin) / indexOf(origin) / some(x => x === origin) / Set.has(origin)
  // Only member-callee calls can be membership tests; a bare identifier call
  // that receives the origin is a helper delegation, handled below.
  if (callee?.type === 'MemberExpression' && args.some((a: any) => originExprOf(a, ctx))) {
    const listNode = recv;
    let list: string[] | null = null;
    if (listNode) {
      const direct = strArray(listNode);
      if (direct) list = direct;
      else {
        const p = pathOf(listNode);
        if (p && ctx.arrayLiterals.has(p)) list = ctx.arrayLiterals.get(p)!;
        else if (p && ctx.scalarLiterals.has(p)) list = ctx.scalarLiterals.get(p)!;
        else if (p && ctx.arrayLiterals.has(p)) list = ctx.arrayLiterals.get(p)!;
      }
    }
    if (list) {
      const bad = list.filter((s) => s !== '*' && !ABS_ORIGIN.test(s));
      if (list.includes('*')) {
        return mk('weak', ev, [], ['allow-list contains "*", accepting every origin']);
      }
      if (bad.length) {
        return mk('weak', ev, [], [`allow-list contains entries that are not absolute origins: ${bad.slice(0, 4).join(', ')}`]);
      }
      if (list.length === 0) return mk('weak', ev, [], ['allow-list is empty at the comparison site']);
      return mk('strong', ev, list.map(normalizeOrigin));
    }
    // uncommon: array.some((x) => x === origin)
    if (name === 'some' && recv) {
      let found = false;
      walk.simple(recv, {
        BinaryExpression(n: any) {
          if ((n.operator === '===' || n.operator === '==') && (originExprOf(n.left, ctx) || originExprOf(n.right, ctx))) found = true;
        },
      });
      if (found) {
        const p = pathOf(recv);
        if (p && ctx.arrayLiterals.has(p)) {
          const arr = ctx.arrayLiterals.get(p)!;
          if (arr.every((s) => ABS_ORIGIN.test(s))) return mk('strong', ev, arr.map(normalizeOrigin));
          return mk('weak', ev, [], ['allow-list entries are not absolute origins']);
        }
      }
    }
    return mk('unknown', ev, [], ['membership test against an allow-list that could not be resolved statically']);
  }

  // delegated helper
  if (callee?.type === 'Identifier' && ctx.resolveHelper) {
    const isSuspicious =
      /origin|whitelist|allowlist|allow|trusted|verify|check|valid|secure|guard|permit/i.test(callee.name);
    if (isSuspicious && ctx.depth < ctx.maxDepth) {
      const src = ctx.resolveHelper(callee.name);
      if (src) {
        const passesOrigin = args[0] ? originExprOf(args[0], ctx) : false;
        const helperParam = helperFirstParam(src);
        const nested = analyzeOriginLogic(src, {
          paramNames: passesOrigin ? [] : ctx.eventAliases.size ? Array.from(ctx.eventAliases) : ['e', 'event', 'ev'],
          originParams: passesOrigin && helperParam ? [helperParam] : [],
          resolveHelper: ctx.resolveHelper,
          maxDepth: ctx.maxDepth,
          depth: ctx.depth + 1,
        });
        if (nested.guard && nested.guard.verdict !== 'none') {
          // Surface the helper name in the evidence for the report.
          return { ...nested.guard, evidence: `${callee.name}(${args[0] ? text(code, args[0], 60) : ''}) → ${nested.guard.evidence}` };
        }
        return mk('unknown', ev, [], [`delegates to ${callee.name}() but no origin condition was found in it`]);
      }
      return mk('unknown', ev, [], [`delegates origin validation to unresolved helper ${callee.name}()`]);
    }
  }

  return null;
}

function regexPredicate(pattern: string, ev: string): OriginPredicate {
  const weaknesses: string[] = [];
  const unescapedDot = /(?<!\\)\./.test(pattern.replace(/\\\./g, '\u0000'));
  if (unescapedDot) weaknesses.push(`pattern "${pattern}" uses unescaped dots, so any character matches where "." was meant`);
  if (!/^\^/.test(pattern)) weaknesses.push(`pattern "${pattern}" is not anchored at the start, so it can match a subdomain or prefixed origin`);
  if (!/\$$/.test(pattern) || /\\\$$/.test(pattern) === false && !pattern.endsWith('$')) {
    if (!pattern.endsWith('$')) weaknesses.push(`pattern "${pattern}" is not anchored at the end, so origins with an appended suffix match`);
  }
  if (/\.\*/.test(pattern)) weaknesses.push(`pattern "${pattern}" contains .* which widens the match`);
  if (/\[\s*\.\s*\]/.test(pattern) || /\\\./.test(pattern) === false) {
    // covered by unescapedDot
  }
  if (weaknesses.length) return mk('weak', ev, [], weaknesses, { operands: [pattern], method: 'regex' });
  // fully anchored, dots escaped: try to enumerate a literal origin
  const m = /^\^https?:\\\/\\\/([A-Za-z0-9.\-]+)\\?\.?(?:\\\/)?\$?$/.exec(pattern.replace(/\//g, '\\/'));
  if (m) return mk('strong', ev, [`https://${m[1]}`], [], { operands: [pattern], method: 'regex' });
  return mk('unknown', ev, [], [`regular expression "${pattern}" is anchored but its accepted origin set cannot be enumerated`], {
    operands: [pattern],
    method: 'regex',
  });
}

/** Resolve an expression to a string when it is a literal or a known constant. */
function resolveConstString(node: any, ctx: Ctx, depth: number): string | null {
  if (!node || depth > 4) return null;
  const lv = literalValue(node);
  if (lv.known && typeof lv.value === 'string') return lv.value;
  if (lv.known && typeof lv.value === 'number') return String(lv.value);
  if (node.type === 'Identifier') {
    const init = ctx.constNodes.get(node.name);
    if (init) return resolveConstString(init, ctx, depth + 1);
    const scalars = ctx.scalarLiterals.get(node.name);
    if (scalars && scalars.length) return scalars[0]!;
    return null;
  }
  if (node.type === 'MemberExpression' && node.object?.type === 'Identifier') {
    const init = ctx.constNodes.get(node.object.name);
    const prop = propName(node.property);
    if (init && prop && (init.type === 'ObjectExpression' || init.type === 'ArrayExpression')) {
      if (init.type === 'ObjectExpression') {
        for (const p of init.properties) {
          if (p.type === 'Property' && propName(p.key) === prop) return resolveConstString(p.value, ctx, depth + 1);
        }
      }
    }
    return null;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const a = resolveConstString(node.left, ctx, depth + 1);
    const b = resolveConstString(node.right, ctx, depth + 1);
    if (a != null && b != null) return a + b;
    return null;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length) {
    let out = '';
    for (let i = 0; i < node.quasis.length; i++) {
      out += node.quasis[i].value.cooked;
      if (i < node.expressions.length) {
        const v = resolveConstString(node.expressions[i], ctx, depth + 1);
        if (v == null) return null;
        out += v;
      }
    }
    return out;
  }
  if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression' && propName(node.callee.property) === 'toLowerCase') {
    const v = resolveConstString(node.callee.object, ctx, depth + 1);
    return v == null ? null : v.toLowerCase();
  }
  return null;
}

/**
 * Build a predicate from operands the browser actually passed to origin string
 * methods. Only a known comparison form is used; anything else leaves the
 * original verdict in place.
 */
function refineWithRuntimeCompares(
  compares: { method: string; operand: string }[],
  evidence: string
): OriginPredicate | null {
  for (const c of compares) {
    const opnd = c.operand;
    if (!opnd) continue;
    if (c.method === 'startsWith') {
      return mk('weak', `${evidence} [runtime: startsWith(${JSON.stringify(opnd)})]`, [], [
        `origin.startsWith("${opnd}") accepts look-alike origins such as "${opnd}.attacker.tld"`,
      ], { operands: [opnd], method: 'startsWith' });
    }
    if (c.method === 'endsWith') {
      return mk('weak', `${evidence} [runtime: endsWith(${JSON.stringify(opnd)})]`, [], [
        `origin.endsWith("${opnd}") accepts origins that merely end with that text`,
      ], { operands: [opnd], method: 'endsWith' });
    }
    if (c.method === 'includes' || c.method === 'indexOf' || c.method === 'lastIndexOf') {
      return mk('weak', `${evidence} [runtime: ${c.method}(${JSON.stringify(opnd)})]`, [], [
        `origin.${c.method}("${opnd}") is a substring test`,
      ], { operands: [opnd], method: c.method });
    }
    if (c.method === 'match' || c.method === 'search') {
      const m = /^\/(.*)\/([a-z]*)$/.exec(opnd);
      if (m) return { ...regexPredicate(m[1]!, evidence), operands: [m[1]!], method: 'regex' };
    }
    if (c.method === 'localeCompare') continue;
  }
  return null;
}

function normalizeOrigin(s: string): string {
  return s.replace(/\/+$/, '');
}

/** First parameter name of a function source, or null. */
function helperFirstParam(src: string): string | null {
  try {
    const { fn } = parseFunction(src);
    const p0 = fn.params?.[0];
    if (p0?.type === 'Identifier') return p0.name;
    if (p0?.type === 'AssignmentPattern' && p0.left?.type === 'Identifier') return p0.left.name;
  } catch {
    /* not parseable */
  }
  return null;
}

function negate(p: OriginPredicate, ev: string): OriginPredicate {
  switch (p.verdict) {
    case 'strong':
      // !(origin === X) -> rejects X, allows the rest
      return mk('deny-list', p.evidence, [], [`the passing set is "everything except ${p.allowedOrigins.join(', ')}"`], {
        excludedOrigins: p.allowedOrigins,
        start: p.start,
        end: p.end,
      });
    case 'deny-list':
      // !(origin !== X) -> origin === X
      return mk('strong', p.evidence, p.excludedOrigins || p.allowedOrigins, []);
    case 'same-origin':
      return mk('same-origin', p.evidence, [], []);
    case 'weak':
      return mk('weak', p.evidence, [], p.weaknesses, { operands: p.operands, method: p.method, start: p.start, end: p.end });
    case 'data-based':
      return mk('data-based', p.evidence, [], p.weaknesses, { operands: p.operands, method: p.method, start: p.start, end: p.end });
    case 'source-based':
      return mk('source-based', p.evidence, [], p.weaknesses, { operands: p.operands, method: p.method, start: p.start, end: p.end });
    default:
      return mk('unknown', p.evidence, [], p.weaknesses.length ? p.weaknesses : ['negated unknown origin condition']);
  }
}

function combine(a: OriginPredicate, b: OriginPredicate, mode: 'and'): OriginPredicate {
  const order: GuardVerdict[] = ['strong', 'same-origin', 'weak', 'deny-list', 'data-based', 'source-based', 'unknown', 'none'];
  const rank = (v: GuardVerdict) => order.indexOf(v);
  const weaker = rank(a.verdict) >= rank(b.verdict) ? a : b;
  const stronger = weaker === a ? b : a;
  const allowed =
    a.verdict === 'strong' && b.verdict === 'strong'
      ? a.allowedOrigins.filter((o) => b.allowedOrigins.includes(o))
      : weaker.verdict === 'strong'
        ? weaker.allowedOrigins
        : [];
  return mk(
    weaker.verdict === 'strong' ? 'strong' : weaker.verdict,
    `${a.evidence} && ${b.evidence}`,
    allowed,
    [...a.weaknesses, ...b.weaknesses],
    { operands: weaker.operands, method: weaker.method }
  );
}

/** Does the statement reject the message (return/throw/continue/break)? */
function isRejectStatement(stmt: any, depthGuard: any[] = []): boolean {
  if (!stmt) return false;
  switch (stmt.type) {
    case 'ReturnStatement':
    case 'ThrowStatement':
    case 'ContinueStatement':
    case 'BreakStatement':
      return true;
    case 'BlockStatement':
      return stmt.body.some((s: any) => isRejectStatement(s));
    case 'IfStatement':
      return isRejectStatement(stmt.consequent) || isRejectStatement(stmt.alternate);
    case 'ExpressionStatement': {
      // e.g. `return;` handled above; `throw new Error()` is ThrowStatement.
      // A bare call like `reject()` is only a reject when it is followed by return.
      return false;
    }
    default:
      return false;
  }
}

interface GuardScope {
  /** predicates that must hold for execution to continue past this point */
  requires: OriginPredicate[];
}

const SINK_PATTERNS: { re: RegExp; kind: string }[] = [
  { re: /\.innerHTML\s*=/, kind: 'html:innerHTML' },
  { re: /\.outerHTML\s*=/, kind: 'html:outerHTML' },
  { re: /insertAdjacentHTML\s*\(/, kind: 'html:insertAdjacentHTML' },
  { re: /document\s*\.\s*write(ln)?\s*\(/, kind: 'html:document.write' },
  { re: /\beval\s*\(/, kind: 'eval' },
  { re: /\bnew\s+Function\s*\(/, kind: 'Function' },
  { re: /\bset(Timeout|Interval)\s*\(\s*['"`]/, kind: 'timer-string' },
  { re: /\.location(\.href)?\s*=/, kind: 'location' },
  { re: /location\s*\.\s*(assign|replace)\s*\(/, kind: 'location' },
  { re: /\bwindow\s*\.\s*open\s*\(/, kind: 'window.open' },
  { re: /\.srcdoc\s*=/, kind: 'attr:srcdoc' },
  { re: /setAttribute\s*\(\s*['"`](srcdoc|on\w+)['"`]/, kind: 'attr:setAttribute' },
];

/**
 * Parse a function source (as produced by Function.prototype.toString, which
 * yields either `function (e) {…}`, `e => {…}`, `async e => {…}`, or a method
 * shorthand like `handleEvent(e) {…}`). Returns the function AST node.
 */
function parseFunction(source: string): { fn: any; code: string } {
  const attempts: { code: string; pick: (program: any) => any }[] = [
    { code: source, pick: pickFunctionFromProgram },
    { code: '(' + source + ')', pick: pickFunctionFromProgram },
    { code: '({' + source + '})', pick: (p: any) => p.body[0]?.expression?.properties?.[0]?.value ?? null },
    { code: '({handleEvent:' + source + '})', pick: (p: any) => p.body[0]?.expression?.properties?.[0]?.value ?? null },
    { code: 'async function ' + source.replace(/^\s*async\s+/, ''), pick: pickFunctionFromProgram },
  ];
  let lastErr: any = null;
  for (const a of attempts) {
    try {
      const program = parse(a.code, {
        ecmaVersion: 'latest',
        locations: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      });
      const fn = a.pick(program);
      if (fn) return { fn, code: a.code };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('unparsable function source');
}

function pickFunctionFromProgram(program: any): any {
  const isFn = (n: any) =>
    n &&
    (n.type === 'FunctionDeclaration' ||
      n.type === 'FunctionExpression' ||
      n.type === 'ArrowFunctionExpression');
  for (const stmt of program.body) {
    if (isFn(stmt)) return stmt;
    if (stmt.type === 'ExpressionStatement' && isFn(stmt.expression)) return stmt.expression;
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'SequenceExpression') {
      const last = stmt.expression.expressions[stmt.expression.expressions.length - 1];
      if (isFn(last)) return last;
    }
    if (stmt.type === 'VariableDeclaration') {
      for (const d of stmt.declarations) if (isFn(d.init)) return d.init;
    }
    if (stmt.type === 'ExportDefaultDeclaration' && isFn(stmt.declaration)) return stmt.declaration;
  }
  return null;
}

/**
 * Analyse a handler function body for origin validation semantics.
 * `source` must be the full text of the handler function.
 */
export function analyzeHandler(source: string, opts: AnalyzeOptions = {}): HandlerSemantics {
  const notes: string[] = [];
  const semantics: HandlerSemantics = {
    readsOrigin: false,
    readsSource: false,
    readsData: false,
    guard: null,
    predicates: [],
    staticSinks: [],
    postCheck: false,
    wildcardOutbound: false,
    dataFields: [],
    originLiterals: [],
    delegatedHelpers: [],
    notes,
  };

  let fn: any;
  let parsedCode = source;
  try {
    const parsed = parseFunction(source);
    fn = parsed.fn;
    parsedCode = parsed.code;
  } catch (e: any) {
    // Function.prototype.toString may produce an invalid snippet when the page
    // used native/bound wrappers; report rather than throw.
    notes.push('unparsable handler: ' + String(e.message || e));
    semantics.readsOrigin = /\borigin\b/.test(source);
    semantics.readsSource = /\.source\b/.test(source);
    semantics.readsData = /\.data\b/.test(source);
    semantics.guard = semantics.readsOrigin
      ? mk('unknown', '(unparsable)', [], ['Handler could not be parsed; review manually'])
      : mk('none', '(unparsable)', [], ['No origin check visible in source text']);
    return semantics;
  }

  // Node offsets come from `parsedCode` (which may include wrapper characters
  // added for method-shorthand parsing), so all text extraction uses it.
  const codeText = parsedCode;
  const bodyNode = fn.type === 'Program' ? fn : fn.body;
  const params = fn.params || [];
  const paramNames = new Set<string>(opts.paramNames || []);
  if (params[0]?.type === 'Identifier') paramNames.add(params[0].name);
  if (params[0]?.type === 'AssignmentPattern' && params[0].left?.type === 'Identifier') paramNames.add(params[0].left.name);

  const ctx: Ctx = {
    eventAliases: new Set(paramNames.size ? paramNames : ['e', 'event', 'ev', 'msg', 'message']),
    originAliases: new Set(opts.originParams || []),
    sourceAliases: new Set(),
    dataAliases: new Set(),
    arrayLiterals: new Map(),
    scalarLiterals: new Map(),
    constNodes: new Map(),
    regexLiterals: new Map(),
    notes,
    resolveHelper: opts.resolveHelper,
    depth: (opts as any).depth || 0,
    maxDepth: opts.maxDepth ?? 2,
  };

  // Seed script-level constants first so the local pre-pass can override them.
  if (opts.consts) {
    for (const [k, v] of Object.entries(opts.consts)) ctx.scalarLiterals.set(k, [v]);
  }
  if (opts.constArrays) {
    for (const [k, v] of Object.entries(opts.constArrays)) ctx.arrayLiterals.set(k, v);
  }
  if (opts.constRegexes) {
    for (const [k, v] of Object.entries(opts.constRegexes)) ctx.regexLiterals.set(k, v);
  }

  // Pre-pass: collect local aliases and literal tables so `const ok = e.origin`
  // and `const ALLOWED = ['https://a']` are resolvable.
  walk.simple(bodyNode, {
    VariableDeclarator(n: any) {
      if (n.id?.type !== 'Identifier' || !n.init) return;
      const nm = n.id.name;
      const arr = strArray(n.init);
      if (arr) ctx.arrayLiterals.set(nm, arr);
      const lv = literalValue(n.init);
      if (lv.known && typeof lv.value === 'string') ctx.scalarLiterals.set(nm, [lv.value]);
      ctx.constNodes.set(nm, n.init);
      if (n.init.type === 'Literal' && n.init.regex) ctx.regexLiterals.set(nm, n.init.regex);
      if (n.init.type === 'NewExpression' && propName(n.init.callee) === 'RegExp' && n.init.arguments?.[0]) {
        const lv = literalValue(n.init.arguments[0]);
        const fl = n.init.arguments[1] ? literalValue(n.init.arguments[1]) : { known: false };
        if (lv.known && typeof lv.value === 'string') {
          ctx.regexLiterals.set(nm, { pattern: lv.value, flags: fl.known ? String(fl.value) : '' });
        }
      }
      const p = pathOf(n.init);
      if (p) {
        if (originExprOf(n.init, ctx)) ctx.originAliases.add(nm);
        if (sourceExprOf(n.init, ctx)) ctx.sourceAliases.add(nm);
        if (dataExprOf(n.init, ctx)) ctx.dataAliases.add(nm);
        if (ctx.eventAliases.has(p)) ctx.eventAliases.add(nm);
      }
      // const origin = e.origin
      if (n.init.type === 'MemberExpression' && propName(n.init.property) === 'origin') {
        ctx.originAliases.add(nm);
      }
      if (n.init.type === 'MemberExpression' && propName(n.init.property) === 'source') {
        ctx.sourceAliases.add(nm);
      }
      if (n.init.type === 'MemberExpression' && propName(n.init.property) === 'data') {
        ctx.dataAliases.add(nm);
      }
    },
    AssignmentExpression(n: any) {
      if (n.left?.type === 'Identifier' && n.right?.type === 'MemberExpression') {
        const prop = propName(n.right.property);
        if (prop === 'origin') ctx.originAliases.add(n.left.name);
        if (prop === 'source') ctx.sourceAliases.add(n.left.name);
        if (prop === 'data') ctx.dataAliases.add(n.left.name);
      }
    },
  });

  // Reads.
  walk.simple(bodyNode, {
    MemberExpression(n: any) {
      const p = propName(n.property);
      if (p === 'origin') {
        semantics.readsOrigin = true;
        semantics.originLiterals.push(pathOf(n.object) || '');
      }
      if (p === 'source') semantics.readsSource = true;
      if (p === 'data') semantics.readsData = true;
    },
  });
  if (!semantics.readsOrigin && ctx.originAliases.size) semantics.readsOrigin = true;
  semantics.originLiterals = [];

  // Data fields: e.data.a.b / e.data['a'] reads, and JSON.parse(e.data).a
  const dataFieldSet = new Set<string>();
  walk.simple(bodyNode, {
    MemberExpression(n: any) {
      const p = pathOf(n);
      if (!p) return;
      const m = /^(?:[A-Za-z_$][\w$]*|this)\.data\.([A-Za-z_$][\w$]*)/.exec(p);
      if (m) dataFieldSet.add(m[1]);
    },
    CallExpression(n: any) {
      // JSON.parse(e.data).field
      if (n.callee?.type === 'MemberExpression' && propName(n.callee.property) === 'parse') {
        const outer = pathOf(n);
        if (outer) {
          const m = /\.parse\([^)]*\)\.([A-Za-z_$][\w$]*)/.exec(codeOf(source, n));
          if (m) dataFieldSet.add(m[1]);
        }
      }
    },
  });
  semantics.dataFields = Array.from(dataFieldSet);

  // Static sinks and their positions.
  for (const pat of SINK_PATTERNS) {
    try {
      walk.simple(bodyNode, {
        AssignmentExpression(n: any) {
          const t = text(codeText, n, 400);
          if (pat.re.test(t)) semantics.staticSinks.push({ kind: pat.kind, at: n.start, guarded: false });
        },
        CallExpression(n: any) {
          const t = text(codeText, n, 400);
          if (pat.re.test(t)) semantics.staticSinks.push({ kind: pat.kind, at: n.start, guarded: false });
        },
        NewExpression(n: any) {
          const t = text(codeText, n, 400);
          if (pat.re.test(t)) semantics.staticSinks.push({ kind: pat.kind, at: n.start, guarded: false });
        },
      });
    } catch {
      /* pattern over malformed node */
    }
  }
  // dedupe by kind+position
  const sinkSeen = new Set<string>();
  semantics.staticSinks = semantics.staticSinks.filter((s) => {
    const k = s.kind + ':' + s.at;
    if (sinkSeen.has(k)) return false;
    sinkSeen.add(k);
    return true;
  });

  // Wildcard outbound: postMessage(..., '*')
  walk.simple(bodyNode, {
    CallExpression(n: any) {
      if (n.callee?.type !== 'MemberExpression') return;
      if (propName(n.callee.property) !== 'postMessage') return;
      const target = n.arguments[1];
      const lv = literalValue(target);
      if (lv.known && lv.value === '*') semantics.wildcardOutbound = true;
      if (!target) semantics.wildcardOutbound = true; // defaults to '/' receiver in some libs
    },
  });

  // ---------------------------------------------------------- guard assembly
  //
  // Walk the handler body carrying the set of predicates that must hold for the
  // current statement to execute. Each sensitive sink is attributed the set
  // active at its position; an empty set means that sink is reachable from any
  // origin, which is what makes a handler exploitable. Early-return guards
  // (`if (bad) return; ...`) extend the active set for the rest of the block.
  const allPredicates: OriginPredicate[] = [];
  const sinkVisits: { kind: string; at: number; active: OriginPredicate[] }[] = [];
  // Statements that execute only inside a conditional branch. Even without a
  // known static sink, an action gated by a weak predicate is a weak guard.
  const gatedActions: { at: number; active: OriginPredicate[] }[] = [];
  const guardPositions: number[] = [];

  function classifyAt(node: any): OriginPredicate | null {
    const c = classify(node, codeText, ctx).predicate;
    if (c) allPredicates.push(c);
    return c;
  }

  function noteSinks(stmt: any, active: OriginPredicate[]) {
    if (!stmt) return;
    if (active.length) gatedActions.push({ at: stmt.start, active });
    for (const sink of semantics.staticSinks) {
      if (sink.at >= stmt.start && sink.at < stmt.end) {
        sinkVisits.push({ kind: sink.kind, at: sink.at, active });
        sink.guarded = active.length > 0;
      }
    }
  }

  function walkBlock(stmts: any[], activeIn: OriginPredicate[]): OriginPredicate[] {
    let active = activeIn;
    for (const stmt of stmts) active = walkStmt(stmt, active);
    return active;
  }

  function walkStmt(stmt: any, active: OriginPredicate[]): OriginPredicate[] {
    if (!stmt) return active;
    switch (stmt.type) {
      case 'BlockStatement':
        return walkBlock(stmt.body, active);
      case 'IfStatement': {
        const pred = classifyAt(stmt.test);
        const thenRejects = isRejectStatement(stmt.consequent);
        const elseRejects = isRejectStatement(stmt.alternate);
        if (pred && pred.start !== undefined) guardPositions.push(pred.start);
        if (!pred) {
          walkStmt(stmt.consequent, active);
          if (stmt.alternate) walkStmt(stmt.alternate, active);
          return active;
        }
        if (thenRejects && !elseRejects) {
          // effects inside the rejected branch still run when the test holds
          walkStmt(stmt.consequent, [...active, pred]);
          if (stmt.alternate) walkStmt(stmt.alternate, [...active, negate(pred, text(codeText, stmt.test))]);
          return [...active, negate(pred, text(codeText, stmt.test))];
        }
        if (elseRejects && !thenRejects) {
          walkStmt(stmt.consequent, [...active, pred]);
          return active;
        }
        if (!thenRejects && !stmt.alternate) {
          walkStmt(stmt.consequent, [...active, pred]);
          return active;
        }
        // if/else where both branches act
        walkStmt(stmt.consequent, [...active, pred]);
        if (stmt.alternate) walkStmt(stmt.alternate, [...active, negate(pred, text(codeText, stmt.test))]);
        return active;
      }
      case 'TryStatement':
        walkStmt(stmt.block, active);
        if (stmt.handler) walkStmt(stmt.handler.body, active);
        if (stmt.finalizer) walkStmt(stmt.finalizer, active);
        return active;
      case 'SwitchStatement': {
        for (const c of stmt.cases) walkBlock(c.consequent, active);
        return active;
      }
      case 'ForStatement':
      case 'ForInStatement':
      case 'ForOfStatement':
      case 'WhileStatement':
      case 'DoWhileStatement':
        noteSinks(stmt, active);
        walkStmt(stmt.body, active);
        return active;
      case 'ReturnStatement': {
        // `return origin === 'https://x'` inside a validation helper: the
        // returned expression IS the guard.
        if (stmt.argument) {
          const p = classifyAt(stmt.argument);
          if (p) return [...active, p];
        }
        noteSinks(stmt, active);
        return active;
      }
      case 'LabeledStatement':
        return walkStmt(stmt.body, active);
      default:
        noteSinks(stmt, active);
        return active;
    }
  }

  let endActive: OriginPredicate[];
  if (bodyNode.type === 'BlockStatement') endActive = walkBlock(bodyNode.body, []);
  else endActive = walkStmt(bodyNode, []);

  // Short-circuit conjunction guards: `e.origin === X && run(e.data)`.
  // These are common in minified bundles and read as expression statements.
  walk.simple(bodyNode, {
    ExpressionStatement(n: any) {
      const e = n.expression;
      if (e.type !== 'LogicalExpression' || e.operator !== '&&') return;
      const parts: any[] = [];
      (function flat(x: any) {
        if (x.type === 'LogicalExpression' && x.operator === '&&') {
          flat(x.left);
          flat(x.right);
        } else parts.push(x);
      })(e);
      const guards = parts
        .slice(0, -1)
        .map((p) => classify(p, codeText, ctx).predicate)
        .filter(Boolean) as OriginPredicate[];
      if (guards.length) {
        for (const g of guards) {
          allPredicates.push(g);
          endActive.push(g);
        }
        // The right-hand side is the effect and it is guarded by the left side.
        const action = parts[parts.length - 1];
        if (action && action.type === 'CallExpression') {
          sinkVisits.push({ kind: 'call', at: action.start, active: guards });
        }
        notes.push('guard expressed as a short-circuit conjunction');
      }
    },
  });

  // ------------------------------------------------------------ verdict
  const dedupe = (ps: OriginPredicate[]) => {
    const seen = new Set<string>();
    return ps.filter((p) => {
      const k = p.verdict + '|' + p.evidence;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  };
  semantics.predicates = dedupe(allPredicates);

  function combineAll(ps: OriginPredicate[]): OriginPredicate {
    if (!ps.length) return mk('none', '(no origin-derived condition)');
    if (ps.every((p) => p.verdict === 'strong')) {
      const inter = ps.map((p) => p.allowedOrigins).reduce((a, b) => a.filter((x) => b.includes(x)));
      return mk('strong', ps.map((p) => p.evidence).join(' && '), inter, [], { start: ps[0].start, end: ps[0].end });
    }
    let combined = ps[0];
    for (let i = 1; i < ps.length; i++) combined = combine(combined, ps[i], 'and');
    return combined;
  }

  if (sinkVisits.length) {
    const ungated = sinkVisits.filter((v) => v.active.length === 0);
    const gated = sinkVisits.filter((v) => v.active.length > 0);
    if (ungated.length) {
      // A sink reachable without any origin condition is the exploitable case.
      const earliest = Math.min(...ungated.map((v) => v.at));
      const laterGuard = guardPositions.some((g) => g > earliest);
      if (laterGuard) {
        semantics.postCheck = true;
        semantics.guard = mk('post-check', 'origin verified only after the sensitive action', [], [
          'the origin check runs after the handler already acted on the message',
        ]);
      } else {
        const weakestGated = gated.length ? combineAll(gated[0].active) : null;
        semantics.guard = mk('none', weakestGated ? 'sensitive action reachable without an origin check' : '(no origin-derived condition)', [], [
          weakestGated
            ? 'at least one sensitive action runs without being gated by the origin check'
            : semantics.readsOrigin
              ? 'origin is read but never gates the sensitive action'
              : 'the handler acts on the message without reading event.origin',
        ]);
      }
    } else {
      // Every sink sits behind a predicate: the effective guard is their
      // conjunction, and it is only as strong as its weakest predicate.
      const perSink = sinkVisits.map((v) => combineAll(v.active));
      semantics.guard = combineAll(perSink);
    }
  } else {
    // No recognised static sink. The handler may only reply, delegate or call
    // page-specific functions. Guards that gate the code following them, or
    // that gate any branch, still describe how the message is validated.
    if (endActive.length) {
      semantics.guard = combineAll(endActive);
    } else if (gatedActions.length) {
      // Union of predicates guarding branches; the weakest decides.
      const all = dedupe(gatedActions.flatMap((g) => g.active));
      semantics.guard = combineAll(all);
    } else {
      semantics.guard = null;
    }
  }

  // Runtime origin comparisons resolve operands that static analysis could not:
  // `origin.startsWith(allowed)` where `allowed` is a runtime config value.
  if (semantics.guard && (semantics.guard.verdict === 'unknown' || semantics.guard.verdict === 'none') &&
      opts.runtimeOriginCompares && opts.runtimeOriginCompares.length) {
    const refined = refineWithRuntimeCompares(opts.runtimeOriginCompares, semantics.guard.evidence);
    if (refined) {
      semantics.guard = refined;
      semantics.predicates.push(refined);
      notes.push('origin compared against a runtime value observed in the browser: ' + opts.runtimeOriginCompares.map((c) => c.method + '(' + c.operand + ')').join(', '));
    }
  }

  if (!semantics.guard) {
    // The handler reacts to the message but no origin-derived predicate gates
    // any of its behaviour.
    semantics.guard = mk('none', '(no origin-derived condition)', [], [
      semantics.readsOrigin
        ? 'origin is read but never used in a condition that gates the handler'
        : 'the handler never reads event.origin',
    ]);
  }

  return semantics;
}

function codeOf(source: string, node: any): string {
  return source.slice(node.start, node.end);
}

/** Analyze a standalone origin-validation function (used for recursive helpers). */
export function analyzeOriginLogic(source: string, opts: AnalyzeOptions & { argPassed?: 'event' | 'origin' }): HandlerSemantics {
  const sem = analyzeHandler(source, opts);
  return sem;
}
