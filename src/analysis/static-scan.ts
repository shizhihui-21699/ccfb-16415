/**
 * Listening-point discovery in static source text.
 *
 * Three complementary sources of truth feed the inventory:
 *   1. Runtime capture (assets/wma-core.js) — catches constructs the parser
 *      cannot see, e.g. listeners inside eval'd strings or inside a framework.
 *   2. This module — AST-based discovery over fetched scripts and inline code.
 *      Works on minified code because it is syntax-, not name-, driven.
 *   3. DOM scan — searches HTML for inline `onmessage=` handlers.
 *
 * The static pass additionally extracts, per listener, the origin-validation
 * expression it contains, which the semantic analyser then grades.
 */
import { parse } from 'acorn';
import * as walk from 'acorn-walk';
import { parse as looseParse } from 'acorn-loose';

export interface SourceUnit {
  url: string;
  /** Raw text as loaded by the browser. */
  code: string;
  /** Optional source map providing original positions. */
  mapUrl?: string;
  /** Inline <script> blocks get a synthetic url like `page#inline-3`. */
  inline?: boolean;
  /** True when content-type suggests a bundle rather than an app script. */
  minified?: boolean;
}

export interface StaticListener {
  id: string;
  unitUrl: string;
  /** Approximate position; over-approximate for minified bundles. */
  line: number;
  column: number;
  /** `addEventListener` | `onmessage` | `port` | `jQuery` | `dynamic` */
  kind: string;
  eventType: string;
  targetExpr: string | null;
  /** Function source text (truncated by the caller if needed). */
  handlerSource: string;
  /** AST node range in the unit. */
  start: number;
  end: number;
  /** Detection confidence: 1 = explicit syntax, 0.5 = heuristic. */
  confidence: number;
  /** Origin checks found inside the handler. */
  checks: StaticOriginCheck[];
  /** Source-map-resolved position, when available. */
  original?: { url: string; line: number; column: number; name?: string };
}

export interface StaticOriginCheck {
  /** Guard expression as written, e.g. `e.origin !== "https://a.com"`. */
  expression: string;
  /** Kind of property read: origin | source | none. */
  subject: 'origin' | 'source' | 'other';
  /** Single string operand(s) extracted from the comparison. */
  literals: string[];
  start: number;
  end: number;
  /** True when the guard is inside an early-return style rejected branch. */
  polarity: 'allow-list' | 'deny-list' | 'unknown';
}

export interface StaticScanResult {
  unitUrl: string;
  listeners: StaticListener[];
  parseErrors: { message: string; line?: number }[];
  /** Free-floating strings that look like origins and appear near listeners. */
  candidateOrigins: string[];
  /** Detect whether handler code was reached through a non-obvious indirection. */
  dynamicRegistrations: number;
}

const EVENT_NAMES = new Set(['message', 'messageerror', 'MessageEvent']);

/** Get a source slice safely. */
function slice(code: string, start: number, end: number, max = 20000): string {
  return code.slice(start, Math.min(end, start + max));
}

function propName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'PrivateIdentifier') return '#' + node.name;
  return null;
}

function isStringLiteral(node: any): boolean {
  return node && node.type === 'Literal' && typeof node.value === 'string';
}

function literalStrings(node: any, out: string[], depth = 0): void {
  if (!node || depth > 4) return;
  if (isStringLiteral(node)) {
    out.push(node.value);
    return;
  }
  if (node.type === 'TemplateLiteral') {
    for (const q of node.quasis) out.push(q.value.cooked || q.value.raw);
    return;
  }
  if (node.type === 'BinaryExpression') {
    literalStrings(node.left, out, depth + 1);
    literalStrings(node.right, out, depth + 1);
    return;
  }
  if (node.type === 'LogicalExpression') {
    literalStrings(node.left, out, depth + 1);
    literalStrings(node.right, out, depth + 1);
    return;
  }
  if (node.type === 'UnaryExpression' && node.operator === '!') {
    literalStrings(node.argument, out, depth + 1);
    return;
  }
  if (node.type === 'CallExpression') {
    for (const a of node.arguments) literalStrings(a, out, depth + 1);
    return;
  }
  if (node.type === 'ConditionalExpression') {
    literalStrings(node.consequent, out, depth + 1);
    literalStrings(node.alternate, out, depth + 1);
  }
}

function mentionsOriginProperty(node: any): boolean {
  if (!node || typeof node !== 'object') return false;
  let found = false;
  walk.simple(node, {
    MemberExpression(n: any) {
      const p = propName(n.property);
      if (p === 'origin' || p === 'referrer' || p === 'source') found = true;
    },
    Identifier(n: any) {
      if (n.name === 'origin' || n.name === 'originWhitelist' || n.name === 'allowedOrigins') found = true;
    },
  });
  return found;
}

function nearestFunction(node: any, ancestors: any[]): any {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const n = ancestors[i];
    if (
      n &&
      (n.type === 'FunctionDeclaration' ||
        n.type === 'FunctionExpression' ||
        n.type === 'ArrowFunctionExpression')
    ) {
      return n;
    }
  }
  return null;
}

interface WalkContext {
  ancestors: any[];
}

/**
 * Find origin checks in a handler. Heuristic by design: any comparison or
 * string test that mentions `.origin` is a candidate, and the semantic layer
 * decides whether it is a real guard.
 */
function extractChecks(code: string, handlerNode: any, paramNames: string[]): StaticOriginCheck[] {
  const checks: StaticOriginCheck[] = [];
  const seen = new Set<string>();

  function report(node: any, subject: 'origin' | 'source' | 'other') {
    const key = node.start + ':' + node.end;
    if (seen.has(key)) return;
    seen.add(key);
    // A comparison is interesting only if it mentions origin/source somewhere.
    const literals: string[] = [];
    literalStrings(node, literals);
    let polarity: StaticOriginCheck['polarity'] = 'unknown';
    const text = slice(code, node.start, node.end, 4000);
    if (/^\s*if\s*\(/.test(text) || node.type === 'IfStatement') {
      // allow-list: if (origin !== X) return ... / if (!allowed.includes(origin)) return
      if (/!==|!=\b|indexOf\([^)]*\)\s*[<>=!]|includes\(|startsWith\(|endsWith\(/.test(text)) polarity = 'allow-list';
      if (/===(?!.*!==)|==\b/.test(text) && !/!==/.test(text)) polarity = 'deny-list';
    }
    checks.push({
      expression: text.length > 400 ? text.slice(0, 400) + '…' : text,
      subject,
      literals: Array.from(new Set(literals)).filter((s) => s.includes('.') || s.includes('://') || s === '*'),
      start: node.start,
      end: node.end,
      polarity,
    });
  }

  try {
    walk.simple(handlerNode, {
      IfStatement(n: any) {
        if (mentionsOriginProperty(n.test)) report(n.test, 'origin');
      },
      ExpressionStatement(n: any) {
        // `if (a !== b) return;` covers most, but also `origin !== X && ...`
        if (mentionsOriginProperty(n.expression)) {
          const t = n.expression;
          if (t.type === 'CallExpression' || t.type === 'BinaryExpression' || t.type === 'LogicalExpression') {
            report(t, 'origin');
          }
        }
      },
      CallExpression(n: any) {
        // e.g. checkOrigin(e) — record the call; the semantic layer resolves it.
        const name = n.callee && (n.callee.name || propName(n.callee.property));
        if (name && /origin|whitelist|allowlist|allow|trusted|verify|check|valid|isvalid/i.test(String(name))) {
          report(n, 'origin');
        }
      },
      VariableDeclarator(n: any) {
        // var ok = e.origin === 'https://x'; used later in an if
        if (n.init && mentionsOriginProperty(n.init)) report(n.init, 'origin');
      },
      ReturnStatement(n: any) {
        if (n.argument && mentionsOriginProperty(n.argument)) report(n.argument, 'origin');
      },
      AssignmentExpression(n: any) {
        if (n.right && mentionsOriginProperty(n.right)) report(n.right, 'origin');
      },
    });
  } catch {
    /* malformed handler node: keep whatever was found */
  }
  return checks;
}

function handlerNodeOf(arg: any): any {
  if (!arg) return null;
  // inline function / arrow
  if (
    arg.type === 'FunctionExpression' ||
    arg.type === 'ArrowFunctionExpression' ||
    arg.type === 'FunctionDeclaration'
  ) {
    return { node: arg, inline: true };
  }
  // identifier: the handler body is resolved separately by identifier lookup
  if (arg.type === 'Identifier') return { node: arg, inline: false, name: arg.name };
  // .bind(this)
  if (arg.type === 'CallExpression' && propName(arg.callee?.property) === 'bind') {
    return handlerNodeOf(arg.callee.object);
  }
  // object with handleEvent: { handleEvent: fn }
  if (arg.type === 'ObjectExpression') {
    for (const p of arg.properties) {
      if (p.type === 'Property' && propName(p.key) === 'handleEvent') {
        return { node: p.value, inline: true, objectListener: true };
      }
    }
  }
  return null;
}

/**
 * Parses one source unit and returns discovered message listeners.
 */
export function scanUnit(unit: SourceUnit, opts: { loose?: boolean } = {}): StaticScanResult {
  const listeners: StaticListener[] = [];
  const parseErrors: { message: string; line?: number }[] = [];
  const candidateOrigins = new Set<string>();
  let dynamicRegistrations = 0;

  let ast: any;
  try {
    ast = parse(unit.code, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      allowHashBang: true,
      locations: true,
      allowReturnOutsideFunction: true,
    });
  } catch (e: any) {
    parseErrors.push({ message: String(e.message || e), line: e.loc?.line });
    if (opts.loose === false) {
      return { unitUrl: unit.url, listeners, parseErrors, candidateOrigins: [], dynamicRegistrations };
    }
    try {
      ast = looseParse(unit.code, { ecmaVersion: 'latest', locations: true });
    } catch (e2: any) {
      parseErrors.push({ message: 'loose: ' + String(e2.message || e2) });
      return { unitUrl: unit.url, listeners, parseErrors, candidateOrigins: [], dynamicRegistrations };
    }
  }

  // Index top-level function declarations and var-declared function expressions
  // so a named handler can be located when registration uses an identifier.
  const declaredFns = new Map<string, any>();
  walk.simple(ast, {
    FunctionDeclaration(n: any) {
      if (n.id?.name) declaredFns.set(n.id.name, n);
    },
    VariableDeclarator(n: any) {
      if (n.id?.type === 'Identifier' && n.init) {
        if (n.init.type === 'FunctionExpression' || n.init.type === 'ArrowFunctionExpression') {
          declaredFns.set(n.id.name, n.init);
        }
      }
    },
    AssignmentExpression(n: any) {
      if (n.left?.type === 'Identifier' && n.right) {
        if (n.right.type === 'FunctionExpression' || n.right.type === 'ArrowFunctionExpression') {
          declaredFns.set(n.left.name, n.right);
        }
      }
    },
  });

  let counter = 0;
  const ancestors: any[] = [];

  function addListener(params: {
    kind: string;
    eventType: string;
    targetExpr: string | null;
    node: any;
    handler: any;
    handlerSource: string;
    start: number;
    end: number;
    confidence: number;
    paramNames: string[];
  }) {
    const id = `${unit.url}#s${++counter}`;
    const checks = params.handler ? extractChecks(unit.code, params.handler, params.paramNames) : [];
    for (const c of checks) for (const l of c.literals) candidateOrigins.add(l);
    const loc = params.node.loc?.start || { line: 1, column: 0 };
    listeners.push({
      id,
      unitUrl: unit.url,
      line: loc.line,
      column: loc.column,
      kind: params.kind,
      eventType: params.eventType,
      targetExpr: params.targetExpr,
      handlerSource: params.handlerSource,
      start: params.start,
      end: params.end,
      confidence: params.confidence,
      checks,
    });
  }

  try {
    walk.ancestor(ast, {
      CallExpression(node: any, _state: any, ancestorsHere: any[]) {
        const callee = node.callee;
        const name = callee?.type === 'MemberExpression' ? propName(callee.property) : callee?.name;
        if (!name) return;
        const args = node.arguments;

        // --------------------------------------------------- addEventListener
        if (name === 'addEventListener' || name === 'addListener' || name === 'on' || name === 'bind') {
          const typeArg = args[0];
          let eventType: string | null = null;
          if (isStringLiteral(typeArg)) eventType = typeArg.value;
          if (!eventType) {
            // jQuery `.on('message', ...)` covers it; anything else is dynamic
            if (name !== 'addEventListener' && name !== 'addListener') {
              // could be custom emitter; low confidence
              if (args.length >= 2) dynamicRegistrations++;
            }
            return;
          }
          if (!EVENT_NAMES.has(eventType) && eventType !== 'message') {
            if (eventType !== 'message') return;
          }
          if (eventType !== 'message' && eventType !== 'messageerror') return;

          const targetExprSource =
            callee.type === 'MemberExpression' ? slice(unit.code, callee.object.start, callee.object.end, 200) : null;
          const handlerArg = args[1];
          const found = handlerNodeOf(handlerArg);
          let handlerNode = null;
          let handlerSource = '';
          let inline = false;
          const paramNames: string[] = [];
          if (found) {
            if (found.inline) {
              handlerNode = found.node;
              inline = true;
            } else if (found.name && declaredFns.has(found.name)) {
              handlerNode = declaredFns.get(found.name);
            } else if (found.name) {
              dynamicRegistrations++;
            }
          }
          if (handlerNode) {
            handlerSource = slice(unit.code, handlerNode.start, handlerNode.end, 8000);
            const p0 = handlerNode.params?.[0];
            if (p0) {
              if (p0.type === 'Identifier') paramNames.push(p0.name);
              else if (p0.type === 'AssignmentPattern' && p0.left?.type === 'Identifier') paramNames.push(p0.left.name);
            }
          } else if (handlerArg) {
            handlerSource = slice(unit.code, handlerArg.start, handlerArg.end, 800);
          }
          addListener({
            kind: name === 'addEventListener' || name === 'addListener' ? 'addEventListener' : 'custom',
            eventType,
            targetExpr: targetExprSource,
            node,
            handler: handlerNode,
            handlerSource,
            start: node.start,
            end: node.end,
            confidence: handlerNode ? 1 : handlerArg ? 0.6 : 0.4,
            paramNames,
          });
          return;
        }

        // -------------------------------------------------------- window.onX =
        // handled under AssignmentExpression below
        // ---------------------------------------------------- MessagePort.start
        if (name === 'start' && callee.type === 'MemberExpression') {
          // port.addEventListener('message') already caught; nothing to add
        }
      },

      AssignmentExpression(node: any, _state: any, ancestorsHere: any[]) {
        const left = node.left;
        if (left?.type !== 'MemberExpression') return;
        const prop = propName(left.property);
        if (prop !== 'onmessage' && prop !== 'onmessageerror') return;
        const targetExprSource = slice(unit.code, left.object.start, left.object.end, 200);
        const handlerNode = handlerNodeOf(node.right)?.node || null;
        const paramNames: string[] = [];
        if (handlerNode?.params?.[0]?.type === 'Identifier') paramNames.push(handlerNode.params[0].name);
        addListener({
          kind: 'onmessage',
          eventType: prop === 'onmessage' ? 'message' : 'messageerror',
          targetExpr: targetExprSource,
          node,
          handler: handlerNode,
          handlerSource: handlerNode ? slice(unit.code, handlerNode.start, handlerNode.end, 8000) : slice(unit.code, node.right.start, node.right.end, 800),
          start: node.start,
          end: node.end,
          confidence: 1,
          paramNames,
        });
      },
    });
  } catch (e: any) {
    parseErrors.push({ message: 'walk: ' + String(e.message || e) });
  }

  return {
    unitUrl: unit.url,
    listeners,
    parseErrors,
    candidateOrigins: Array.from(candidateOrigins),
    dynamicRegistrations,
  };
}

/**
 * Scan inline `onmessage="..."` attributes and `<script>` blocks in HTML.
 * Inline scripts are returned as units so the caller can feed them to scanUnit;
 * inline attributes are reported directly.
 */
export function scanHtml(html: string, pageUrl: string): { units: SourceUnit[]; attributeListeners: StaticListener[] } {
  const units: SourceUnit[] = [];
  const attributeListeners: StaticListener[] = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  let idx = 0;
  while ((m = scriptRe.exec(html))) {
    const attrs = m[1];
    if (/\bsrc\s*=/.test(attrs)) continue;
    const typeMatch = /type\s*=\s*["']?([^"'\s>]+)/i.exec(attrs);
    const type = typeMatch ? typeMatch[1].toLowerCase() : '';
    if (type && !/javascript|module|ecmascript|babel|jsx/.test(type)) continue;
    const code = m[2];
    if (!/\bmessage\b|\bonmessage\b/.test(code)) {
      idx++;
      continue;
    }
    units.push({
      url: `${pageUrl}#inline-${idx}`,
      code,
      inline: true,
    });
    idx++;
  }

  // onmessage attributes on the <html>/<body>/<iframe> tags
  const attrRe = /\bon(message|messageerror)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let a: RegExpExecArray | null;
  while ((a = attrRe.exec(html))) {
    const code = a[3] ?? a[4] ?? a[5] ?? '';
    attributeListeners.push({
      id: `${pageUrl}#attr-${attributeListeners.length}`,
      unitUrl: pageUrl,
      line: lineOf(html, a.index),
      column: 0,
      kind: 'onmessage-attribute',
      eventType: 'message',
      targetExpr: 'window',
      handlerSource: code,
      start: a.index,
      end: a.index + a[0].length,
      confidence: 1,
      checks: [],
    });
  }

  return { units, attributeListeners };
}

export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}
