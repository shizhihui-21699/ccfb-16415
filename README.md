# postmsg-audit

An automated detector for **cross-window message (`postMessage`) vulnerabilities**.
It loads a page in a real Chromium, discovers every message listener, grades the
origin-validation logic inside each handler, and then **proves exploitability by
delivering genuine cross-origin messages** from an attacker-controlled origin and
observing what the page actually does with them.

> 一个针对跨窗口消息处理漏洞的自动化检测工具:在浏览器里自动找出所有消息监听点,
> 分析其来源校验逻辑,并构造真实跨源消息验证可利用性。

Node 20+ · TypeScript · Playwright (Chromium). No build step required for the
Python-free CLI — `tsx src/cli.ts` runs the sources directly.

---

## Why this is hard, and how the tool answers it

The three difficulties named in the problem statement each map to a layer of the
tool.

| Difficulty | Where it is handled |
|---|---|
| **Handlers are minified / obfuscated** | `src/browser/page-model.ts` captures *every* listener at runtime from every frame (including SDK-registered ones the host never registers itself), and `src/analysis/source-maps.ts` resolves positions back to the original file through the script's source map. |
| **Origin checks that look right but are not** | `src/analysis/origin-check.ts` grades the check rather than detecting it: `strong` / `same-origin` / `weak` (substring, prefix, suffix, unanchored regex) / `deny-list` / `data-based` / `source-based` / `post-check` / `none` / `unknown`. Constants are resolved from the enclosing script, and runtime comparison operands are captured when static analysis cannot see them. |
| **Handlers need a specific message shape and page state** | `src/analysis/message-schema.ts` reconstructs each handler's expected message from the AST (discriminators, `switch` cases, equality/prefix/`one-of` constraints, truthiness), merges runtime property reads, and folds in protocol samples the page itself sends. `src/probe/verify.ts` then delivers schema-derived messages plus payload-bearing variants. |

## How exploitability is proven (not guessed)

A finding is only **confirmed** when three things line up:

1. **Real delivery** — the attacker page (served on an uncontrolled origin) frames
   or opens the target and calls `postMessage`, so `event.origin` is genuinely the
   attacker's. Synthetic `dispatchEvent(new MessageEvent(...))` is never used,
   because it tests a different code path and fabricates an origin.
2. **Attribution** — the instrumentation (`assets/wma-core.js`) routes every
   listener through a wrapper and attributes sinks to the handler that ran,
   *including across `setTimeout`/promise callbacks*, so an effect fired from a
   deferred callback is still tied to the message that caused it.
3. **Attacker-controlled effect** — a script-execution canary fires, or a
   dangerous sink / navigation / outbound request receives content derived from
   the probe. A weak check alone is reported as *weak validation*, never as a
   confirmed exploit.

### Bypassing weak checks with a correctly-shaped attacker origin

A prefix or substring check is only provably exploitable by an origin that
*passes it* while still being attacker-controlled. `src/probe/bypass.ts`
synthesises such origins from the check's own expression:

| Check the page wrote | Attacker origin the tool serves the harness on |
|---|---|
| `origin.startsWith('https://pay.example.com')` | `https://pay.example.com.wma-attacker.test` |
| `origin.indexOf('example.com') !== -1` | `https://example.com.wma-attacker.test` or `https://wma-attacker.test/?example.com` |
| `/^https:\/\/example.com/` (unescaped dots, no `$`) | `https://exampleXcomXwma-attacker.test` |
| `origin === location.origin`-style sibling | a longer host under the same labels |

The harness is served on that origin and the message is delivered from it, so a
passing delivery is real proof of the bypass, not an inference.

## What it finds

| Class | Example in the fixture corpus | Grading |
|---|---|---|
| Unguarded handler | `window.onmessage = …` with no origin test | high / critical if a sink is reachable |
| Prefix / substring bypass | `origin.indexOf(WIDGET_ORIGIN) !== 0` | critical when XSS is confirmed |
| Unanchored / unescaped regex | `/^https:\/\/app\.corp\.test/` | critical when XSS is confirmed |
| Deny-list | `if (origin === 'known-bad') return` | medium–high |
| Data-based auth | `if (data.token === 'SECRET')` | low–medium |
| Source-identity check | `if (e.source !== window.parent)` | high (an attacker-framed copy passes) |
| Post-check | origin checked after `innerHTML = …` | medium |
| Correct allow-list | `new Set([...]).has(e.origin)` | **not a finding** (reported as info) |

## Usage

```bash
# scan a live site
npx tsx src/cli.ts https://app.example.com/

# scan a local build
npx tsx src/cli.ts https://app.example.com/ --serve-dir ./dist

# report only, no live exploitation
npx tsx src/cli.ts https://app.example.com/ --analyze-only

# CI gate: fail if anything high or above is found
npx tsx src/cli.ts https://app.example.com/ --fail-on high --format sarif,json

# capture screenshots of confirmed findings
npx tsx src/cli.ts https://app.example.com/ --evidence -o out/
```

Outputs (default `wma-report/`): `report.json`, `report.html` (self-contained,
friend- and developer-readable), `report.sarif` (code scanning), `report.md`.

Key options: `--channels iframe,popup`, `--messages <n>` (budget per listener),
`--attacker-origin`, `--header`/`--cookie`/`--basic-auth`, `--min-severity`,
`--max-targets`, `--headed`, `--debug`.

### As a library

```ts
import { runScan } from './src/scan.js';
import { writeReports } from './src/report/writers.js';

const report = await runScan({ url: 'https://app.example.com/' });
await writeReports(report, { outDir: 'out', formats: ['json', 'html', 'sarif'] });
console.log(report.stats.bySeverity); // { critical, high, medium, low, info }
```

## Architecture

```
src/
  scan.ts                     orchestration: acquire → assemble → verify → report
  browser/page-model.ts       Chromium context, script capture, listener inventory
  analysis/
    static-scan.ts            AST discovery of message listeners + raw checks
    origin-check.ts           the semantic grader (the core of the tool)
    message-schema.ts         reconstruction of the expected message shape
    source-maps.ts            minified position → original source
  probe/
    attacker.ts               the attacker page served on an uncontrolled origin
    bypass.ts                 synthesise a passing-but-hostile origin per check
    candidates.ts             merge runtime + static listeners into targets
    probe-session.ts          real iframe/popup delivery + effect capture
    verify.ts                 per-target exploitation loop and judgement
  report/
    severity.ts               probe result → graded finding + remediation
    writers.ts                console / JSON / SARIF / HTML / Markdown
assets/
  wma-core.js                 in-page instrumentation (captures, attributes, traces)
  wma-sinks.js                sink hooks (eval, innerHTML, location, script src, …)
```

The instrumentation is injected as an init script into every frame before page
code runs. It wraps `addEventListener('message'|'messageerror')`, the
`window.onmessage` accessor and `MessagePort` accessors, records each handler's
source and registration stack, and tracks which event properties and data paths
each invocation reads. It also hooks the sinks that turn a message into a security
impact and propagates the invocation context through timers, microtasks and
property writes so effects stay attributable.

## Tests

```bash
npm run test:unit     # 36 unit tests: grader, schema inference, bypass synthesis
npm run test:corpus   # 8 end-to-end tests over the fixture corpus (real Chromium)
npm run build         # compile to dist/
```

The corpus (`corpus/`) contains a payment popup, an embedded chat widget, a
visual editor with a nested canvas frame, an OAuth bridge, a minified bundle with
a source map, a framework SDK that registers its own listener, and a **hardened
negative control** — the last one asserts that correctly written code produces no
critical or high findings.

## Honest limitations

- A handler whose required message shape depends on data flowing through an
  opaque cross-handler indirection (e.g. an SDK dispatcher forwarding `payload`
  into a callback in another file) may be classified `weak`/`none` but not driven
  to execution. The tool says so (`vulnerable-unconfirmed`, low confidence) rather
  than claiming an exploit.
- A strong, exactly-enforced allow-list of absolute origins cannot be bypassed by
  any origin a browser will produce; those handlers are reported as informational.
- Frames that block embedding (`X-Frame-Options: DENY`, `frame-ancestors`) cannot
  be reached through the iframe channel; the popup channel is then used.
- Live probing sends real messages to the target; run it against staging or a
  local build you own. Only use it on systems you are authorized to test.
