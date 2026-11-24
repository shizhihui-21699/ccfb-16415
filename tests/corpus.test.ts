/**
 * Corpus integration test.
 *
 * Runs the complete pipeline against the fixture corpus and asserts the tool's
 * detection behaviour, including the negative control (a correctly written page
 * must not produce a critical/high finding). These run a real Chromium, so they
 * are slower than the unit tests; each case is bounded.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/scan.ts';
import type { ScanReport } from '../src/report/types.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function scanFixture(dir: string, host = 'https://target.corp.test/'): Promise<ScanReport> {
  return runScan({
    url: host,
    serveDir: path.join(ROOT, 'corpus', dir),
    attackerOrigin: 'https://attacker.evil.test',
    headless: true,
    messagesPerTarget: 16,
    channels: ['iframe'],
    timeoutMs: 15000,
  });
}

function byVerdict(r: ScanReport) {
  return {
    critical: r.findings.filter((f) => f.severity === 'critical'),
    high: r.findings.filter((f) => f.severity === 'high'),
    confirmed: r.findings.filter((f) => f.verdict === 'exploited'),
    all: r.findings,
  };
}

test('payment widget: prefix bypass and unguarded onmessage yield script execution', { timeout: 120000 }, async () => {
  const r = await scanFixture('pay-popup');
  const v = byVerdict(r);
  assert.ok(r.stats.listenersDiscovered >= 3, 'should discover all three listeners');
  assert.ok(v.critical.length >= 2, 'expected at least two critical findings, got: ' + JSON.stringify(v.all.map((f) => [f.id, f.severity, f.validation.verdict])));
  assert.ok(v.critical.some((f) => f.impact.canaryExecuted), 'at least one finding must prove script execution');
  // The prefix bypass must actually be tagged as weak validation.
  assert.ok(v.critical.some((f) => f.validation.verdict === 'weak'), 'prefix check should be classified weak');
});

test('support chat: startsWith bypass reaches insertAdjacentHTML', { timeout: 120000 }, async () => {
  const r = await scanFixture('embedded-chat', 'https://chat.corp.test/');
  const v = byVerdict(r);
  assert.ok(v.critical.length >= 1, 'expected a critical finding');
  const c = v.critical[0]!;
  assert.equal(c.validation.verdict, 'weak');
  assert.ok(c.impact.canaryExecuted, 'script execution should be confirmed');
});

test('visual editor: regex anchor defect and source-identity check are exploitable', { timeout: 150000 }, async () => {
  const r = await scanFixture('visual-editor', 'https://ed.corp.test/');
  const v = byVerdict(r);
  const verdicts = v.all.map((f) => f.validation.verdict);
  assert.ok(verdicts.includes('strong'), 'the exact allow-list listener must be recognised as strong');
  assert.ok(verdicts.includes('weak'), 'the unanchored regex must be classified weak');
  assert.ok(verdicts.includes('source-based'), 'the event.source check must be classified source-based');
  assert.ok(v.critical.length >= 2, 'expected two critical findings, got: ' + JSON.stringify(v.all.map((f) => [f.id, f.severity, f.validation.verdict])));
  // The correctly written listener must not be reported as exploitable.
  const strongFinding = v.all.find((f) => f.validation.verdict === 'strong');
  assert.ok(strongFinding);
  assert.notEqual(strongFinding!.severity, 'critical');
});

test('oauth bridge: navigation and deny-list are detected', { timeout: 120000 }, async () => {
  const r = await scanFixture('oauth-sso', 'https://sso.corp.test/');
  const v = byVerdict(r);
  assert.ok(v.all.some((f) => f.validation.verdict === 'deny-list'), 'deny-list must be identified');
  assert.ok(v.all.some((f) => f.validation.verdict === 'none'), 'unguarded handler must be identified');
  // A location sink reachable from an attacker origin is at least high.
  assert.ok(v.high.length + v.critical.length >= 1, 'expected a navigation-class finding');
});

test('hardened page: no critical or high false positives', { timeout: 120000 }, async () => {
  const r = await scanFixture('hardened', 'https://hardened.corp.test/');
  const v = byVerdict(r);
  assert.equal(v.critical.length, 0, 'correct code must not be critical');
  assert.equal(v.high.length, 0, 'correct code must not be high');
  const strong = v.all.filter((f) => f.validation.verdict === 'strong');
  assert.ok(strong.length >= 1, 'the Set allow-list must be recognised as strong');
});

test('report is well-formed and SARIF is valid', { timeout: 60000 }, async () => {
  const r = await scanFixture('pay-popup');
  assert.equal(r.tool, 'postmsg-audit');
  assert.ok(r.stats.candidates >= r.stats.listenersDiscovered);
  const { toSarif } = await import('../src/report/writers.ts');
  const sarif = toSarif(r);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs[0].results));
  for (const res of sarif.runs[0].results) {
    assert.ok(res.ruleId);
    assert.ok(['error', 'warning', 'note'].includes(res.level));
    assert.ok(res.locations[0].physicalLocation.artifactLocation.uri);
  }
});

test('minified bundle: exploit confirmed and reported at the source-mapped position', { timeout: 120000 }, async () => {
  const r = await scanFixture('minified-bundle', 'https://bundle.corp.test/');
  const v = byVerdict(r);
  assert.ok(v.critical.length >= 1, 'minified handler must still be exploited');
  const f = v.critical[0]!;
  assert.ok(f.impact.canaryExecuted);
  assert.ok(f.handler.original, 'a resolved source-map position must be attached');
  assert.match(f.handler.original!.url, /app\.original\.js$/);
  assert.equal(f.handler.original!.line, 6);
});

test('framework SDK: runtime-only origin operand is recovered and bypassed', { timeout: 120000 }, async () => {
  const r = await scanFixture('framework-widget', 'https://fw.corp.test/');
  const f = r.findings.find((x) => /WidgetSDK/.test(x.handler.name)) || r.findings[0];
  assert.ok(f, 'the SDK-registered listener must be discovered even though the host never calls addEventListener');
  // The origin constant lives in SDK options, so only a runtime observation can
  // resolve it; the tool must still end up with a weak verdict and a bypass origin.
  assert.equal(f!.validation.verdict, 'weak', 'must classify the config-driven startsWith as weak');
  const senders = (f!.proof?.attempts || []).map((a) => a.senderOrigin).filter(Boolean) as string[];
  assert.ok(
    senders.some((o) => o !== r.options.attackerOrigin),
    'a synthesised bypass origin must have been used for delivery'
  );
});
