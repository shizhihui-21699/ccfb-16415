import { test } from 'node:test';
import assert from 'node:assert/strict';
import { synthesizeBypassOrigins } from '../src/probe/bypass.ts';
import { analyzeHandler } from '../src/analysis/origin-check.ts';

function originsFor(src: string): string[] {
  const sem = analyzeHandler(src);
  return synthesizeBypassOrigins(sem.guard, sem.guard?.verdict || 'none').map((o) => o.origin);
}

/** Does a real browser origin string satisfy the same check, replayed in JS? */
function checkPasses(src: string, origin: string): boolean {
  // Extract the handler's guard as a function of the event and run it with a
  // real origin; weaker but independent of the synthesiser's own logic.
  const sem = analyzeHandler(src);
  const evidence = sem.guard?.evidence || '';
  const ev = { origin, data: {} };
  try {
    if (/startsWith/.test(evidence)) {
      const p = /startsWith\(\s*['"`]([^'"`]+)/.exec(evidence);
      return p ? origin.startsWith(p[1]!) : false;
    }
    if (/endsWith/.test(evidence)) {
      const p = /endsWith\(\s*['"`]([^'"`]+)/.exec(evidence);
      return p ? origin.endsWith(p[1]!) : false;
    }
    if (/indexOf|includes/.test(evidence)) {
      const p = /(?:indexOf|includes)\(\s*['"`]([^'"`]+)/.exec(evidence);
      return p ? origin.includes(p[1]!) : false;
    }
  } catch {
    return false;
  }
  return false;
}

test('startsWith bypass origin passes the check and differs from the target', () => {
  const src = `function h(e){ if (!e.origin.startsWith('https://pay.example.com')) return; go(); }`;
  const origins = originsFor(src);
  assert.ok(origins.length > 0);
  const passing = origins.filter((o) => checkPasses(src, o));
  assert.ok(passing.length > 0, 'expected a synthesised origin that startsWith the prefix: ' + origins.join(', '));
  assert.ok(passing.every((o) => o !== 'https://pay.example.com'));
});

test('substring bypass origin embeds the needle', () => {
  const src = `function h(e){ if (e.origin.indexOf('example.com') === -1) return; go(); }`;
  const origins = originsFor(src);
  assert.ok(origins.some((o) => checkPasses(src, o)), origins.join(', '));
});

test('regex with unescaped dot and no anchor yields a passing origin', () => {
  const src = `function h(e){ if (!/^https:\\/\\/example.com/.test(e.origin)) return; go(); }`;
  const sem = analyzeHandler(src);
  assert.equal(sem.guard?.verdict, 'weak');
  const origins = originsFor(src);
  // /^https:\/\/example.com/ accepts https://exampleXcom...
  const matching = origins.filter((o) => /^https:\/\/example.com/.test(o));
  assert.ok(matching.length > 0, 'alt: ' + origins.join(', '));
  assert.ok(origins.some((o) => o !== 'https://example.com'));
});

test('deny-list offers a fresh origin', () => {
  const src = `function h(e){ if (e.origin === 'https://known-bad.example') return; go(); }`;
  const origins = originsFor(src);
  assert.ok(origins.length > 0);
  assert.ok(origins.every((o) => o !== 'https://known-bad.example'));
});

test('data-based check yields baseline attacker origin', () => {
  const src = `function h(e){ if (e.data.token !== 'x') return; go(); }`;
  const origins = originsFor(src);
  assert.ok(origins.length > 0);
});

test('every synthesised origin is a syntactically valid http(s) origin', () => {
  const cases = [
    `function h(e){ if (!e.origin.startsWith('https://a.example.com')) return; }`,
    `function h(e){ if (e.origin.indexOf('a.example.com') === -1) return; }`,
    `function h(e){ if (!/^https:\\/\\/a\\.example\\.com/.test(e.origin)) return; }`,
  ];
  for (const src of cases) {
    for (const o of originsFor(src)) {
      const u = new URL(o);
      assert.match(u.protocol, /^https?:$/);
      assert.ok(u.hostname.length > 0);
    }
  }
});
