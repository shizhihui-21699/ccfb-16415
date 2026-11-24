import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHandler } from '../src/analysis/origin-check.ts';

function guard(src: string, opts = {}) {
  return analyzeHandler(src, opts).guard;
}

test('no check at all -> none', () => {
  const g = guard(`function h(e){ document.getElementById('x').innerHTML = e.data.html; }`);
  assert.equal(g?.verdict, 'none');
});

test('exact allow-list via early return -> strong', () => {
  const g = guard(`function h(e){ if (e.origin !== 'https://pay.example.com') return; go(); }`);
  assert.equal(g?.verdict, 'strong');
  assert.deepEqual(g?.allowedOrigins, ['https://pay.example.com']);
});

test('array allow-list includes -> strong', () => {
  const g = guard(`function h(e){ const OK=['https://a.com','https://b.com']; if (!OK.includes(e.origin)) return; go(e.data); }`);
  assert.equal(g?.verdict, 'strong');
  assert.deepEqual(new Set(g?.allowedOrigins), new Set(['https://a.com', 'https://b.com']));
});

test('startsWith prefix bypass -> weak', () => {
  const g = guard(`function h(e){ if (e.origin.startsWith('https://pay.example.com')) go(); }`);
  assert.equal(g?.verdict, 'weak');
  assert.match(g!.weaknesses.join(' '), /startsWith/);
});

test('endsWith suffix bypass -> weak', () => {
  const g = guard(`function h(e){ if (!e.origin.endsWith('.example.com')) return; go(); }`);
  assert.equal(g?.verdict, 'weak');
});

test('indexOf substring bypass -> weak', () => {
  const g = guard(`function h(e){ if (e.origin.indexOf('example.com') === -1) return; go(); }`);
  assert.equal(g?.verdict, 'weak');
});

test('includes substring bypass -> weak', () => {
  const g = guard(`function h(e){ if (!e.origin.includes('example.com')) return; go(); }`);
  assert.equal(g?.verdict, 'weak');
});

test('unescaped-dot regex -> weak', () => {
  const g = guard(`function h(e){ if (/^https:\\/\\/example.com/.test(e.origin)) go(); }`);
  assert.equal(g?.verdict, 'weak');
  assert.match(g!.weaknesses.join(' '), /dot|anchor/i);
});

test('deny-list only blocks one origin -> deny-list', () => {
  const g = guard(`function h(e){ if (e.origin === 'https://evil.example') return; go(); }`);
  assert.equal(g?.verdict, 'deny-list');
});

test('token in data -> data-based', () => {
  const g = guard(`function h(e){ if (e.data.token === 'SECRET') { go(); } }`);
  assert.equal(g?.verdict, 'data-based');
});

test('source identity is not an origin check -> source-based', () => {
  const g = guard(`function h(e){ if (e.source !== window.parent) return; go(); }`);
  assert.equal(g?.verdict, 'source-based');
});

test('same-origin comparison', () => {
  const g = guard(`function h(e){ if (e.origin !== location.origin) return; go(); }`);
  assert.equal(g?.verdict, 'same-origin');
});

test('guard after sink -> post-check', () => {
  const g = guard(`function h(e){ document.body.innerHTML = e.data.h; if (e.origin !== 'https://a.com') return; }`);
  assert.equal(g?.verdict, 'post-check');
});

test('short-circuit conjunction guard -> strong', () => {
  const g = guard(`function h(e){ e.origin === 'https://a.com' && run(e.data); }`);
  assert.equal(g?.verdict, 'strong');
});

test('nested branch is a real guard -> strong', () => {
  const g = guard(`function h(e){ if (e.origin === 'https://a.com') { document.body.innerHTML = e.data.x; } }`);
  assert.equal(g?.verdict, 'strong');
});

test('disjunction cannot be proven -> unknown', () => {
  const g = guard(`function h(e){ if (e.origin === 'https://a.com' || e.data.admin) { go(); } }`);
  assert.equal(g?.verdict, 'unknown');
});

test('delegated helper resolves to strong', () => {
  const helpers: Record<string, string> = {
    isTrustedOrigin: `function isTrustedOrigin(origin) { return origin === 'https://trusted.example'; }`,
  };
  const g = guard(
    `function h(e){ if (!isTrustedOrigin(e.origin)) return; go(); }`,
    { resolveHelper: (n: string) => helpers[n] ?? null }
  );
  assert.ok(g);
  assert.equal(g!.verdict, 'strong');
});

test('delegated helper that ignores origin -> unknown', () => {
  const helpers: Record<string, string> = {
    checkOrigin: `function checkOrigin(x) { return true; }`,
  };
  const g = guard(`function h(e){ if (!checkOrigin(e)) return; go(); }`, {
    resolveHelper: (n: string) => helpers[n] ?? null,
  });
  assert.equal(g!.verdict, 'unknown');
});

test('data fields are extracted for probe schema', () => {
  const sem = analyzeHandler(`function h(e){ if (e.origin !== 'https://a.com') return; const m = e.data.payload; use(m.type, m.value); }`);
  assert.ok(sem.dataFields.includes('payload'));
});

test('wildcard outbound response detected', () => {
  const sem = analyzeHandler(`function h(e){ e.source.postMessage({ok:1}, '*'); }`);
  assert.equal(sem.wildcardOutbound, true);
});

test('param name is honoured', () => {
  const g = guard(`function h(evt){ if (evt.origin !== 'https://a.com') return; go(); }`, { paramNames: ['evt'] });
  assert.equal(g?.verdict, 'strong');
});

test('minified-style short names still work', () => {
  const g = guard(`function(a){if("https://app.corp.com"!==a.origin)return;b(a.data)}`);
  assert.equal(g?.verdict, 'strong');
});
