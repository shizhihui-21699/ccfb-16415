import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inferStaticSchema, materializeTemplates, mergeRuntimeSchema } from '../src/analysis/message-schema.ts';

test('discriminator branch becomes a template', () => {
  const s = inferStaticSchema(`function h(e){ if(e.data.type === 'PAY'){ if(e.data.payload.amount > 0){ pay(e.data.payload); } } }`);
  assert.ok(s.discriminators.find((d) => d.path === 'type' && d.values.includes('PAY')));
  const t = materializeTemplates(s, [], 50);
  assert.ok(t.some((x) => x.type === 'PAY' && x.payload && x.payload.amount === 1));
});

test('switch statement values are enumerated', () => {
  const s = inferStaticSchema(`function h(e){ switch(e.data.cmd){ case 'open': a(); break; case 'close': b(); break; } }`);
  const d = s.discriminators.find((x) => x.path === 'cmd');
  assert.ok(d);
  assert.deepEqual(new Set(d!.values), new Set(['open', 'close']));
});

test('prefix constraint produces matching value', () => {
  const s = inferStaticSchema(`function h(e){ if (e.data.action.startsWith('nav:')) go(e.data); }`);
  const t = materializeTemplates(s, [], 10);
  assert.ok(t.some((x) => typeof x.action === 'string' && x.action.startsWith('nav:')));
});

test('allow-list one-of yields each value', () => {
  const s = inferStaticSchema(`function h(e){ const ok=['a','b']; if(ok.includes(e.data.kind)) go(); }`);
  const t = materializeTemplates(s, [], 30);
  assert.ok(t.some((x) => x.kind === 'a'));
  assert.ok(t.some((x) => x.kind === 'b'));
});

test('runtime reads add fields', () => {
  const s = inferStaticSchema(`function h(e){ go(e.data); }`);
  mergeRuntimeSchema(s, { 'widget.mode': { n: 2, sample: { t: 'string', v: 'inbox' } } }, []);
  assert.ok(s.fields.find((f) => f.path === 'widget.mode'));
});

test('protocol samples from the page are included verbatim', () => {
  const s = inferStaticSchema(`function h(e){ handle(e.data); }`);
  const t = materializeTemplates(s, [{ type: 'hello', v: 2 }], 50);
  assert.ok(t.some((x) => x.type === 'hello' && x.v === 2));
});

test('origin fields are not treated as schema inputs', () => {
  const s = inferStaticSchema(`function h(e){ if (e.origin !== 'https://a.com') return; if (e.data.origin) go(); }`);
  assert.ok(!s.fields.find((f) => f.path === 'origin'));
});

test('nested objects imply parent presence', () => {
  const s = inferStaticSchema(`function h(e){ use(e.data.a.b.c); }`);
  assert.ok(s.fields.find((f) => f.path === 'a'));
  assert.ok(s.fields.find((f) => f.path === 'a.b'));
});
