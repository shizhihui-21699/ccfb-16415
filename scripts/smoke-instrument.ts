import { chromium } from 'playwright';
import fs from 'node:fs';

const core = fs.readFileSync('assets/wma-core.js', 'utf8');
const sinks = fs.readFileSync('assets/wma-sinks.js', 'utf8');
const bundle = core + '\n' + sinks;

const html = `<!doctype html><meta charset=utf-8><body>
<div id=box></div>
<script>
window.onmessage = function(e) {
  if (e.origin !== 'https://trusted.example') return;
  document.getElementById('box').innerHTML = e.data.html;
};
addEventListener('message', function(ev) {
  if (!ev.origin.startsWith('https://pay.example')) return;
  setTimeout(() => { eval(ev.data.cmd); }, 10);
});
window.addEventListener('message', (e) => {
  if (e.data.cmd === 'go') { e.source.postMessage({ok:1}, '*'); }
});
</script></body>`;

const b = await chromium.launch();
const ctx = await b.newContext();
await ctx.route('**/*', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: html }));
await ctx.addInitScript({ content: bundle });
const page = await ctx.newPage();
page.on('pageerror', (e) => console.log('  [pageerror]', e.message));
await page.goto('http://target.test/app');

console.log('LISTENERS', JSON.stringify(await page.evaluate(() =>
  window.__WMA__.listeners().map((l) => ({ lid: l.lid, origin: l.origin, target: l.target, stack: l.stack.slice(0, 2).map((f) => `${f.fn}@${f.url}:${f.line}`) }))), null, 1));

await page.evaluate(() => {
  window.__WMA__.clear();
  window.dispatchEvent(new MessageEvent('message', { origin: 'https://trusted.example', data: { html: '<img src=x onerror=__WMA_HIT__("m1")>' } }));
  window.dispatchEvent(new MessageEvent('message', { origin: 'https://pay.example', data: { cmd: 'window.__WMA_HIT__("m2")' } }));
});
console.log('INVOCATIONS', JSON.stringify(await page.evaluate(() =>
  window.__WMA__.invocations().map((i) => ({ id: i.id, lid: i.lid, o: i.originRead, s: i.sourceRead, d: i.dataRead, paths: Object.keys(i.paths), cmp: i.compareSamples, sinks: i.sinks, threw: i.threw }))), null, 1));
console.log('SINKS', JSON.stringify(await page.evaluate(() => window.__WMA__.sinksSince(0).map((s) => ({ kind: s.kind, inv: s.inv, lid: s.lid, drv: s.driver, d: s.detail }))), null, 1));
console.log('HITS', await page.evaluate(() => JSON.stringify(window.__WMA__.hits())));
console.log('HOOKS', await page.evaluate(() => JSON.stringify(window.__WMA__.installedHooks())), 'ERRS', await page.evaluate(() => JSON.stringify(window.__WMA__.errors())));
console.log('OUTBOUND', JSON.stringify(await page.evaluate(() => window.__WMA__.outboundSince(0).map(o => ({ch:o.detail.channel, inv:o.inv, lid:o.lid})))));
await b.close();
