/* editor.js — loaded by visual-editor/index.html */
(function () {
  'use strict';
  var TRUSTED = ['https://app.editor-corp.test', 'https://staging.editor-corp.test'];

  // Correct: exact allow-list membership.
  window.addEventListener('message', function (e) {
    if (TRUSTED.indexOf(e.origin) === -1) return;
    if (e.data && e.data.tool === 'select') {
      document.title = 'sel:' + e.data.id;
    }
  });

  // BUG: regex with an unescaped dot and no end anchor.
  var RE = /^https:\/\/app.editor-corp.test/;
  window.addEventListener('message', function (e) {
    if (!RE.test(e.origin)) return;
    if (e.data && e.data.tool === 'insert') {
      document.body.innerHTML += e.data.markup;
    }
  });
})();
