/*!
 * WMA sink hooks. Concatenated AFTER wma-core.js into one init script.
 * Installs itself against the core API (which is created first).
 */
(function () {
  'use strict';
  var W = window;

  W.__WMA_INSTALL_SINKS__ = function install(api) {
    if (api.installedHooks) return; // idempotent
    var CFG = api.config;
    var describeValue = api.describeValue;
    var truncString = api.truncString;

    var hits = [];
    var MARKER = /__WMA[0-9a-z]{4,40}__/i;

    function snippet(v, n) {
      if (typeof v !== 'string') return describeValue(v, 0);
      return truncString(v, n || 300);
    }

    W.__WMA_HIT__ = function (token) {
      if (hits.length < 100) hits.push({ token: String(token), at: Date.now() });
    };
    // XSS payloads call a function named after the per-probe marker. Defining
    // that global makes script execution observable without the payload having
    // to know about our hook name (some sinks strip quotes/arguments).
    api.defineCanary = function (name) {
      try {
        if (!/^[A-Za-z_$][\w$]*$/.test(name)) return false;
        W[name] = function () { W.__WMA_HIT__(name); return name; };
        return true;
      } catch (e) {
        return false;
      }
    };
    api.hits = function () { return hits.slice(); };
    api.clearHits = function () { hits.length = 0; };

    function sink(kind, detail) {
      api.recordSink(kind, detail);
    }

    var installed = [];
    function tryHook(name, fn) {
      try {
        fn();
        installed.push(name);
      } catch (e) {
        api._hookErrors = api._hookErrors || [];
        api._hookErrors.push({ hook: name, message: String((e && e.message) || e) });
      }
    }
    api.installedHooks = function () { return installed.slice(); };

    // ------------------------------------------------------------- eval-ish
    function hookEval() {
      var ev = W.eval;
      if (typeof ev !== 'function' || ev.__wma) return;
      var wrapped = function (code) {
        if (typeof code === 'string') sink('eval', { code: snippet(code, 400), marker: MARKER.test(code) });
        return ev.apply(W, arguments);
      };
      wrapped.__wma = true;
      W.eval = wrapped;
    }

    function hookFunctionCtor() {
      var F = W.Function;
      if (typeof F !== 'function' || F.__wma) return;
      var wrapped = function () {
        var args = Array.prototype.slice.call(arguments);
        var body = args.length ? String(args[args.length - 1]) : '';
        sink('Function', { code: snippet(body, 400), marker: MARKER.test(body) });
        return F.apply(W, arguments);
      };
      wrapped.__wma = true;
      W.Function = wrapped;
    }

    function hookTimers() {
      // string forms are a script-injection sink; function forms are covered by
      // the async-context timer patch in core.
      ['setTimeout', 'setInterval'].forEach(function (name) {
        var orig = W[name];
        if (typeof orig !== 'function') return;
        var wrapped = function (fn) {
          if (typeof fn === 'string') sink(name + '-string', { code: snippet(fn, 300), marker: MARKER.test(fn) });
          return orig.apply(W, arguments);
        };
        wrapped.__wma = true;
        try { W[name] = wrapped; } catch (e) {}
      });
    }

    // ------------------------------------------------------------ HTML sinks
    function describeElement(el) {
      try {
        if (!el || !el.tagName) return null;
        return { tag: String(el.tagName).toLowerCase(), id: el.id || null, cls: typeof el.className === 'string' ? el.className.slice(0, 120) : null };
      } catch (e) {
        return null;
      }
    }

    function hookHtmlSinks() {
      if (typeof Element === 'undefined') return;
      ['innerHTML', 'outerHTML'].forEach(function (prop) {
        var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
        if (!d || !d.set || !d.configurable) return;
        try {
          Object.defineProperty(Element.prototype, prop, {
            configurable: true,
            enumerable: d.enumerable,
            get: d.get,
            set: function (v) {
              try {
                if (typeof v === 'string') sink('html:' + prop, { html: snippet(v, 400), marker: MARKER.test(v), el: describeElement(this) });
              } catch (e) {}
              return d.set.call(this, v);
            }
          });
        } catch (e) {}
      });
      var iah = Element.prototype.insertAdjacentHTML;
      if (typeof iah === 'function' && !iah.__wma) {
        var w = function (pos, html) {
          try {
            if (typeof html === 'string') sink('html:insertAdjacentHTML', { html: snippet(html, 400), marker: MARKER.test(html), el: describeElement(this) });
          } catch (e) {}
          return iah.apply(this, arguments);
        };
        w.__wma = true;
        Element.prototype.insertAdjacentHTML = w;
      }
      ['write', 'writeln'].forEach(function (name) {
        var orig = Document.prototype[name];
        if (typeof orig !== 'function' || orig.__wma) return;
        var w = function () {
          try {
            var s = Array.prototype.map.call(arguments, String).join('');
            sink('html:document.' + name, { html: snippet(s, 400), marker: MARKER.test(s) });
          } catch (e) {}
          return orig.apply(this, arguments);
        };
        w.__wma = true;
        Document.prototype[name] = w;
      });
    }

    function hookSetAttribute() {
      if (typeof Element === 'undefined' || !Element.prototype.setAttribute) return;
      var orig = Element.prototype.setAttribute;
      if (orig.__wma) return;
      var w = function (name, value) {
        try {
          var n = String(name).toLowerCase();
          var s = String(value);
          var t = String(this.tagName || '').toLowerCase();
          if (
            (n === 'srcdoc' && t === 'iframe') ||
            ((n === 'src' || n === 'href') && s.indexOf('javascript:') === 0) ||
            (n.indexOf('on') === 0 && MARKER.test(s)) ||
            (MARKER.test(s) && (n === 'src' || n === 'srcdoc' || n === 'href'))
          ) {
            sink('attr:' + n, { tag: t, value: snippet(s, 300), marker: MARKER.test(s), el: describeElement(this) });
          }
        } catch (e) {}
        return orig.apply(this, arguments);
      };
      w.__wma = true;
      Element.prototype.setAttribute = w;
    }

    function hookScriptAttrs() {
      var pairs = [];
      if (typeof HTMLIFrameElement !== 'undefined') pairs.push([HTMLIFrameElement.prototype, 'srcdoc'], [HTMLIFrameElement.prototype, 'src']);
      if (typeof HTMLScriptElement !== 'undefined') pairs.push([HTMLScriptElement.prototype, 'src']);
      pairs.forEach(function (pair) {
        var proto = pair[0], prop = pair[1];
        var d = Object.getOwnPropertyDescriptor(proto, prop);
        if (!d || !d.set || !d.configurable) return;
        try {
          Object.defineProperty(proto, prop, {
            configurable: true,
            enumerable: d.enumerable,
            get: d.get,
            set: function (v) {
              try {
                var s = String(v);
                if (s.indexOf('javascript:') === 0 || MARKER.test(s)) sink('attr:' + prop, { value: snippet(s, 300), marker: MARKER.test(s), el: describeElement(this) });
              } catch (e) {}
              return d.set.call(this, v);
            }
          });
        } catch (e) {}
      });
    }

    // ------------------------------------------------------ navigation sinks
    function hookNavigation() {
      if (typeof W.open === 'function' && !W.open.__wma) {
        var open = W.open;
        var w = function (url) {
          try { sink('window.open', { url: snippet(String(url), 300) }); } catch (e) {}
          return open.apply(W, arguments);
        };
        w.__wma = true;
        W.open = w;
      }
      try {
        ['assign', 'replace'].forEach(function (name) {
          var orig = Location.prototype[name];
          if (typeof orig !== 'function' || orig.__wma) return;
          var w = function (url) {
            try { sink('location.' + name, { url: snippet(String(url), 300) }); } catch (e) {}
            return orig.apply(this, arguments);
          };
          w.__wma = true;
          Location.prototype[name] = w;
        });
        var hd = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        if (hd && hd.set && hd.configurable) {
          Object.defineProperty(Location.prototype, 'href', {
            configurable: true,
            enumerable: hd.enumerable,
            get: hd.get,
            set: function (v) {
              try { sink('location.href', { url: snippet(String(v), 300) }); } catch (e) {}
              return hd.set.call(this, v);
            }
          });
        }
      } catch (e) {}
    }

    // -------------------------------------------------------------- outbound
    function hookOutbound() {
      if (typeof W.postMessage === 'function' && !W.postMessage.__wma) {
        var pm = W.postMessage;
        var w = function (message, targetOrigin) {
          try {
            api.recordOutbound({ channel: 'window.postMessage', targetOrigin: String(targetOrigin), data: describeValue(message, 0) });
          } catch (e) {}
          return pm.apply(W, arguments);
        };
        w.__wma = true;
        W.postMessage = w;
      }
      if (typeof MessagePort !== 'undefined' && MessagePort.prototype.postMessage && !MessagePort.prototype.postMessage.__wma) {
        var pmp = MessagePort.prototype.postMessage;
        var wp = function (message) {
          try { api.recordOutbound({ channel: 'MessagePort.postMessage', data: describeValue(message, 0) }); } catch (e) {}
          return pmp.apply(this, arguments);
        };
        wp.__wma = true;
        MessagePort.prototype.postMessage = wp;
      }
      if (typeof W.fetch === 'function' && !W.fetch.__wma) {
        var fe = W.fetch;
        var wf = function (input, init) {
          try {
            var url = typeof input === 'string' ? input : input && input.url;
            var body = init && init.body;
            api.recordOutbound({ channel: 'fetch', url: snippet(String(url), 300), body: typeof body === 'string' ? snippet(body, 300) : describeValue(body, 0) });
          } catch (e) {}
          return fe.apply(W, arguments);
        };
        wf.__wma = true;
        W.fetch = wf;
      }
      if (typeof XMLHttpRequest !== 'undefined') {
        var xo = XMLHttpRequest.prototype.open;
        var xs = XMLHttpRequest.prototype.send;
        if (typeof xo === 'function' && !xo.__wma) {
          var wo = function (method, url) {
            try { api.recordOutbound({ channel: 'xhr.open', method: String(method), url: snippet(String(url), 300) }); } catch (e) {}
            return xo.apply(this, arguments);
          };
          wo.__wma = true;
          XMLHttpRequest.prototype.open = wo;
        }
        if (typeof xs === 'function' && !xs.__wma) {
          var ws = function (body) {
            try { if (body != null) api.recordOutbound({ channel: 'xhr.send', body: typeof body === 'string' ? snippet(body, 300) : describeValue(body, 0) }); } catch (e) {}
            return xs.apply(this, arguments);
          };
          ws.__wma = true;
          XMLHttpRequest.prototype.send = ws;
        }
      }
      if (typeof W.navigator !== 'undefined' && typeof W.navigator.sendBeacon === 'function' && !W.navigator.sendBeacon.__wma) {
        var sb = W.navigator.sendBeacon;
        var wb = function (url, data) {
          try { api.recordOutbound({ channel: 'sendBeacon', url: snippet(String(url), 300), data: typeof data === 'string' ? snippet(data, 300) : describeValue(data, 0) }); } catch (e) {}
          return sb.apply(W.navigator, arguments);
        };
        wb.__wma = true;
        try { W.navigator.sendBeacon = wb; } catch (e) {}
      }
      if (typeof W.WebSocket === 'function') {
        try {
          var NativeWS = W.WebSocket;
          var WS = function (url, protocols) {
            var inst = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
            try { api.recordOutbound({ channel: 'WebSocket', url: snippet(String(url), 300) }); } catch (e) {}
            try {
              var send = inst.send;
              inst.send = function (data) {
                try { api.recordOutbound({ channel: 'WebSocket.send', data: typeof data === 'string' ? snippet(data, 300) : describeValue(data, 0) }); } catch (e) {}
                return send.apply(inst, arguments);
              };
            } catch (e) {}
            return inst;
          };
          WS.prototype = NativeWS.prototype;
          Object.setPrototypeOf(WS, NativeWS);
          WS.__wma = true;
          W.WebSocket = WS;
        } catch (e) {}
      }
      if (typeof W.localStorage !== 'undefined') {
        try {
          var ls = W.localStorage;
          var setItem = ls.setItem.bind(ls);
          var fake = {
            setItem: function (k, v) {
              try { api.recordOutbound({ channel: 'localStorage.setItem', key: String(k), value: snippet(String(v), 200) }); } catch (e) {}
              return setItem(k, v);
            },
            getItem: function (k) { return ls.getItem(k); },
            removeItem: function (k) { return ls.removeItem(k); },
            clear: function () { return ls.clear(); },
            key: function (i) { return ls.key(i); }
          };
          Object.defineProperty(fake, 'length', { get: function () { return ls.length; } });
          Object.defineProperty(W, 'localStorage', { configurable: true, get: function () { return fake; } });
        } catch (e) {}
      }
    }

    if (CFG.hookSinks) {
      tryHook('eval', hookEval);
      tryHook('Function', hookFunctionCtor);
      tryHook('timers', hookTimers);
      tryHook('html', hookHtmlSinks);
      tryHook('setAttribute', hookSetAttribute);
      tryHook('scriptAttrs', hookScriptAttrs);
      tryHook('navigation', hookNavigation);
    }
    if (CFG.trackOutbound) tryHook('outbound', hookOutbound);
  };

  // Core loads first in the concatenated bundle, so install immediately.
  if (W.__WMA__) {
    try { W.__WMA_INSTALL_SINKS__(W.__WMA__); } catch (e) {}
  }
})();
