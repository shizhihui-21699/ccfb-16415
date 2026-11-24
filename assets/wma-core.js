/*!
 * Window Message Audit (WMA) — in-page instrumentation core.
 *
 * Injected via Playwright addInitScript into EVERY frame before page code runs.
 * Captures message-listener registrations, routes handler invocations through a
 * wrapper, tracks how each handler uses the event (origin / source / data paths)
 * and attributes side effects to the handler even across async callbacks.
 *
 * Plain ES2019, no imports, must never throw into page code.
 */
(function () {
  'use strict';

  var W = window;
  if (W.__WMA__ && W.__WMA__.version) return;

  var CFG = Object.assign(
    {
      version: '1.0.1',
      maxListeners: 600,
      maxInvocations: 4000,
      maxSinks: 4000,
      maxOutbound: 1200,
      maxString: 1500,
      maxDepth: 5,
      maxKeys: 80,
      maxPaths: 120,
      traceData: true,
      trackOutbound: true,
      hookSinks: true,
      maxErrors: 60
    },
    W.__WMA_CONFIG__ || {}
  );

  // ------------------------------------------------------------------ state

  var state = {
    frameTag: 'f' + Math.random().toString(36).slice(2, 8),
    seq: 0,
    listeners: [],
    listenerSeq: 0,
    byHandler: new WeakMap(), // raw handler -> listener record
    wrapperOf: new WeakMap(), // raw handler -> wrapper
    rawOfWrapper: new WeakMap(), // wrapper -> raw handler
    lidMap: new Map(), // lid -> raw handler
    invocations: [],
    sinks: [],
    outbound: [],
    errors: [],
    current: null,
    eventProxy: new WeakMap(), // MessageEvent -> { proxy, inv, paths }
    installed: Date.now()
  };

  function err(where, e) {
    if (state.errors.length < CFG.maxErrors) {
      state.errors.push({
        where: where,
        message: e && e.message ? String(e.message).slice(0, 500) : String(e).slice(0, 500),
        stack: e && e.stack ? String(e.stack).slice(0, 900) : null,
        at: Date.now()
      });
    }
  }

  // -------------------------------------------------------------- utilities

  var hasOwn = Object.prototype.hasOwnProperty;
  // Captured before sink hooks run: hooking Window.Function must not change how
  // we stringify handlers, or every captured source becomes "[object Function]".
  var nativeFnToString = Function.prototype.toString;
  var NativeMessageEvent = typeof MessageEvent !== 'undefined' ? MessageEvent : null;
  var nativeAdd = EventTarget.prototype.addEventListener;
  var nativeRemove = EventTarget.prototype.removeEventListener;
  var nativeOnMessageDesc = (function () {
    var proto = W;
    var depth = 0;
    while (proto && depth++ < 8) {
      var d = Object.getOwnPropertyDescriptor(proto, 'onmessage');
      if (d) return { owner: proto, desc: d };
      proto = Object.getPrototypeOf(proto);
    }
    return null;
  })();

  function safe(fn, fallback) {
    try {
      return fn();
    } catch (e) {
      err('safe', e);
      return fallback;
    }
  }

  function truncString(s, n) {
    s = String(s);
    n = n || CFG.maxString;
    if (s.length <= n) return s;
    return s.slice(0, n) + '…[' + (s.length - n) + ']';
  }

  function describeValue(v, depth, seen) {
    depth = depth == null ? 0 : depth;
    seen = seen || [];
    if (v === null) return { t: 'null' };
    var t = typeof v;
    if (t === 'string') return { t: 'string', v: truncString(v, 400), len: v.length };
    if (t === 'number' || t === 'boolean' || t === 'undefined') return { t: t, v: v };
    if (t === 'bigint' || t === 'symbol') return { t: t, v: String(v).slice(0, 200) };
    if (t === 'function') return { t: 'function', name: v.name || '(anonymous)' };
    if (seen.indexOf(v) !== -1) return { t: 'circular' };
    if (depth >= CFG.maxDepth) return { t: Array.isArray(v) ? 'array' : 'object', truncated: true };
    seen = seen.concat([v]);
    if (Array.isArray(v)) {
      var arr = [];
      for (var i = 0; i < Math.min(v.length, 16); i++) arr.push(describeValue(v[i], depth + 1, seen));
      return { t: 'array', len: v.length, items: arr };
    }
    if (typeof Node !== 'undefined' && v instanceof Node) {
      return { t: 'node', name: v.nodeName, id: v.id || undefined };
    }
    if (typeof Window !== 'undefined' && v instanceof Window) return { t: 'window' };
    if (typeof MessagePort !== 'undefined' && v instanceof MessagePort) return { t: 'messageport' };
    var keys = [];
    safe(function () {
      keys = Object.keys(v).slice(0, CFG.maxKeys);
    });
    var props = {};
    for (var k = 0; k < keys.length; k++) props[keys[k]] = describeValue(v[keys[k]], depth + 1, seen);
    return { t: 'object', keys: keys, props: props };
  }

  function jsonSafe(v) {
    var seen = [];
    return JSON.stringify(v, function (k, val) {
      if (typeof val === 'object' && val !== null) {
        if (seen.indexOf(val) !== -1) return '[circular]';
        seen.push(val);
      }
      if (typeof val === 'string' && val.length > 600) return truncString(val, 600);
      if (typeof val === 'function') return '[function]';
      return val;
    });
  }

  var SELF_URL = /wma-inject\.js/;

  function parseStack(stack) {
    if (!stack) return [];
    var lines = String(stack).split('\n');
    var out = [];
    for (var i = 1; i < lines.length && out.length < 16; i++) {
      var m = /(?:at\s+(?:(.*?)\s+\()?)?((?:https?|file|blob|chrome-extension):[^\s)]+|[^()\s]*:\d+:\d+)/.exec(lines[i]);
      if (!m) continue;
      var raw = m[2].replace(/[()]/g, '');
      var loc = /^(.*):(\d+):(\d+)$/.exec(raw);
      out.push({
        fn: (m[1] || '(anonymous)').trim().replace(/^Object\./, ''),
        url: loc ? loc[1] : raw,
        line: loc ? Number(loc[2]) : null,
        col: loc ? Number(loc[3]) : null
      });
    }
    return out;
  }

  function captureStack(top) {
    var limit = Error.stackTraceLimit;
    var stack;
    try {
      Error.stackTraceLimit = 50;
      stack = new Error().stack;
    } catch (e) {
      stack = null;
    }
    try {
      Error.stackTraceLimit = limit;
    } catch (e) {}
    var frames = parseStack(stack);
    var out = [];
    for (var i = 0; i < frames.length; i++) {
      var f = frames[i];
      if (SELF_URL.test(f.url)) continue;
      var sig = f.fn + '@' + f.url + ':' + f.line;
      if (/^(captureStack|registerListener|patchedAdd|patchedRemove|makeWrapper|dispatch|safe|runInContext|ensureEventProxy|onEventRead|recordSink|recordOutbound)@/.test(sig)) continue;
      out.push(f);
      if (out.length >= (top || 10)) break;
    }
    return out;
  }

  function fnSource(fn) {
    return safe(function () {
      return truncString(nativeFnToString.call(fn), 6000);
    }, null);
  }

  function targetKind(target) {
    try {
      if (target === W) return 'window';
      if (typeof Document !== 'undefined' && target === W.document) return 'document';
      if (typeof WorkerGlobalScope !== 'undefined' && target instanceof WorkerGlobalScope) return 'worker';
      if (typeof MessagePort !== 'undefined' && target instanceof MessagePort) return 'messageport';
      if (typeof ServiceWorker !== 'undefined' && target instanceof ServiceWorker) return 'serviceworker';
      if (typeof BroadcastChannel !== 'undefined' && target instanceof BroadcastChannel) return 'broadcastchannel';
      if (typeof EventTarget !== 'undefined' && target instanceof EventTarget) {
        var nm = target.nodeName;
        return 'eventtarget' + (nm ? ':' + String(nm).toLowerCase() : '');
      }
      return 'object';
    } catch (e) {
      return 'unknown';
    }
  }

  // ------------------------------------------------ async context propagation

  // Handlers frequently defer work to timers/microtasks/promises. Without this,
  // a sink fired from a timer is unattributable. Each deferred callback carries
  // the invocation that scheduled it.
  var ctx = { inv: null };

  function runInContext(inv, fn, thisArg, args) {
    var prev = ctx.inv;
    ctx.inv = inv;
    try {
      return fn.apply(thisArg, args || []);
    } finally {
      ctx.inv = prev;
    }
  }

  function hookAsync() {
    var wrapCb = function (cb) {
      var inv = ctx.inv;
      if (!inv || typeof cb !== 'function') return cb;
      return function () {
        return runInContext(inv, cb, this, arguments);
      };
    };
    function patchTimer(name) {
      var orig = W[name];
      if (typeof orig !== 'function' || orig.__wma) return;
      var wrapped = function (fn) {
        var args = Array.prototype.slice.call(arguments);
        if (typeof fn === 'function') args[0] = wrapCb(fn);
        return orig.apply(W, args);
      };
      wrapped.__wma = true;
      try { W[name] = wrapped; } catch (e) {}
    }
    patchTimer('setTimeout');
    patchTimer('setInterval');
    patchTimer('requestAnimationFrame');
    patchTimer('requestIdleCallback');

    var qm = W.queueMicrotask;
    if (typeof qm === 'function' && !qm.__wma) {
      var wqm = function (cb) { return qm.call(W, wrapCb(cb)); };
      wqm.__wma = true;
      try { W.queueMicrotask = wqm; } catch (e) {}
    }
    // Promise callbacks: a then/catch/finally chain started inside a handler
    // keeps that handler as its attribution context.
    safe(function () {
      var P = W.Promise;
      if (!P || !P.prototype || P.prototype.then.__wma) return;
      var then = P.prototype.then;
      function patchMethod(name) {
        var orig = P.prototype[name];
        if (typeof orig !== 'function') return;
        var wrapped = function (onFulfilled, onRejected) {
          var wrap = bindAsync(user);
          var a = typeof onFulfilled === 'function' ? wrap(onFulfilled) : onFulfilled;
          var b = typeof onRejected === 'function' ? wrap(onRejected) : onRejected;
          return orig.call(this, a, b);
        };
        wrapped.__wma = true;
        P.prototype[name] = wrapped;
      }
      patchMethod('then');
      patchMethod('catch');
      patchMethod('finally');
    });
    // MessageChannel (used by scheduler libraries)
    safe(function () {
      if (typeof MessageChannel === 'undefined') return;
      var orig = W.MessageChannel;
      if (!orig) return;
      var Patched = function () {
        var mc = new orig();
        var p1 = mc.port1;
        var add = p1.addEventListener;
        p1.addEventListener = function (type, cb) {
          return add.call(p1, type, typeof cb === 'function' ? wrapCb(cb) : cb);
        };
        return mc;
      };
      Patched.prototype = orig.prototype;
      Object.setPrototypeOf(Patched, orig);
      W.MessageChannel = Patched;
    });
  }

  // ---------------------------------------------------- listener registration

  var MESSAGE_TYPES = { message: 1, messageerror: 1 };

  function registerListener(target, type, listener, options, origin) {
    if (!MESSAGE_TYPES[type]) return null;
    if (!listener) return null;
    if (state.listeners.length >= CFG.maxListeners) {
      err('maxListeners', new Error('listener budget reached'));
      return null;
    }
    var isObject = typeof listener === 'object';
    var handler = listener;
    if (isObject) {
      handler = safe(function () {
        return listener.handleEvent || null;
      }, null);
      if (typeof handler !== 'function') return null;
    } else if (typeof listener !== 'function') {
      return null;
    }

    var capture = false,
      once = false,
      passive = false;
    if (typeof options === 'boolean') capture = options;
    else if (options && typeof options === 'object') {
      capture = !!options.capture;
      once = !!options.once;
      passive = !!options.passive;
    }

    var rec = {
      lid: 'l' + ++state.listenerSeq,
      type: type,
      target: targetKind(target),
      capture: capture,
      once: once,
      passive: passive,
      objectListener: isObject,
      origin: origin,
      registeredAt: Date.now(),
      stack: captureStack(10),
      source: fnSource(handler),
      invocations: 0,
      removed: false
    };
    state.listeners.push(rec);
    state.byHandler.set(handler, rec);
    state.lidMap.set(rec.lid, handler);
    return rec;
  }

  function makeWrapper(handler, rec) {
    var wrapper = function (event) {
      return dispatch(handler, rec, event, this);
    };
    state.wrapperOf.set(handler, wrapper);
    state.rawOfWrapper.set(wrapper, handler);
    return wrapper;
  }

  function dispatch(handler, rec, event, thisArg) {
    var inv = {
      id: ++state.seq,
      lid: rec ? rec.lid : null,
      fid: state.frameTag,
      listener: rec ? rec.type : null,
      target: rec ? rec.target : null,
      at: Date.now(),
      rel: Math.round(performance.now()),
      originRead: false,
      sourceRead: false,
      portsRead: false,
      dataRead: false,
      dataType: null,
      dataPreview: null,
      originValue: null,
      paths: {},
      compareSamples: [],
      originCompares: [],
      threw: null,
      durationMs: 0,
      sinks: 0,
      outbound: 0
    };
    if (event && typeof event === 'object') {
      inv.originValue = safe(function () {
        var d = Object.getOwnPropertyDescriptor((NativeMessageEvent || MessageEvent).prototype, 'origin');
        return d && d.get ? d.get.call(event) : event.origin;
      }, null);
      if (CFG.traceData) safe(function () { ensureEventProxy(event, inv); });
    }
    if (rec) rec.invocations++;
    state.invocations.push(inv);
    if (state.invocations.length > CFG.maxInvocations) state.invocations.shift();


    var t0 = performance.now();
    try {
      return runInContext(inv, handler, thisArg, [event]);
    } catch (e) {
      inv.threw = e && e.message ? String(e.message).slice(0, 400) : String(e).slice(0, 400);
      throw e;
    } finally {
      inv.durationMs = Math.round((performance.now() - t0) * 100) / 100;
    }
  }

  // ------------------------------------------------------- data path tracking

  function ensureEventProxy(event, inv) {
    var existing = state.eventProxy.get(event);
    if (existing) {
      existing.inv = inv;
      return existing.proxy;
    }
    var raw = safe(function () { return event.data; }, undefined);
    if (raw === null || typeof raw !== 'object') {
      inv.dataType = raw === null ? 'null' : typeof raw;
      inv.dataPreview = describeValue(raw, 0);
      return;
    }

    var cache = new WeakMap();
    var paths = inv.paths;

    function note(path, value) {
      var invNow = ctx.inv || inv;
      invNow.dataRead = true;
      var slot = invNow.paths[path];
      if (!slot) {
        if (Object.keys(invNow.paths).length >= CFG.maxPaths) return;
        slot = invNow.paths[path] = { n: 0, sample: describeValue(value, 1) };
      }
      slot.n++;
    }

    function wrap(obj, prefix) {
      var cached = cache.get(obj);
      if (cached && cached.prefix === prefix) return cached.proxy;
      var proxy = new Proxy(obj, {
        get: function (target, prop, receiver) {
          if (typeof prop === 'symbol') return Reflect.get(target, prop, receiver);
          var path = prefix ? prefix + '.' + String(prop) : String(prop);
          var value = Reflect.get(target, prop, receiver);
          note(path, value);
          if (typeof value === 'function') {
            // data.payload.action.indexOf('x') — record the call and string args
            var method = String(prop);
            if (method === 'indexOf' || method === 'includes' || method === 'startsWith' || method === 'endsWith' || method === 'match' || method === 'test' || method === 'search') {
              return function () {
                var invNow = ctx.inv || inv;
                if (invNow.compareSamples.length < 20) {
                  invNow.compareSamples.push({ path: prefix || 'data', method: method, args: Array.prototype.slice.call(arguments, 0, 2).map(function (a) { return describeValue(a, 1); }) });
                }
                return value.apply(target, arguments);
              };
            }
            return value.bind(target);
          }
          if (value && typeof value === 'object') return wrap(value, path);
          return value;
        },
        has: function (target, prop) {
          note((prefix ? prefix + '.' : '') + String(prop), undefined);
          return Reflect.has(target, prop);
        },
        ownKeys: function (target) {
          note(prefix ? prefix + '.*' : '*', undefined);
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor: function (target, prop) {
          return Reflect.getOwnPropertyDescriptor(target, prop);
        }
      });
      cache.set(obj, { proxy: proxy, prefix: prefix });
      return proxy;
    }

    inv.dataType = Array.isArray(raw) ? 'array' : 'object';
    inv.dataPreview = describeValue(raw, 0);
    var root = wrap(raw, '');
    state.eventProxy.set(event, { proxy: root, inv: inv, raw: raw, paths: paths });
    return root;
  }

  // ------------------------------------------------------ event property reads

  // Origin comparisons are the crux of validation. `origin.startsWith(X)` is
  // only gradeable when X is known; when X is a runtime value (a config object,
  // a reducer constant, an SDK option) static analysis cannot see it. Capture
  // the actual operand at call time by watching String methods whose receiver is
  // precisely the origin string of the event being dispatched.
  function hookOriginComparisons() {
    if (typeof String === 'undefined' || !String.prototype) return;
    var methods = ['startsWith', 'endsWith', 'includes', 'indexOf', 'lastIndexOf', 'match', 'search', 'localeCompare'];
    methods.forEach(function (name) {
      var orig = String.prototype[name];
      if (typeof orig !== 'function' || orig.__wma) return;
      var wrapped = function (arg) {
        try {
          var inv = ctx.inv || state.current;
          if (inv && inv.originValue != null && this === inv.originValue) {
            var operand = typeof arg === 'string' ? arg : null;
            if (operand == null && arg instanceof RegExp) operand = '/' + arg.source + '/' + arg.flags;
            if (operand != null && (inv.originCompares || (inv.originCompares = [])).length < 24) {
              inv.originCompares.push({ method: name, operand: operand });
            }
          }
        } catch (e) {}
        return orig.apply(this, arguments);
      };
      wrapped.__wma = true;
      try { String.prototype[name] = wrapped; } catch (e) {}
    });
  }

  function hookMessageEvent() {
    var proto = safe(function () { return (NativeMessageEvent || MessageEvent).prototype; }, null);
    if (!proto) return;
    ['origin', 'source', 'data', 'ports'].forEach(function (prop) {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.get || !d.configurable) return;
      try {
        Object.defineProperty(proto, prop, {
          configurable: true,
          enumerable: d.enumerable,
          get: function () {
            onEventRead(prop, this);
            if (prop === 'data' && CFG.traceData) {
              var entry = state.eventProxy.get(this);
              if (entry) return entry.proxy;
            }
            return d.get.call(this);
          }
        });
      } catch (e) {
        err('hookMessageEvent:' + prop, e);
      }
    });
  }

  function onEventRead(prop, event) {
    var inv = ctx.inv;
    if (!inv) {
      var entry = state.eventProxy.get(event);
      inv = entry ? entry.inv : null;
    }
    if (!inv) return;
    if (prop === 'origin') inv.originRead = true;
    else if (prop === 'source') inv.sourceRead = true;
    else if (prop === 'ports') inv.portsRead = true;
    else if (prop === 'data') inv.dataRead = true;
  }

  // ----------------------------------------------------------- install patches

  function patchedAdd(type, listener, options) {
    var self = this == null ? W : this;
    try {
      if ((type === 'message' || type === 'messageerror') && listener) {
        var rec = registerListener(self, String(type), listener, options, 'addEventListener');
        if (rec) {
          var handler = typeof listener === 'function' ? listener : listener.handleEvent;
          if (typeof handler === 'function') {
            var wrapper = state.wrapperOf.get(handler) || makeWrapper(handler, rec);
            return nativeAdd.call(self, type, wrapper, options);
          }
        }
      }
    } catch (e) {
      err('addEventListener', e);
    }
    return nativeAdd.apply(self, arguments);
  }

  function patchedRemove(type, listener, options) {
    var self = this == null ? W : this;
    try {
      if ((type === 'message' || type === 'messageerror') && listener) {
        var handler = typeof listener === 'function' ? listener : listener.handleEvent;
        if (handler && state.byHandler.has(handler)) {
          var rec = state.byHandler.get(handler);
          rec.removed = true;
          var wrapper = state.wrapperOf.get(handler);
          if (wrapper) return nativeRemove.call(self, type, wrapper, options);
        }
      }
    } catch (e) {
      err('removeEventListener', e);
    }
    return nativeRemove.apply(self, arguments);
  }

  safe(function () {
    EventTarget.prototype.addEventListener = patchedAdd;
    EventTarget.prototype.removeEventListener = patchedRemove;
  });

  function installOnMessageAccessor() {
    var h = nativeOnMessageDesc;
    if (!h || !h.desc.set || !h.desc.get) return;
    try {
      Object.defineProperty(h.owner, 'onmessage', {
        configurable: true,
        enumerable: h.desc.enumerable,
        get: function () {
          var fn = h.desc.get.call(this);
          return (fn && state.rawOfWrapper.get(fn)) || fn;
        },
        set: function (value) {
          if (typeof value === 'function') {
            var rec = registerListener(this, 'message', value, undefined, 'onmessage-setter');
            if (rec) return h.desc.set.call(this, makeWrapper(value, rec));
          }
          return h.desc.set.call(this, value);
        }
      });
    } catch (e) {
      err('onmessage-accessor', e);
    }
  }
  safe(installOnMessageAccessor);

  safe(function () {
    if (typeof MessagePort === 'undefined') return;
    ['onmessage', 'onmessageerror'].forEach(function (prop) {
      var d = Object.getOwnPropertyDescriptor(MessagePort.prototype, prop);
      if (!d || !d.set) return;
      try {
        Object.defineProperty(MessagePort.prototype, prop, {
          configurable: true,
          enumerable: d.enumerable,
          get: d.get,
          set: function (value) {
            if (typeof value === 'function') {
              var rec = registerListener(this, 'message', value, undefined, 'port-' + prop);
              if (rec) return d.set.call(this, makeWrapper(value, rec));
            }
            return d.set.call(this, value);
          }
        });
      } catch (e) {
        err('port-accessor', e);
      }
    });
  });

  // --------------------------------------------------------------- sinks API

  function activeInv() {
    return ctx.inv || state.current;
  }

  // Playwright evaluates driver expressions with eval from its UtilityScript
  // world; those must never be mistaken for page behaviour.
  function isDriverStack(stack) {
    for (var i = 0; i < stack.length; i++) {
      var f = stack[i];
      var u = f.url || '';
      var n = f.fn || '';
      if (SELF_URL.test(u)) continue; // our own instrumentation
      if (/^wrapped$|^sink$|^recordSink$|^Object\.(wrapped|recordSink)$/.test(n)) continue;
      if (/UtilityScript|pptr:|__playwright|injectedScript/.test(u) || /UtilityScript|pptr/.test(n)) return true;
      return false; // first real frame belongs to the page
    }
    return false;
  }

  function recordSink(kind, detail) {
    var inv = activeInv();
    var stack = captureStack(8);
    var rec = {
      id: ++state.sinkSeq,
      kind: kind,
      inv: inv ? inv.id : null,
      lid: inv ? inv.lid : null,
      at: Date.now(),
      detail: detail,
      stack: stack,
      driver: isDriverStack(stack)
    };
    if (inv) inv.sinks++;
    state.sinks.push(rec);
    if (state.sinks.length > CFG.maxSinks) state.sinks.shift();
    return rec;
  }

  function recordOutbound(detail) {
    var inv = activeInv();
    var rec = {
      id: ++state.outSeq,
      inv: inv ? inv.id : null,
      lid: inv ? inv.lid : null,
      at: Date.now(),
      detail: detail
    };
    if (inv) inv.outbound++;
    state.outbound.push(rec);
    if (state.outbound.length > CFG.maxOutbound) state.outbound.shift();
    return rec;
  }

  state.sinkSeq = 0;
  state.outSeq = 0;

  var api = {
    version: CFG.version,
    config: CFG,
    frameInfo: function () {
      var href = '', origin = '';
      try { href = location.href; origin = location.origin; } catch (e) {}
      return {
        href: href,
        origin: origin,
        isTop: safe(function () { return W.top === W; }, false),
        name: safe(function () { return W.name; }, '')
      };
    },
    listeners: function () {
      return state.listeners.map(function (r) {
        return {
          lid: r.lid, type: r.type, target: r.target, capture: r.capture, once: r.once,
          passive: r.passive, objectListener: r.objectListener, origin: r.origin,
          registeredAt: r.registeredAt, stack: r.stack, source: r.source,
          invocations: r.invocations, removed: r.removed
        };
      });
    },
    getHandler: function (lid) {
      return state.lidMap.get(lid) || null;
    },
    invocations: function (sinceId) {
      return state.invocations.filter(function (i) { return !sinceId || i.id > sinceId; });
    },
    sinksSince: function (id) {
      return state.sinks.filter(function (s) { return s.id > (id || 0); });
    },
    sinkSeq: function () { return state.sinkSeq; },
    outboundSince: function (id) {
      return state.outbound.filter(function (o) { return o.id > (id || 0); });
    },
    outboundSeq: function () { return state.outSeq; },
    errors: function () { return state.errors.slice(); },
    stats: function () {
      return {
        listeners: state.listeners.length,
        invocations: state.invocations.length,
        sinks: state.sinks.length,
        outbound: state.outbound.length,
        errors: state.errors.length
      };
    },
    recordSink: recordSink,
    recordOutbound: recordOutbound,
    clear: function () {
      state.invocations.length = 0;
      state.sinks.length = 0;
      state.outbound.length = 0;
      state.sinkSeq = 0;
      state.outSeq = 0;
    },
    resetCounters: function () {
      state.sinkSeq = state.sinks.length;
      state.outSeq = state.outbound.length;
    },
    setConfig: function (patch) { Object.assign(CFG, patch || {}); },
    describeValue: describeValue,
    jsonSafe: jsonSafe,
    truncString: truncString
  };

  Object.defineProperty(W, '__WMA__', {
    value: api,
    enumerable: false,
    configurable: false,
    writable: false
  });

  hookMessageEvent();
  safe(hookAsync);
  safe(hookOriginComparisons);

  if (typeof W.__WMA_INSTALL_SINKS__ === 'function') {
    safe(function () { W.__WMA_INSTALL_SINKS__(api); });
  }
})();
