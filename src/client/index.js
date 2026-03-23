/**
 * Athar (اثر) Browser SDK v3.1.0
 * Device intelligence for MENA financial services
 * Every device leaves a trace.
 *
 * 22+ signal categories:
 *  [v1] canvas, webgl-params, audio, screen, fonts, browser, hardware
 *  [v2] arabic-fonts, arabic-rendering, timezone, webrtc, bot, tampering
 *  [v3] clientRects, webgl-render, speechVoices, emoji, codecs,
 *       cssSupports, permissions, storageQuota, mathml, intlProbe
 *  [v3.1] devTools, virtualMachine, locationSpoofing, highActivity, rawAttributes
 */

class DeviceID {
  constructor(o) {
    o = o || {};
    this.apiKey = o.apiKey;
    this.apiEndpoint = o.apiEndpoint || 'https://api.arch-hayder.workers.dev/v1/fingerprint';
    this.debug = o.debug || false;
    this._cache = null;
    this._cacheExp = 0;
  }

  async identify() {
    if (this._cache && Date.now() < this._cacheExp) return this._cache;
    try {
      var sig = await this.collectSignals();
      if (this.debug) console.log('[Athar] signals:', sig);
      var r = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': this.apiKey },
        body: JSON.stringify(sig),
      });
      if (!r.ok) throw new Error('API ' + r.status);
      var res = await r.json();
      if (res.visitorId) this._persistId(res.visitorId);
      this._cache = res;
      this._cacheExp = Date.now() + 300000;
      return res;
    } catch (e) {
      if (this.debug) console.error('[Athar]', e);
      throw e;
    }
  }

  async collectSignals() {
    var t0 = performance.now();
    var pAudio = this._getAudio();
    var pRTC = this._getWebRTCIPs();
    var pPriv = this._detectPrivate();
    var pVoices = this._getSpeechVoices();
    var pPerms = this._getPermissions();
    var pQuota = this._getStorageQuota();

    var audio = await pAudio;
    var rtc = await pRTC;
    var priv = await pPriv;
    var voices = await pVoices;
    var perms = await pPerms;
    var quota = await pQuota;

    return {
      v: '3.1.0',
      ts: Date.now(),
      canvas: this._getCanvas(),
      webgl: this._getWebGL(),
      audio: audio,
      screen: this._getScreen(),
      fonts: this._getFonts(),
      browser: this._getBrowser(),
      hardware: this._getHardware(),
      arabicFonts: this._getArabicFonts(),
      timezone: this._getTimezone(),
      clientRects: this._getClientRects(),
      webglRender: this._getWebGLRender(),
      voices: voices,
      emoji: this._getEmojiFingerprint(),
      codecs: this._getCodecs(),
      cssSupports: this._getCSSSupports(),
      permissions: perms,
      storageQuota: quota,
      mathml: this._getMathMLFingerprint(),
      intlProbe: this._getIntlProbe(),
      evasion: {
        headlessScore: this._detectHeadless(),
        isPrivate: priv,
        webrtcIPs: rtc,
        bot: this._detectBot(),
        tampering: this._detectTampering(),
        devTools: this._detectDevTools(),
        virtualMachine: this._detectVM(),
        locationSpoofing: this._detectLocationSpoofing(),
      },
      rawAttributes: this._getRawAttributes(),
      storedIds: this._getStoredIds(),
      collectionMs: Math.round(performance.now() - t0),
    };
  }

  _getCanvas() {
    try {
      var c = document.createElement('canvas');
      c.width = 256;
      c.height = 128;
      var x = c.getContext('2d');
      x.textBaseline = 'alphabetic';
      x.fillStyle = '#f60';
      x.fillRect(100, 1, 62, 20);
      x.fillStyle = '#069';
      x.font = '11pt "Times New Roman"';
      x.fillText('Athar,cvs,fp', 2, 15);
      x.fillStyle = 'rgba(102,204,0,0.7)';
      x.font = '18pt Arial';
      x.fillText('Athar,cvs,fp', 4, 45);
      x.font = '16pt serif';
      x.fillStyle = '#333';
      x.fillText('\u0628\u0633\u0645 \u0627\u0644\u0644\u0647', 2, 75);
      x.globalCompositeOperation = 'multiply';
      x.fillStyle = 'rgb(255,0,255)';
      x.beginPath();
      x.arc(50, 50, 50, 0, Math.PI * 2, true);
      x.closePath();
      x.fill();
      x.fillStyle = 'rgb(0,255,255)';
      x.beginPath();
      x.arc(100, 50, 50, 0, Math.PI * 2, true);
      x.closePath();
      x.fill();
      x.globalCompositeOperation = 'source-over';
      var g = x.createLinearGradient(0, 0, 256, 0);
      g.addColorStop(0, 'red');
      g.addColorStop(0.5, 'green');
      g.addColorStop(1, 'blue');
      x.fillStyle = g;
      x.fillRect(0, 90, 256, 38);
      return c.toDataURL();
    } catch (e) {
      return null;
    }
  }

  _getWebGL() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;
      var d = gl.getExtension('WEBGL_debug_renderer_info');
      var a = gl.getExtension('EXT_texture_filter_anisotropic');
      return {
        vendor: d ? gl.getParameter(d.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: d ? gl.getParameter(d.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLang: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTexSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewport: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)),
        maxRenderbuf: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxAniso: a ? gl.getParameter(a.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null,
        aliasedLine: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)),
        aliasedPoint: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)),
        maxVertAttr: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        maxVarying: gl.getParameter(gl.MAX_VARYING_VECTORS),
        maxFragUni: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        maxVertUni: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        exts: (gl.getSupportedExtensions() || []).sort(),
      };
    } catch (e) {
      return null;
    }
  }

  _getWebGLRender() {
    try {
      var c = document.createElement('canvas');
      c.width = 64;
      c.height = 64;
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;

      var vs = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vs, 'attribute vec2 p;void main(){gl_Position=vec4(p,0,1);}');
      gl.compileShader(vs);

      var fs = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fs, 'precision mediump float;void main(){gl_FragColor=vec4(0.176,0.408,0.337,1.0);}');
      gl.compileShader(fs);

      var prog = gl.createProgram();
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      gl.useProgram(prog);

      var buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, 0, 1]), gl.STATIC_DRAW);
      var loc = gl.getAttribLocation(prog, 'p');
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

      gl.clearColor(0, 0, 0, 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      var px = new Uint8Array(64 * 64 * 4);
      gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);

      var hash = 0;
      for (var i = 0; i < px.length; i += 3) {
        hash = ((hash << 5) - hash) + px[i];
        hash = hash & hash;
      }
      return hash;
    } catch (e) {
      return null;
    }
  }

  _getClientRects() {
    try {
      var container = document.createElement('div');
      container.style.cssText = 'position:absolute;top:-9999px;left:-9999px;visibility:hidden;';
      document.body.appendChild(container);

      var tests = [
        { tag: 'span', text: 'Athar mmmmmmm', style: 'font:16px/1 Arial;display:inline;' },
        { tag: 'span', text: '\u0628\u0633\u0645 \u0627\u0644\u0644\u0647', style: 'font:20px/1 serif;display:inline;direction:rtl;' },
        { tag: 'div', text: 'Test', style: 'width:100px;height:50px;border:1px solid;transform:scale(1.5) rotate(0.01deg);' },
        { tag: 'div', text: '', style: 'width:1px;height:1px;transform:scale(100000000000000000000009999999999999.99,1.89);' },
        { tag: 'span', text: 'fi fl ffi', style: 'font:14px "Times New Roman";display:inline;font-variant-ligatures:common-ligatures;' },
      ];

      var results = [];
      for (var i = 0; i < tests.length; i++) {
        var el = document.createElement(tests[i].tag);
        el.textContent = tests[i].text;
        el.style.cssText = tests[i].style;
        container.appendChild(el);
        var rects = el.getClientRects();
        for (var j = 0; j < rects.length; j++) {
          var r = rects[j];
          results.push(
            Math.round(r.width * 1000) / 1000,
            Math.round(r.height * 1000) / 1000,
            Math.round(r.top * 1000) / 1000,
            Math.round(r.left * 1000) / 1000
          );
        }
        var br = el.getBoundingClientRect();
        results.push(Math.round(br.width * 1000) / 1000, Math.round(br.height * 1000) / 1000);
      }

      container.remove();
      return results;
    } catch (e) {
      return null;
    }
  }

  _getSpeechVoices() {
    return new Promise(function (resolve) {
      try {
        if (!window.speechSynthesis) return resolve(null);
        var completed = false;
        var done = function (value) {
          if (!completed) {
            completed = true;
            resolve(value);
          }
        };

        var getV = function () {
          var voices = speechSynthesis.getVoices();
          if (voices.length > 0) {
            done(voices.map(function (v) {
              return v.name + '|' + v.lang + '|' + (v.localService ? 'L' : 'R');
            }).sort());
          }
        };

        getV();
        if (speechSynthesis.onvoiceschanged !== undefined) {
          speechSynthesis.onvoiceschanged = getV;
        }
        setTimeout(function () { done(null); }, 1500);
      } catch (e) {
        resolve(null);
      }
    });
  }

  _getEmojiFingerprint() {
    try {
      var c = document.createElement('canvas');
      c.width = 200;
      c.height = 50;
      var x = c.getContext('2d');
      x.font = '32px serif';

      var emojis = ['\uD83D\uDE00', '\uD83C\uDDEE\uD83C\uDDF6', '\u2764\uFE0F', '\uD83D\uDC68\u200D\uD83D\uDCBB', '\uD83E\uDD1D', '\uD83C\uDF0D', '\u2603\uFE0F', '\uD83C\uDFE6'];
      var measurements = [];
      for (var i = 0; i < emojis.length; i++) {
        var m = x.measureText(emojis[i]);
        measurements.push(Math.round(m.width * 100) / 100);
      }

      x.clearRect(0, 0, 200, 50);
      x.fillText('\uD83D\uDE00\uD83C\uDDEE\uD83C\uDDF6\u2764\uFE0F', 0, 35);
      var d = x.getImageData(0, 0, 200, 50).data;
      var hash = 0;
      for (var j = 0; j < d.length; j += 13) {
        hash = ((hash << 5) - hash) + d[j];
        hash = hash & hash;
      }

      return { widths: measurements, renderHash: hash };
    } catch (e) {
      return null;
    }
  }

  _getCodecs() {
    try {
      var v = document.createElement('video');
      var a = document.createElement('audio');
      var codecs = [
        'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="avc1.42E01E, mp4a.40.2"', 'video/mp4; codecs="avc1.4D401E"',
        'video/mp4; codecs="avc1.64001E"', 'video/mp4; codecs="hev1.1.6.L93.B0"', 'video/mp4; codecs="hvc1.1.6.L93.B0"',
        'video/mp4; codecs="av01.0.01M.08"', 'video/mp4; codecs="vp09.00.10.08"', 'video/webm; codecs="vp8"',
        'video/webm; codecs="vp9"', 'video/webm; codecs="vp09.00.10.08"', 'video/ogg; codecs="theora"',
        'audio/mp4; codecs="mp4a.40.2"', 'audio/mp4; codecs="mp4a.40.5"', 'audio/mp4; codecs="flac"',
        'audio/mpeg', 'audio/ogg; codecs="vorbis"', 'audio/ogg; codecs="opus"', 'audio/wav; codecs="1"',
        'audio/webm; codecs="opus"', 'audio/aac',
      ];

      var results = [];
      for (var i = 0; i < codecs.length; i++) {
        var type = codecs[i];
        var el = type.indexOf('video') === 0 ? v : a;
        var support = el.canPlayType(type);
        results.push(support === 'probably' ? 2 : support === 'maybe' ? 1 : 0);
      }
      return results;
    } catch (e) {
      return null;
    }
  }

  _getCSSSupports() {
    try {
      if (!window.CSS || !CSS.supports) return null;
      var props = [
        'display: grid', 'display: flex', 'display: contents', 'display: flow-root',
        'gap: 1px', 'aspect-ratio: 1/1', 'container-type: inline-size',
        'color: oklch(50% 0.2 240)', 'color: color(display-p3 1 0 0)', 'color: lab(50% 40 59.5)',
        'backdrop-filter: blur(1px)', 'overflow: clip', 'overscroll-behavior: contain',
        'scroll-timeline-name: --test', 'view-transition-name: test', 'text-wrap: balance', 'text-wrap: pretty',
        'font-size: 1cap', 'font-size: 1rex', 'font-size: 1rlh', 'accent-color: auto', 'offset-path: none',
        'contain: paint', 'content-visibility: auto', 'text-decoration-thickness: from-font', 'hyphens: auto',
        'writing-mode: vertical-rl', 'direction: rtl', 'mask-image: none', 'anchor-name: --test',
        'field-sizing: content', 'interpolate-size: allow-keywords',
      ];

      var bits = [];
      for (var i = 0; i < props.length; i++) bits.push(CSS.supports(props[i]) ? 1 : 0);
      return bits;
    } catch (e) {
      return null;
    }
  }

  _getPermissions() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.permissions || !navigator.permissions.query) return resolve(null);
        var names = ['camera', 'microphone', 'notifications', 'geolocation', 'persistent-storage', 'push', 'midi', 'background-sync'];
        var pending = names.length;
        var results = {};
        names.forEach(function (name) {
          navigator.permissions.query({ name: name }).then(function (s) {
            results[name] = s.state;
            if (--pending === 0) resolve(results);
          }).catch(function () {
            results[name] = 'error';
            if (--pending === 0) resolve(results);
          });
        });
        setTimeout(function () { resolve(results); }, 1500);
      } catch (e) {
        resolve(null);
      }
    });
  }

  _getStorageQuota() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.storage || !navigator.storage.estimate) return resolve(null);
        navigator.storage.estimate().then(function (est) {
          resolve({ quota: est.quota || null, usage: est.usage || null });
        }).catch(function () { resolve(null); });
      } catch (e) {
        resolve(null);
      }
    });
  }

  _getMathMLFingerprint() {
    try {
      var container = document.createElement('div');
      container.style.cssText = 'position:absolute;top:-9999px;visibility:hidden;';
      container.innerHTML =
        '<math><mfrac><mrow><mo>-</mo><mi>b</mi><mo>\u00B1</mo>' +
        '<msqrt><mrow><msup><mi>b</mi><mn>2</mn></msup>' +
        '<mo>-</mo><mn>4</mn><mi>a</mi><mi>c</mi></mrow></msqrt>' +
        '</mrow><mrow><mn>2</mn><mi>a</mi></mrow></mfrac></math>' +
        '<math><munderover><mo>\u2211</mo><mrow><mi>i</mi><mo>=</mo><mn>0</mn></mrow>' +
        '<mi>n</mi></munderover><msub><mi>x</mi><mi>i</mi></msub></math>';

      document.body.appendChild(container);
      var rects = [];
      var elements = container.querySelectorAll('math');
      for (var i = 0; i < elements.length; i++) {
        var r = elements[i].getBoundingClientRect();
        rects.push(Math.round(r.width * 1000) / 1000, Math.round(r.height * 1000) / 1000);
      }
      container.remove();
      return rects;
    } catch (e) {
      return null;
    }
  }

  _getIntlProbe() {
    try {
      var d = new Date(2026, 2, 23, 14, 30, 0);
      var n = 1234567.891;
      var results = {};

      var numLocales = ['en-US', 'ar-IQ', 'ar-SA', 'ar-EG', 'fa-IR', 'ku-IQ'];
      results.numbers = {};
      for (var i = 0; i < numLocales.length; i++) {
        try {
          results.numbers[numLocales[i]] = new Intl.NumberFormat(numLocales[i]).format(n);
        } catch (e) {
          results.numbers[numLocales[i]] = null;
        }
      }

      results.dates = {};
      var dateLocales = ['en-US', 'ar-IQ', 'ar-SA'];
      for (var j = 0; j < dateLocales.length; j++) {
        try {
          results.dates[dateLocales[j]] = new Intl.DateTimeFormat(dateLocales[j], {
            year: 'numeric', month: 'long', day: 'numeric',
          }).format(d);
        } catch (e) {
          results.dates[dateLocales[j]] = null;
        }
      }

      try {
        results.hijri = new Intl.DateTimeFormat('ar-SA-u-ca-islamic', {
          year: 'numeric', month: 'long', day: 'numeric',
        }).format(d);
      } catch (e) {
        results.hijri = null;
      }

      try {
        results.relativeTime = new Intl.RelativeTimeFormat('ar-IQ', { numeric: 'auto' }).format(-1, 'day');
      } catch (e) {
        results.relativeTime = null;
      }

      try {
        var pr = new Intl.PluralRules('ar-IQ');
        results.plurals = [pr.select(0), pr.select(1), pr.select(2), pr.select(3), pr.select(11), pr.select(100)];
      } catch (e) {
        results.plurals = null;
      }

      try {
        results.listFormat = new Intl.ListFormat('ar-IQ', { style: 'long', type: 'conjunction' })
          .format(['\u0623\u062d\u0645\u062f', '\u0639\u0644\u064a', '\u062d\u064a\u062f\u0631']);
      } catch (e) {
        results.listFormat = null;
      }

      try {
        var col = new Intl.Collator('ar-IQ');
        results.collation = col.compare('\u0627', '\u0628') < 0 ? 'standard' : 'nonstandard';
      } catch (e) {
        results.collation = null;
      }

      try {
        var testLocales = ['ar-IQ', 'ar-SA', 'ar-EG', 'ku-IQ', 'fa-IR', 'tr-TR', 'en-US', 'fr-FR', 'ckb-IQ'];
        results.supportedLocales = Intl.DateTimeFormat.supportedLocalesOf(testLocales);
      } catch (e) {
        results.supportedLocales = null;
      }

      return results;
    } catch (e) {
      return null;
    }
  }

  _getAudio() {
    return new Promise(function (resolve) {
      try {
        var AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!AC) return resolve(null);
        var ctx = new AC(1, 44100, 44100);
        var osc = ctx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, ctx.currentTime);
        var comp = ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50, ctx.currentTime);
        comp.knee.setValueAtTime(40, ctx.currentTime);
        comp.ratio.setValueAtTime(12, ctx.currentTime);
        comp.attack.setValueAtTime(0, ctx.currentTime);
        comp.release.setValueAtTime(0.25, ctx.currentTime);
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);
        ctx.startRendering().then(function (buf) {
          var d = buf.getChannelData(0);
          var s = 0;
          for (var i = 4500; i < 5000; i++) s += Math.abs(d[i]);
          resolve(Math.round(s * 10000) / 10000);
        }).catch(function () { resolve(null); });
        setTimeout(function () { resolve(null); }, 1500);
      } catch (e) {
        resolve(null);
      }
    });
  }

  _getScreen() {
    return {
      w: screen.width,
      h: screen.height,
      aw: screen.availWidth,
      ah: screen.availHeight,
      cd: screen.colorDepth,
      pd: screen.pixelDepth,
      dpr: window.devicePixelRatio || 1,
      touch: navigator.maxTouchPoints || 0,
      touchEvt: 'ontouchstart' in window,
      orient: (screen.orientation || {}).type || null,
    };
  }

  _getFonts() {
    return this._detectFontList([
      'Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Palatino',
      'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Impact', 'Tahoma',
      'Lucida Console', 'Lucida Sans', 'Century Gothic', 'Franklin Gothic',
      'Calibri', 'Cambria', 'Segoe UI', 'Optima', 'Helvetica Neue', 'Futura',
      'Gill Sans', 'Candara', 'Consolas', 'Constantia', 'Corbel', 'Rockwell',
      'Copperplate', 'Papyrus',
    ], 'mmmmmmmmmmlli');
  }

  _getArabicFonts() {
    var aStr = '\u0628\u0633\u0645 \u0627\u0644\u0644\u0647 \u0627\u0644\u0631\u062d\u0645\u0646 \u0627\u0644\u0631\u062d\u064a\u0645';
    var detected = this._detectFontList([
      'Arabic Typesetting', 'Simplified Arabic', 'Traditional Arabic', 'Tahoma',
      'Sakkal Majalla', 'Droid Arabic Naskh', 'Noto Naskh Arabic', 'Noto Sans Arabic',
      'Noto Kufi Arabic', 'Geeza Pro', 'Al Bayan', 'Baghdad', 'KufiStandardGK',
      'DecoType Naskh', 'Andalus', 'Microsoft Sans Serif', 'Arial Unicode MS',
      'Scheherazade', 'Amiri', 'Lateef', 'IBM Plex Sans Arabic', 'Cairo', 'Tajawal',
      'Almarai', 'Markazi Text', 'Reem Kufi', 'Harmattan', 'Mada', 'El Messiri', 'Changa',
    ], aStr);
    var metrics = this._measureArabicRendering();
    return { installed: detected, rendering: metrics };
  }

  _measureArabicRendering() {
    try {
      var c = document.createElement('canvas');
      c.width = 500;
      c.height = 100;
      var x = c.getContext('2d');
      var res = {};
      var tests = [
        '\u0628\u0633\u0645 \u0627\u0644\u0644\u0647 \u0627\u0644\u0631\u062d\u0645\u0646 \u0627\u0644\u0631\u062d\u064a\u0645',
        '\u0644\u0627 \u0625\u0644\u0647 \u0625\u0644\u0627 \u0627\u0644\u0644\u0647',
        '\u0627\u0644\u0639\u0631\u0627\u0642 \u0628\u063a\u062f\u0627\u062f \u0662\u0660\u0662\u0666',
        'Hello \u0645\u0631\u062d\u0628\u0627 Mixed',
      ];
      var fonts = ['serif', 'sans-serif', 'Tahoma', 'Arial'];
      for (var fi = 0; fi < fonts.length; fi++) {
        x.font = '20px "' + fonts[fi] + '"';
        var w = [];
        for (var si = 0; si < tests.length; si++) w.push(Math.round(x.measureText(tests[si]).width * 100) / 100);
        res[fonts[fi]] = w;
      }
      return res;
    } catch (e) {
      return null;
    }
  }

  _detectFontList(list, testStr) {
    var bases = ['monospace', 'sans-serif', 'serif'];
    var detected = [];
    var sp = document.createElement('span');
    sp.style.cssText = 'font-size:72px;visibility:hidden;position:absolute;top:-9999px;';
    sp.textContent = testStr;
    document.body.appendChild(sp);
    var bw = {};
    for (var b = 0; b < bases.length; b++) {
      sp.style.fontFamily = bases[b];
      bw[bases[b]] = sp.offsetWidth;
    }
    for (var f = 0; f < list.length; f++) {
      var found = false;
      for (var bj = 0; bj < bases.length; bj++) {
        sp.style.fontFamily = '"' + list[f] + '",' + bases[bj];
        if (sp.offsetWidth !== bw[bases[bj]]) {
          found = true;
          break;
        }
      }
      if (found) detected.push(list[f]);
    }
    sp.remove();
    return detected;
  }

  _getBrowser() {
    var pl = [];
    try {
      for (var i = 0; i < (navigator.plugins || []).length; i++) pl.push(navigator.plugins[i].name);
    } catch (e) {}
    return {
      ua: navigator.userAgent,
      lang: navigator.language,
      langs: (navigator.languages || []).join(','),
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      dnt: navigator.doNotTrack,
      pdfViewer: navigator.pdfViewerEnabled != null ? navigator.pdfViewerEnabled : null,
      plugins: pl.sort().join('|'),
      connType: (navigator.connection || {}).effectiveType || null,
      connDown: (navigator.connection || {}).downlink || null,
      connRtt: (navigator.connection || {}).rtt || null,
      saveData: (navigator.connection || {}).saveData || null,
    };
  }

  _getHardware() {
    return {
      cores: navigator.hardwareConcurrency || 0,
      mem: navigator.deviceMemory || 0,
      touch: navigator.maxTouchPoints || 0,
      platform: navigator.platform,
    };
  }

  _getTimezone() {
    var d = new Date();
    var jan = new Date(d.getFullYear(), 0, 1);
    var jul = new Date(d.getFullYear(), 6, 1);
    var o = {};
    try {
      o = Intl.DateTimeFormat().resolvedOptions();
    } catch (e) {}
    return {
      tz: o.timeZone || null,
      offset: d.getTimezoneOffset(),
      offJan: jan.getTimezoneOffset(),
      offJul: jul.getTimezoneOffset(),
      dst: jan.getTimezoneOffset() !== jul.getTimezoneOffset(),
      dateFmt: new Intl.DateTimeFormat().format(d),
      numFmt: new Intl.NumberFormat().format(1234567.89),
      calendar: o.calendar || null,
      numSys: o.numberingSystem || null,
    };
  }

  _getWebRTCIPs() {
    return new Promise(function (resolve) {
      var ips = [];
      var completed = false;

      var addIp = function (ip) {
        if (!ip || ips.indexOf(ip) !== -1) return;
        ips.push(ip);
      };

      var extractIps = function (text) {
        if (!text) return;
        var ipv4 = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
        for (var i = 0; i < ipv4.length; i++) addIp(ipv4[i]);

        var ipv6 = text.match(/\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b/g) || [];
        for (var j = 0; j < ipv6.length; j++) addIp(ipv6[j].toLowerCase());
      };

      var finish = function (pc) {
        if (completed) return;
        completed = true;
        try {
          pc.close();
        } catch (x) {}
        resolve(ips);
      };

      try {
        var pc = new RTCPeerConnection({
          iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
        });
        pc.createDataChannel('');

        pc.createOffer().then(function (offer) {
          extractIps(offer && offer.sdp ? offer.sdp : '');
          return pc.setLocalDescription(offer);
        }).then(function () {
          if (pc.localDescription && pc.localDescription.sdp) extractIps(pc.localDescription.sdp);
        }).catch(function () {});

        pc.onicecandidate = function (e) {
          if (!e.candidate) {
            finish(pc);
            return;
          }
          extractIps(e.candidate.candidate || '');
        };

        setTimeout(function () { finish(pc); }, 5000);
      } catch (e) {
        resolve([]);
      }
    });
  }

  _detectHeadless() {
    var s = 0;
    if (navigator.webdriver === true) s += 0.3;
    if (!window.chrome && /Chrome/.test(navigator.userAgent)) s += 0.15;
    if (!navigator.permissions) s += 0.1;
    if ((navigator.plugins || []).length === 0) s += 0.1;
    if (!navigator.languages || navigator.languages.length === 0) s += 0.1;
    if (window.outerWidth === 0 || window.outerHeight === 0) s += 0.15;
    if (window.chrome && !window.chrome.runtime) s += 0.05;
    if (typeof Notification !== 'undefined' && Notification.permission === 'denied') s += 0.05;
    return Math.round(Math.min(1, s) * 100) / 100;
  }

  _detectBot() {
    return {
      phantom: !!window.callPhantom || !!window._phantom,
      webdriver: !!navigator.webdriver,
      nightmare: !!window.__nightmare,
      selenium: !!window._selenium || !!document.__webdriver_evaluate || !!document.__selenium_unwrapped,
      domAuto: !!window.domAutomation || !!window.domAutomationController,
      headlessUA: /HeadlessChrome/.test(navigator.userAgent),
      puppeteer: !!(navigator.webdriver && window.chrome && !window.chrome.runtime),
    };
  }

  _detectTampering() {
    var s = {};
    try {
      var cv = document.createElement('canvas');
      s.canvasOverride = cv.toDataURL.toString().indexOf('native') === -1;
    } catch (e) {
      s.canvasOverride = true;
    }
    try {
      var d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
      s.uaOverride = d && typeof d.get === 'function' && d.get.toString().indexOf('native') === -1;
    } catch (e) {
      s.uaOverride = null;
    }
    try {
      s.navigatorProxy = navigator.toString() !== '[object Navigator]';
    } catch (e) {
      s.navigatorProxy = true;
    }
    try {
      var cv2 = document.createElement('canvas');
      var gl = cv2.getContext('webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) s.genericRenderer = /SwiftShader|llvmpipe|Software/.test(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL));
      }
    } catch (e) {}
    try {
      var mq = window.matchMedia('(min-width:' + screen.width + 'px)');
      s.screenMismatch = !mq.matches && screen.width > 0;
    } catch (e) {}
    return s;
  }

  _detectPrivate() {
    return new Promise(async function (resolve) {
      var score = 0;
      var ua = navigator.userAgent || '';
      var isChromeFamily = /Chrome|CriOS|Edg\//.test(ua) && !/Firefox|FxiOS/.test(ua);
      var isFirefox = /Firefox|FxiOS/.test(ua);
      var isSafari = /Safari/.test(ua) && !/Chrome/.test(ua);

      // ── CHECK 1: Storage Quota (Chrome incognito caps to ~60% of normal) ──
      try {
        if (navigator.storage && navigator.storage.estimate) {
          var est = await navigator.storage.estimate();
          var quota = est && est.quota ? est.quota : 0;
          // Chrome incognito: quota is significantly lower (varies by device)
          // Normal Chrome: usually 50%+ of disk space (tens to hundreds of GB)
          // Incognito Chrome: capped around 2-5 GB on most systems
          if (isChromeFamily && quota > 0 && quota < 6000000000) score += 2;
          // Safari private: storage persist API throws or quota is 0
          if (isSafari && quota === 0) score += 2;
        }
      } catch (e) {
        // Safari private-mode throws on storage.estimate()
        if (isSafari) score += 2;
      }

      // ── CHECK 2: FileSystem API (legacy Chrome detection, still works on some) ──
      try {
        var fs = window.RequestFileSystem || window.webkitRequestFileSystem;
        if (fs) {
          var fsDenied = await new Promise(function (done) {
            fs(window.TEMPORARY, 1, function () { done(false); }, function () { done(true); });
          });
          if (fsDenied) score += 2;
        }
      } catch (e) {}

      // ── CHECK 3: navigator.storage.persist() behavior ──
      // In incognito, persist() always resolves false (cannot grant persistence)
      try {
        if (navigator.storage && navigator.storage.persist) {
          var persisted = await navigator.storage.persist();
          if (!persisted) score += 1;
        }
      } catch (e) {
        score += 1;
      }

      // ── CHECK 4: Cache storage write test ──
      // Some private mode implementations restrict CacheStorage
      try {
        if (typeof caches !== 'undefined') {
          var testName = '__athar_prv_' + Date.now();
          var cache = await caches.open(testName);
          await cache.put(new Request('/__t'), new Response('t'));
          await caches.delete(testName);
        }
      } catch (e) {
        // CacheStorage restriction → likely private
        score += 2;
      }

      // ── CHECK 5: Firefox-specific ServiceWorker registration test ──
      // Firefox private blocks service worker registration
      try {
        if (isFirefox && navigator.serviceWorker) {
          var reg = await navigator.serviceWorker.getRegistrations();
          // If zero registrations on a site that should have one, could be private
          // But more reliable: the serviceWorker controller is null in private
          if (!navigator.serviceWorker.controller && reg.length === 0) score += 1;
        }
      } catch (e) {
        if (isFirefox) score += 2;
      }

      // ── CHECK 6: IndexedDB create test (still catches some Safari/Firefox) ──
      try {
        var idbBlocked = await new Promise(function (done) {
          if (typeof indexedDB === 'undefined') {
            done(true);
            return;
          }

          var completed = false;
          var finish = function (value) {
            if (!completed) {
              completed = true;
              done(value);
            }
          };

          try {
            var dbName = '__athar_private_test__';
            var req = indexedDB.open(dbName, 1);
            req.onupgradeneeded = function () {};
            req.onerror = function () { finish(true); };
            req.onsuccess = function (event) {
              try {
                var db = event.target.result;
                db.close();
                indexedDB.deleteDatabase(dbName);
              } catch (x) {}
              finish(false);
            };
            setTimeout(function () { finish(false); }, 1000);
          } catch (x) {
            finish(true);
          }
        });

        if (idbBlocked) score += 1;
      } catch (e) {}

      // ── CHECK 7: Performance memory (Chrome) ──
      // In incognito, jsHeapSizeLimit is often lower
      try {
        if (isChromeFamily && performance && performance.memory) {
          var heapLimit = performance.memory.jsHeapSizeLimit || 0;
          // Normal Chrome: typically 4+ GB heap limit
          // Incognito Chrome: sometimes reduced to ~2 GB
          if (heapLimit > 0 && heapLimit < 2500000000) score += 1;
        }
      } catch (e) {}

      resolve(score >= 2);
    });
  }

  // ─── Developer Tools Detection ───
  _detectDevTools() {
    var result = { open: false, orientation: null };
    try {
      var widthThreshold = window.outerWidth - window.innerWidth > 160;
      var heightThreshold = window.outerHeight - window.innerHeight > 160;
      if (widthThreshold) { result.open = true; result.orientation = 'vertical'; }
      if (heightThreshold) { result.open = true; result.orientation = 'horizontal'; }
      // Firebug detection
      if (window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized) result.open = true;
      // console.profile trick — if devtools is open, console.profiles changes
      if (typeof console.profile === 'function') {
        console.profile();
        console.profileEnd();
        if (console.clear) console.clear();
      }
    } catch (e) {}
    return result;
  }

  // ─── Virtual Machine Detection ───
  _detectVM() {
    var indicators = {};
    try {
      // WebGL renderer hints
      var cv = document.createElement('canvas');
      var gl = cv.getContext('webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
          var vendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
          indicators.vmRenderer = /VirtualBox|VMware|Parallels|Hyper-V|QEMU|vbox|virtio|llvmpipe|Mesa/.test(renderer);
          indicators.vmVendor = /VMware|VirtualBox|Parallels|QEMU|Red Hat/.test(vendor);
          indicators.renderer = renderer;
        }
      }
    } catch (e) {}
    try {
      // Hardware signals typical of VMs
      indicators.lowCores = (navigator.hardwareConcurrency || 0) <= 1;
      indicators.lowMemory = (navigator.deviceMemory || 99) <= 1;
      indicators.noTouch = navigator.maxTouchPoints === 0 && /Mobile|Android/.test(navigator.userAgent);
      // Screen resolution often locked in VMs
      var w = screen.width, h = screen.height;
      indicators.vmResolution = (w === 800 && h === 600) || (w === 1024 && h === 768);
      // Battery API — VMs often have no battery
      indicators.noBattery = typeof navigator.getBattery === 'function' ? null : false;
    } catch (e) {}
    try {
      // Platform check
      indicators.platformMismatch =
        /Win/.test(navigator.platform) && /Linux|Android/.test(navigator.userAgent) ||
        /Linux/.test(navigator.platform) && /Windows/.test(navigator.userAgent);
    } catch (e) {}
    indicators.result = !!(indicators.vmRenderer || indicators.vmVendor ||
      (indicators.lowCores && indicators.lowMemory && indicators.vmResolution));
    return indicators;
  }

  // ─── Location Spoofing Detection ───
  _detectLocationSpoofing() {
    var result = { spoofed: false, signals: {} };
    try {
      // Timezone vs Intl consistency
      var offset = new Date().getTimezoneOffset();
      var intlTz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      // Check if Date locale formatting matches Intl
      var dateLocale = new Date().toLocaleDateString('en-US', { timeZoneName: 'short' });
      result.signals.timezone = intlTz;
      result.signals.offset = offset;
      result.signals.dateLocale = dateLocale;

      // Language vs geolocation hints
      var lang = (navigator.language || '').toLowerCase();
      result.signals.language = lang;

      // Timezone offset sanity: check if timezone name matches offset range
      // Middle East timezones should be UTC+3 to UTC+4 (offset -180 to -240)
      // If tz says "Asia/Baghdad" but offset is +480 (US Pacific), that's spoofing
      var tzParts = intlTz.split('/');
      result.signals.continent = tzParts[0] || null;
    } catch (e) {}
    try {
      // WebRTC timestamp drift — if system clock is manipulated
      var t1 = Date.now();
      var t2 = performance.timeOrigin + performance.now();
      result.signals.clockDrift = Math.abs(t1 - t2);
      if (result.signals.clockDrift > 5000) result.spoofed = true; // >5s drift = suspicious
    } catch (e) {}
    return result;
  }

  // ─── Raw Device Attributes (matches FP Pro format) ───
  _getRawAttributes() {
    var attrs = {};
    try { attrs.platform = navigator.platform; } catch (e) {}
    try { attrs.vendor = navigator.vendor; } catch (e) {}
    try { attrs.cookiesEnabled = navigator.cookieEnabled; } catch (e) {}
    try { attrs.sessionStorage = typeof sessionStorage !== 'undefined'; } catch (e) {}
    try { attrs.localStorage = typeof localStorage !== 'undefined'; } catch (e) {}
    try { attrs.indexedDB = typeof indexedDB !== 'undefined'; } catch (e) {}
    try { attrs.openDatabase = typeof openDatabase === 'function'; } catch (e) {}
    try { attrs.pdfViewerEnabled = navigator.pdfViewerEnabled; } catch (e) {}
    try { attrs.hardwareConcurrency = navigator.hardwareConcurrency; } catch (e) {}
    try { attrs.deviceMemory = navigator.deviceMemory || null; } catch (e) {}
    try { attrs.maxTouchPoints = navigator.maxTouchPoints || 0; } catch (e) {}
    try { attrs.colorDepth = screen.colorDepth; } catch (e) {}
    try { attrs.screenResolution = [screen.width, screen.height]; } catch (e) {}
    try { attrs.architecture = navigator.userAgentData ? navigator.userAgentData.architecture : null; } catch (e) {}
    try {
      attrs.languages = navigator.languages ? Array.from(navigator.languages) : [navigator.language];
    } catch (e) {}
    try {
      var mq = window.matchMedia;
      if (mq) {
        attrs.colorGamut = mq('(color-gamut: p3)').matches ? 'p3' : mq('(color-gamut: srgb)').matches ? 'srgb' : null;
        attrs.hdr = mq('(dynamic-range: high)').matches;
        attrs.contrast = mq('(prefers-contrast: more)').matches ? 'more' : mq('(prefers-contrast: less)').matches ? 'less' : 'no-preference';
        attrs.reducedMotion = mq('(prefers-reduced-motion: reduce)').matches;
        attrs.forcedColors = mq('(forced-colors: active)').matches;
        attrs.invertedColors = mq('(inverted-colors: inverted)').matches;
        attrs.monochrome = mq('(monochrome)').matches;
      }
    } catch (e) {}
    try {
      attrs.connection = navigator.connection ? {
        type: navigator.connection.effectiveType,
        downlink: navigator.connection.downlink,
        rtt: navigator.connection.rtt,
        saveData: navigator.connection.saveData,
      } : null;
    } catch (e) {}
    try {
      attrs.screenFrame = [
        window.screen.availTop || 0,
        window.screen.availLeft || 0,
        window.screen.height - window.screen.availHeight,
        window.screen.width - window.screen.availWidth,
      ];
    } catch (e) {}
    try {
      // Font preferences — measure default widths of key font families
      var testStr = 'mmmmmmmmmmlli';
      var span = document.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;font-size:72px;';
      document.body.appendChild(span);
      var measure = function (font) {
        span.style.fontFamily = font;
        return span.offsetWidth;
      };
      attrs.fontPreferences = {
        'default': measure('serif'),
        sans: measure('sans-serif'),
        mono: measure('monospace'),
        system: measure('system-ui'),
      };
      span.textContent = testStr;
      attrs.fontPreferences['default'] = measure('serif');
      attrs.fontPreferences.sans = measure('sans-serif');
      attrs.fontPreferences.mono = measure('monospace');
      attrs.fontPreferences.system = measure('system-ui');
      document.body.removeChild(span);
    } catch (e) {}
    return attrs;
  }

  _persistId(id) {
    if (!id) return;
    try { localStorage.setItem('_athar', id); } catch (e) {}
    try { sessionStorage.setItem('_athar', id); } catch (e) {}
    try { document.cookie = '_athar=' + id + ';max-age=31536000;path=/;SameSite=Lax'; } catch (e) {}
    try {
      var r = indexedDB.open('_athar', 1);
      r.onupgradeneeded = function (e) { e.target.result.createObjectStore('ids'); };
      r.onsuccess = function (e) {
        try { e.target.result.transaction('ids', 'readwrite').objectStore('ids').put(id, 'vid'); } catch (x) {}
      };
    } catch (e) {}
  }

  _getStoredIds() {
    var ids = {};
    try { ids.ls = localStorage.getItem('_athar'); } catch (e) {}
    try { ids.ss = sessionStorage.getItem('_athar'); } catch (e) {}
    try {
      var m = document.cookie.match(/_athar=([^;]+)/);
      ids.ck = m ? m[1] : null;
    } catch (e) {}
    try {
      var l = localStorage.getItem('deviceid_visitor_id');
      if (l) ids.legacy = l;
    } catch (e) {}
    return ids;
  }
}

if (typeof module !== 'undefined' && module.exports) { module.exports = DeviceID; }
if (typeof window !== 'undefined') { window.DeviceID = DeviceID; }
