/**
 * Athar (أثر) Browser SDK
 * Device intelligence for MENA financial services
 * Every device leaves a trace.
 * @version 2.0.0
 */

class DeviceID {
  constructor(options = {}) {
    this.apiKey = options.apiKey;
    this.apiEndpoint = options.apiEndpoint || 'https://api.arch-hayder.workers.dev/v1/fingerprint';
    this.debug = options.debug || false;
    this._cache = null;
    this._cacheExpiry = 0;
  }

  async identify() {
    if (this._cache && Date.now() < this._cacheExpiry) {
      return this._cache;
    }
    try {
      var signals = await this.collectSignals();
      if (this.debug) console.log('[Athar] Signals collected:', signals);

      var response = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': this.apiKey },
        body: JSON.stringify(signals),
      });

      if (!response.ok) throw new Error('API error: ' + response.status);
      var result = await response.json();

      if (result.visitorId) this._persistId(result.visitorId);

      this._cache = result;
      this._cacheExpiry = Date.now() + 300000;
      return result;
    } catch (err) {
      if (this.debug) console.error('[Athar] Error:', err);
      throw err;
    }
  }

  async collectSignals() {
    var t0 = performance.now();
    var audioP = this._getAudio();
    var webrtcP = this._getWebRTCIPs();
    var privP = this._detectPrivate();
    var audioResult = await audioP;
    var webrtcResult = await webrtcP;
    var privResult = await privP;

    return {
      v: '2.0.0',
      ts: Date.now(),
      canvas: this._getCanvas(),
      webgl: this._getWebGL(),
      audio: audioResult,
      screen: this._getScreen(),
      fonts: this._getFonts(),
      arabicFonts: this._getArabicFonts(),
      browser: this._getBrowser(),
      hardware: this._getHardware(),
      timezone: this._getTimezone(),
      evasion: {
        headlessScore: this._detectHeadless(),
        isPrivate: privResult,
        webrtcIPs: webrtcResult,
        bot: this._detectBot(),
        tampering: this._detectTampering(),
      },
      storedIds: this._getStoredIds(),
      collectionMs: Math.round(performance.now() - t0),
    };
  }

  // ============================================================
  // CANVAS — larger, more ops, Arabic text, full dataURL
  // ============================================================
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
      x.fillText('Athar,canvas,fp', 2, 15);
      x.fillStyle = 'rgba(102, 204, 0, 0.7)';
      x.font = '18pt Arial';
      x.fillText('Athar,canvas,fp', 4, 45);

      // Arabic text — renders differently per device/OS/font engine
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
      g.addColorStop(1.0, 'blue');
      x.fillStyle = g;
      x.fillRect(0, 90, 256, 38);

      return c.toDataURL();
    } catch (e) {
      return null;
    }
  }

  // ============================================================
  // WEBGL — full parameter set + extensions
  // ============================================================
  _getWebGL() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;

      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

      var maxAniso = null;
      var anisoExt = gl.getExtension('EXT_texture_filter_anisotropic');
      if (anisoExt) maxAniso = gl.getParameter(anisoExt.MAX_TEXTURE_MAX_ANISOTROPY_EXT);

      return {
        vendor: vendor,
        renderer: renderer,
        version: gl.getParameter(gl.VERSION),
        shadingLang: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewport: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)),
        maxRenderbuffer: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxAnisotropy: maxAniso,
        aliasedLineWidth: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)),
        aliasedPointSize: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)),
        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
        maxFragUniforms: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        maxVertUniforms: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        extensions: (gl.getSupportedExtensions() || []).sort(),
      };
    } catch (e) {
      return null;
    }
  }

  // ============================================================
  // AUDIO — OfflineAudioContext (proper method)
  // ============================================================
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
          var data = buf.getChannelData(0);
          var sum = 0;
          for (var i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
          resolve(Math.round(sum * 10000) / 10000);
        }).catch(function () { resolve(null); });

        setTimeout(function () { resolve(null); }, 1500);
      } catch (e) {
        resolve(null);
      }
    });
  }

  // ============================================================
  // SCREEN — expanded with orientation and touch
  // ============================================================
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
      touchEvent: 'ontouchstart' in window,
      orientation: (screen.orientation || {}).type || null,
    };
  }

  // ============================================================
  // LATIN FONTS — 30 fonts
  // ============================================================
  _getFonts() {
    var testFonts = [
      'Arial', 'Verdana', 'Times New Roman', 'Courier New',
      'Georgia', 'Palatino', 'Garamond', 'Bookman',
      'Comic Sans MS', 'Trebuchet MS', 'Impact', 'Tahoma',
      'Lucida Console', 'Lucida Sans', 'Century Gothic',
      'Franklin Gothic', 'Calibri', 'Cambria', 'Segoe UI',
      'Optima', 'Helvetica Neue', 'Futura', 'Gill Sans',
      'Candara', 'Consolas', 'Constantia', 'Corbel',
      'Rockwell', 'Copperplate', 'Papyrus',
    ];
    return this._detectFontList(testFonts, 'mmmmmmmmmmlli');
  }

  // ============================================================
  // ARABIC FONTS — 30 Arabic fonts + rendering metrics
  // ============================================================
  _getArabicFonts() {
    var arabicFonts = [
      'Arabic Typesetting', 'Simplified Arabic', 'Traditional Arabic',
      'Tahoma', 'Sakkal Majalla', 'Droid Arabic Naskh',
      'Noto Naskh Arabic', 'Noto Sans Arabic', 'Noto Kufi Arabic',
      'Geeza Pro', 'Al Bayan', 'Baghdad', 'KufiStandardGK',
      'DecoType Naskh', 'Andalus', 'Microsoft Sans Serif',
      'Arial Unicode MS', 'Scheherazade', 'Amiri', 'Lateef',
      'IBM Plex Sans Arabic', 'Cairo', 'Tajawal', 'Almarai',
      'Markazi Text', 'Reem Kufi', 'Harmattan', 'Mada',
      'El Messiri', 'Changa',
    ];

    var testStr = '\u0628\u0633\u0645 \u0627\u0644\u0644\u0647 \u0627\u0644\u0631\u062d\u0645\u0646 \u0627\u0644\u0631\u062d\u064a\u0645';
    var detected = this._detectFontList(arabicFonts, testStr);
    var metrics = this._measureArabicRendering();

    return { installed: detected, rendering: metrics };
  }

  _measureArabicRendering() {
    try {
      var c = document.createElement('canvas');
      c.width = 500;
      c.height = 100;
      var x = c.getContext('2d');
      var results = {};

      var tests = [
        '\u0628\u0633\u0645 \u0627\u0644\u0644\u0647 \u0627\u0644\u0631\u062d\u0645\u0646 \u0627\u0644\u0631\u062d\u064a\u0645',
        '\u0644\u0627 \u0625\u0644\u0647 \u0625\u0644\u0627 \u0627\u0644\u0644\u0647',
        '\u0627\u0644\u0639\u0631\u0627\u0642 \u0628\u063a\u062f\u0627\u062f \u0662\u0660\u0662\u0666',
        'Hello \u0645\u0631\u062d\u0628\u0627 Mixed',
      ];

      var fonts = ['serif', 'sans-serif', 'Tahoma', 'Arial'];
      for (var fi = 0; fi < fonts.length; fi++) {
        x.font = '20px "' + fonts[fi] + '"';
        var widths = [];
        for (var si = 0; si < tests.length; si++) {
          widths.push(Math.round(x.measureText(tests[si]).width * 100) / 100);
        }
        results[fonts[fi]] = widths;
      }
      return results;
    } catch (e) {
      return null;
    }
  }

  // ============================================================
  // FONT DETECTION ENGINE
  // ============================================================
  _detectFontList(fontList, testString) {
    var baseFonts = ['monospace', 'sans-serif', 'serif'];
    var detected = [];

    var span = document.createElement('span');
    span.style.fontSize = '72px';
    span.style.visibility = 'hidden';
    span.style.position = 'absolute';
    span.style.top = '-9999px';
    span.textContent = testString;
    document.body.appendChild(span);

    var baseWidths = {};
    for (var bi = 0; bi < baseFonts.length; bi++) {
      span.style.fontFamily = baseFonts[bi];
      baseWidths[baseFonts[bi]] = span.offsetWidth;
    }

    for (var fi = 0; fi < fontList.length; fi++) {
      var found = false;
      for (var bj = 0; bj < baseFonts.length; bj++) {
        span.style.fontFamily = '"' + fontList[fi] + '", ' + baseFonts[bj];
        if (span.offsetWidth !== baseWidths[baseFonts[bj]]) {
          found = true;
          break;
        }
      }
      if (found) detected.push(fontList[fi]);
    }

    span.remove();
    return detected;
  }

  // ============================================================
  // BROWSER — full navigator properties
  // ============================================================
  _getBrowser() {
    var plugins = [];
    try {
      for (var i = 0; i < (navigator.plugins || []).length; i++) {
        plugins.push(navigator.plugins[i].name);
      }
    } catch (e) {}

    return {
      ua: navigator.userAgent,
      lang: navigator.language,
      langs: (navigator.languages || []).join(','),
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      pdfViewer: navigator.pdfViewerEnabled != null ? navigator.pdfViewerEnabled : null,
      plugins: plugins.sort().join('|'),
      connectionType: (navigator.connection || {}).effectiveType || null,
      connectionDownlink: (navigator.connection || {}).downlink || null,
    };
  }

  // ============================================================
  // HARDWARE
  // ============================================================
  _getHardware() {
    return {
      cores: navigator.hardwareConcurrency || 0,
      memory: navigator.deviceMemory || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      platform: navigator.platform,
    };
  }

  // ============================================================
  // TIMEZONE — deep locale + calendar signals
  // ============================================================
  _getTimezone() {
    var d = new Date();
    var jan = new Date(d.getFullYear(), 0, 1);
    var jul = new Date(d.getFullYear(), 6, 1);
    var opts = {};
    try { opts = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}

    return {
      tz: opts.timeZone || null,
      offset: d.getTimezoneOffset(),
      offsetJan: jan.getTimezoneOffset(),
      offsetJul: jul.getTimezoneOffset(),
      dst: jan.getTimezoneOffset() !== jul.getTimezoneOffset(),
      dateFormat: new Intl.DateTimeFormat().format(d),
      numberFormat: new Intl.NumberFormat().format(1234567.89),
      calendar: opts.calendar || null,
      numberingSystem: opts.numberingSystem || null,
    };
  }

  // ============================================================
  // WEBRTC — IP leak detection (bypasses VPN)
  // ============================================================
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
        try { pc.close(); } catch (x) {}
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
          if (pc.localDescription && pc.localDescription.sdp) {
            extractIps(pc.localDescription.sdp);
          }
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

  // ============================================================
  // HEADLESS + BOT DETECTION — expanded
  // ============================================================
  _detectHeadless() {
    var score = 0;
    if (navigator.webdriver === true) score += 0.3;
    if (!window.chrome && /Chrome/.test(navigator.userAgent)) score += 0.15;
    if (!navigator.permissions) score += 0.1;
    if ((navigator.plugins || []).length === 0) score += 0.1;
    if (!navigator.languages || navigator.languages.length === 0) score += 0.1;
    if (window.outerWidth === 0 || window.outerHeight === 0) score += 0.15;
    if (window.chrome && !window.chrome.runtime) score += 0.05;
    if (typeof Notification !== 'undefined' && Notification.permission === 'denied') score += 0.05;
    return Math.round(Math.min(1, score) * 100) / 100;
  }

  _detectBot() {
    return {
      phantom: !!window.callPhantom || !!window._phantom,
      webdriver: !!navigator.webdriver,
      nightmare: !!window.__nightmare,
      selenium: !!window._selenium || !!document.__webdriver_evaluate || !!document.__selenium_unwrapped,
      domAutomation: !!window.domAutomation || !!window.domAutomationController,
      headlessUA: /HeadlessChrome/.test(navigator.userAgent),
      puppeteer: !!(navigator.webdriver && window.chrome && !window.chrome.runtime),
    };
  }

  // ============================================================
  // TAMPERING / ANTI-DETECT BROWSER DETECTION
  // ============================================================
  _detectTampering() {
    var s = {};

    try {
      var cv = document.createElement('canvas');
      s.canvasOverride = cv.toDataURL.toString().indexOf('native') === -1;
    } catch (e) { s.canvasOverride = true; }

    try {
      var desc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
      s.uaOverride = desc && typeof desc.get === 'function' && desc.get.toString().indexOf('native') === -1;
    } catch (e) { s.uaOverride = null; }

    try {
      s.navigatorProxy = navigator.toString() !== '[object Navigator]';
    } catch (e) { s.navigatorProxy = true; }

    try {
      var cv2 = document.createElement('canvas');
      var gl = cv2.getContext('webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          s.genericRenderer = /SwiftShader|llvmpipe|Software/.test(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL));
        }
      }
    } catch (e) {}

    try {
      var mq = window.matchMedia('(min-width: ' + screen.width + 'px)');
      s.screenMismatch = !mq.matches && screen.width > 0;
    } catch (e) {}

    return s;
  }

  // ============================================================
  // PRIVATE MODE DETECTION
  // ============================================================
  _detectPrivate() {
    return new Promise(async function (resolve) {
      var score = 0;

      // Chrome-family private windows usually report much lower storage quota.
      try {
        if (navigator.storage && navigator.storage.estimate) {
          var est = await navigator.storage.estimate();
          var quota = est && est.quota ? est.quota : 0;
          var ua = navigator.userAgent || '';
          var isChromeFamily = /Chrome|CriOS|Edg\//.test(ua) && !/Firefox|FxiOS/.test(ua);
          var lowQuotaThreshold = (navigator.deviceMemory || 4) <= 2 ? 120000000 : 320000000;
          if (isChromeFamily && quota > 0 && quota < lowQuotaThreshold) {
            score += 2;
          }
        }
      } catch (e) {}

      // Older WebKit private mode tends to deny temporary filesystem access.
      try {
        var fs = window.RequestFileSystem || window.webkitRequestFileSystem;
        if (fs) {
          var fsDenied = await new Promise(function (done) {
            fs(window.TEMPORARY, 1, function () { done(false); }, function () { done(true); });
          });
          if (fsDenied) {
            score += 2;
          }
        }
      } catch (e) {}

      // Firefox private mode and hardened browsers often block IndexedDB access.
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

        if (idbBlocked) {
          score += 1;
        }
      } catch (e) {}

      resolve(score >= 2);
    });
  }

  // ============================================================
  // EVERCOOKIE — persist across 4 mechanisms
  // ============================================================
  _persistId(visitorId) {
    if (!visitorId) return;
    try { localStorage.setItem('_athar', visitorId); } catch (e) {}
    try { sessionStorage.setItem('_athar', visitorId); } catch (e) {}
    try { document.cookie = '_athar=' + visitorId + ';max-age=31536000;path=/;SameSite=Lax'; } catch (e) {}
    try {
      var req = indexedDB.open('_athar', 1);
      req.onupgradeneeded = function (e) { e.target.result.createObjectStore('ids'); };
      req.onsuccess = function (e) {
        try { e.target.result.transaction('ids', 'readwrite').objectStore('ids').put(visitorId, 'vid'); } catch (x) {}
      };
    } catch (e) {}
  }

  _getStoredIds() {
    var ids = {};
    try { ids.ls = localStorage.getItem('_athar'); } catch (e) {}
    try { ids.ss = sessionStorage.getItem('_athar'); } catch (e) {}
    try { var m = document.cookie.match(/_athar=([^;]+)/); ids.ck = m ? m[1] : null; } catch (e) {}
    try { var leg = localStorage.getItem('deviceid_visitor_id'); if (leg) ids.legacy = leg; } catch (e) {}
    return ids;
  }
}

if (typeof module !== 'undefined' && module.exports) { module.exports = DeviceID; }
if (typeof window !== 'undefined') { window.DeviceID = DeviceID; }
