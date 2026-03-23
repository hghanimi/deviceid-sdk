/**
 * DeviceID SDK — Client-Side Fingerprint Collector
 * Lightweight browser fingerprinting for fraud prevention
 * 
 * Usage:
 *   const did = new DeviceID({ apiKey: 'pk_live_xxx' });
 *   const result = await did.identify();
 */
(function(window) {
  'use strict';

  const SDK_VERSION = '1.0.0';
  const DEFAULT_ENDPOINT = 'https://api.deviceid.io/v1/fingerprint';

  // ═══════════════════════════════════════════
  // SIGNAL COLLECTORS
  // ═══════════════════════════════════════════

  function getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 256;
      canvas.height = 128;
      const ctx = canvas.getContext('2d');

      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(100, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.font = '11pt "Times New Roman"';
      ctx.fillText('DeviceID,canvas,fp', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.font = '18pt Arial';
      ctx.fillText('DeviceID,canvas,fp', 4, 45);

      ctx.globalCompositeOperation = 'multiply';
      ctx.fillStyle = 'rgb(255,0,255)';
      ctx.beginPath();
      ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = 'rgb(0,255,255)';
      ctx.beginPath();
      ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fill();

      const gradient = ctx.createLinearGradient(0, 0, 256, 0);
      gradient.addColorStop(0, 'red');
      gradient.addColorStop(0.5, 'green');
      gradient.addColorStop(1.0, 'blue');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 80, 256, 48);

      return canvas.toDataURL();
    } catch (e) {
      return null;
    }
  }

  function getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');

      return {
        vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        extensions: (gl.getSupportedExtensions() || []).sort(),
        maxAnisotropy: (function() {
          var ext = gl.getExtension('EXT_texture_filter_anisotropic');
          return ext ? gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null;
        })(),
        aliasedLineWidthRange: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)),
        aliasedPointSizeRange: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)),
      };
    } catch (e) {
      return null;
    }
  }

  function getAudioFingerprint() {
    return new Promise(function(resolve) {
      try {
        var AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!AudioCtx) return resolve(null);

        var context = new AudioCtx(1, 44100, 44100);
        var oscillator = context.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, context.currentTime);

        var compressor = context.createDynamicsCompressor();
        compressor.threshold.setValueAtTime(-50, context.currentTime);
        compressor.knee.setValueAtTime(40, context.currentTime);
        compressor.ratio.setValueAtTime(12, context.currentTime);
        compressor.attack.setValueAtTime(0, context.currentTime);
        compressor.release.setValueAtTime(0.25, context.currentTime);

        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);

        context.startRendering().then(function(buffer) {
          var data = buffer.getChannelData(0);
          var sum = 0;
          for (var i = 4500; i < 5000; i++) {
            sum += Math.abs(data[i]);
          }
          resolve(sum);
        }).catch(function() { resolve(null); });

        setTimeout(function() { resolve(null); }, 1000);
      } catch (e) {
        resolve(null);
      }
    });
  }

  function getScreenSignals() {
    return {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      touchSupport: 'ontouchstart' in window,
    };
  }

  function getHardwareSignals() {
    return {
      cpuCores: navigator.hardwareConcurrency || null,
      deviceMemory: navigator.deviceMemory || null,
      platform: navigator.platform,
    };
  }

  function getBrowserSignals() {
    return {
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: (navigator.languages || [navigator.language]).join(','),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      pdfViewerEnabled: navigator.pdfViewerEnabled != null ? navigator.pdfViewerEnabled : null,
      plugins: Array.from(navigator.plugins || []).map(function(p) { return p.name; }).sort().join(','),
    };
  }

  function getInstalledFonts() {
    var testFonts = [
      'Arial', 'Verdana', 'Times New Roman', 'Courier New',
      'Georgia', 'Palatino', 'Garamond', 'Comic Sans MS',
      'Trebuchet MS', 'Impact', 'Tahoma', 'Lucida Console',
      'Lucida Sans', 'Century Gothic', 'Calibri', 'Cambria',
      'Segoe UI', 'Optima', 'Helvetica Neue', 'Futura', 'Gill Sans',
      'Arabic Typesetting', 'Simplified Arabic', 'Traditional Arabic',
      'Sakkal Majalla', 'Droid Arabic Naskh',
    ];

    var baseFonts = ['monospace', 'sans-serif', 'serif'];
    var testString = 'mmmmmmmmmmlli';
    var testSize = '72px';

    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');

    var baseWidths = {};
    baseFonts.forEach(function(font) {
      ctx.font = testSize + ' ' + font;
      baseWidths[font] = ctx.measureText(testString).width;
    });

    var detected = [];
    testFonts.forEach(function(font) {
      var isInstalled = baseFonts.some(function(base) {
        ctx.font = testSize + " '" + font + "', " + base;
        return ctx.measureText(testString).width !== baseWidths[base];
      });
      if (isInstalled) detected.push(font);
    });

    return detected;
  }

  function detectHeadless() {
    var score = 0;
    if (navigator.webdriver === true) score++;
    if (!window.chrome && /Chrome/.test(navigator.userAgent)) score++;
    if (!navigator.permissions) score++;
    if (navigator.plugins.length === 0) score++;
    if (!navigator.languages || navigator.languages.length === 0) score++;
    if (window.domAutomation) score++;
    return score;
  }

  function detectBot() {
    var botPatterns = /bot|crawl|spider|slurp|mediapartners|headless/i;
    return {
      uaBot: botPatterns.test(navigator.userAgent),
      webdriver: !!navigator.webdriver,
      noPlugins: navigator.plugins.length === 0,
      phantomjs: !!window._phantom || !!window.phantom,
      nightmare: !!window.__nightmare,
      selenium: !!window._selenium || !!document.__webdriver_evaluate,
    };
  }

  function getWebRTCIPs() {
    return new Promise(function(resolve) {
      var ips = [];
      try {
        var pc = new RTCPeerConnection({
          iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        pc.createDataChannel('');
        pc.createOffer().then(function(offer) {
          return pc.setLocalDescription(offer);
        });

        pc.onicecandidate = function(event) {
          if (!event.candidate) {
            pc.close();
            resolve(ips);
            return;
          }
          var match = event.candidate.candidate.match(/(\d{1,3}\.{0,1}){4}/);
          if (match && ips.indexOf(match[0]) === -1) ips.push(match[0]);
        };

        setTimeout(function() { pc.close(); resolve(ips); }, 3000);
      } catch (e) {
        resolve([]);
      }
    });
  }

  // ═══════════════════════════════════════════
  // STORAGE PERSISTENCE (EVERCOOKIE LAYER)
  // ═══════════════════════════════════════════

  function persistId(visitorId) {
    if (!visitorId) return;
    var stores = [
      function() { localStorage.setItem('_did', visitorId); },
      function() { sessionStorage.setItem('_did', visitorId); },
      function() {
        var req = indexedDB.open('_did', 1);
        req.onupgradeneeded = function(e) { e.target.result.createObjectStore('ids'); };
        req.onsuccess = function(e) {
          var tx = e.target.result.transaction('ids', 'readwrite');
          tx.objectStore('ids').put(visitorId, 'vid');
        };
      },
      function() {
        document.cookie = '_did=' + visitorId + ';max-age=31536000;path=/;SameSite=Lax';
      },
    ];
    stores.forEach(function(fn) { try { fn(); } catch(e) {} });
  }

  function getStoredIds() {
    var ids = {};
    try { ids.ls = localStorage.getItem('_did'); } catch(e) {}
    try { ids.ss = sessionStorage.getItem('_did'); } catch(e) {}
    try {
      var match = document.cookie.match(/_did=([^;]+)/);
      ids.cookie = match ? match[1] : null;
    } catch(e) {}
    return ids;
  }

  // ═══════════════════════════════════════════
  // MAIN SDK CLASS
  // ═══════════════════════════════════════════

  function DeviceID(config) {
    config = config || {};
    this.apiKey = config.apiKey;
    this.endpoint = config.endpoint || DEFAULT_ENDPOINT;
    this.timeout = config.timeout || 5000;
    this._cache = null;
    this._cacheExpiry = 0;

    if (!this.apiKey) {
      throw new Error('DeviceID: apiKey is required');
    }
  }

  DeviceID.prototype.identify = function() {
    var self = this;

    if (self._cache && Date.now() < self._cacheExpiry) {
      return Promise.resolve(self._cache);
    }

    return self._collectSignals().then(function(signals) {
      return self._send(signals);
    }).then(function(result) {
      self._cache = result;
      self._cacheExpiry = Date.now() + 300000;
      persistId(result.visitorId);
      return result;
    });
  };

  DeviceID.prototype._collectSignals = function() {
    var startTime = performance.now();

    return Promise.all([
      getAudioFingerprint(),
      getWebRTCIPs(),
    ]).then(function(results) {
      return {
        v: SDK_VERSION,
        ts: Date.now(),
        url: window.location.hostname,
        canvas: getCanvasFingerprint(),
        webgl: getWebGLFingerprint(),
        audio: results[0],
        screen: getScreenSignals(),
        hardware: getHardwareSignals(),
        browser: getBrowserSignals(),
        fonts: getInstalledFonts(),
        evasion: {
          headlessScore: detectHeadless(),
          bot: detectBot(),
          webrtcIPs: results[1],
        },
        storedIds: getStoredIds(),
        collectionTime: performance.now() - startTime,
      };
    });
  };

  DeviceID.prototype._send = function(signals) {
    var self = this;
    var controller = new AbortController();
    var timeout = setTimeout(function() { controller.abort(); }, self.timeout);

    return fetch(self.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': self.apiKey,
      },
      body: JSON.stringify(signals),
      signal: controller.signal,
    }).then(function(response) {
      clearTimeout(timeout);
      if (!response.ok) throw new Error('DeviceID API error: ' + response.status);
      return response.json();
    }).catch(function(err) {
      clearTimeout(timeout);
      throw err;
    });
  };

  // Export
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = DeviceID;
  } else {
    window.DeviceID = DeviceID;
  }

})(typeof window !== 'undefined' ? window : {});