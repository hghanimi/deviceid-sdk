/**
 * DeviceID Browser SDK
 * Collects browser signals and identifies unique devices.
 * @version 1.1.0
 */

class DeviceID {
  constructor(options = {}) {
    this.apiKey = options.apiKey;
    this.apiEndpoint = options.apiEndpoint || 'https://api.arch-hayder.workers.dev/v1/fingerprint';
    this.debug = options.debug || false;
    this.behaviorStart = Date.now();
    this.behavior = {
      mouseMoves: 0,
      clicks: 0,
      scrolls: 0,
      keys: 0,
      touches: 0,
      pointerDistance: 0,
      scrollDistance: 0,
      keyIntervals: [],
      clickIntervals: [],
      moveIntervals: [],
      lastMouse: null,
      lastEventAt: null,
    };
    this.startBehaviorTracking();
  }

  async identify() {
    try {
      const signals = await this.collectSignals();
      if (this.debug) console.log('Collected signals:', signals);

      const response = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
        },
        body: JSON.stringify(signals),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      if (result.visitorId) {
        try {
          localStorage.setItem('deviceid_visitor_id', result.visitorId);
          sessionStorage.setItem('deviceid_visitor_id', result.visitorId);
        } catch {
          // Storage may be unavailable.
        }
      }

      return result;
    } catch (err) {
      console.error('DeviceID.identify() error:', err);
      throw err;
    }
  }

  async collectSignals() {
    return {
      canvas: this.getCanvasFingerprint(),
      webgl: this.getWebGLFingerprint(),
      audio: await this.getAudioFingerprint(),
      screen: this.getScreenInfo(),
      fonts: this.getInstalledFonts(),
      browser: this.getBrowserInfo(),
      hardware: this.getHardwareInfo(),
      evasion: {
        headlessScore: this.detectHeadless(),
        isPrivate: await this.detectPrivate(),
        webrtcIPs: [],
        bot: this.detectBot(),
      },
      behavior: this.getBehaviorProfile(),
      storedIds: this.getStoredIds(),
    };
  }

  startBehaviorTracking() {
    if (typeof window === 'undefined' || this.behaviorTrackingStarted) {
      return;
    }

    this.behaviorTrackingStarted = true;
    const markInterval = (bucketName) => {
      const now = Date.now();
      if (this.behavior.lastEventAt) {
        this.behavior[bucketName].push(now - this.behavior.lastEventAt);
      }
      this.behavior.lastEventAt = now;
    };

    window.addEventListener('mousemove', (event) => {
      markInterval('moveIntervals');
      this.behavior.mouseMoves += 1;
      if (this.behavior.lastMouse) {
        const deltaX = event.clientX - this.behavior.lastMouse.x;
        const deltaY = event.clientY - this.behavior.lastMouse.y;
        this.behavior.pointerDistance += Math.sqrt((deltaX * deltaX) + (deltaY * deltaY));
      }
      this.behavior.lastMouse = { x: event.clientX, y: event.clientY };
    }, { passive: true });

    window.addEventListener('click', () => {
      markInterval('clickIntervals');
      this.behavior.clicks += 1;
    }, { passive: true });

    window.addEventListener('scroll', () => {
      this.behavior.scrolls += 1;
      this.behavior.scrollDistance = Math.max(
        this.behavior.scrollDistance,
        window.scrollY || document.documentElement.scrollTop || 0
      );
    }, { passive: true });

    window.addEventListener('keydown', () => {
      markInterval('keyIntervals');
      this.behavior.keys += 1;
    }, { passive: true });

    window.addEventListener('touchstart', () => {
      this.behavior.touches += 1;
    }, { passive: true });
  }

  average(numbers) {
    if (!numbers || numbers.length === 0) {
      return 0;
    }
    return Math.round(numbers.reduce((sum, value) => sum + value, 0) / numbers.length);
  }

  getBehaviorProfile() {
    const durationMs = Date.now() - this.behaviorStart;
    const totalEvents = this.behavior.mouseMoves + this.behavior.clicks + this.behavior.scrolls + this.behavior.keys + this.behavior.touches;

    return {
      durationMs,
      totalEvents,
      mouseMoves: this.behavior.mouseMoves,
      clicks: this.behavior.clicks,
      scrolls: this.behavior.scrolls,
      keys: this.behavior.keys,
      touches: this.behavior.touches,
      pointerDistance: Math.round(this.behavior.pointerDistance),
      scrollDistance: Math.round(this.behavior.scrollDistance),
      averageMouseIntervalMs: this.average(this.behavior.moveIntervals),
      averageClickIntervalMs: this.average(this.behavior.clickIntervals),
      averageKeyIntervalMs: this.average(this.behavior.keyIntervals),
      visibilityState: typeof document !== 'undefined' ? document.visibilityState : 'unknown',
      hasFocus: typeof document !== 'undefined' && document.hasFocus ? document.hasFocus() : false,
    };
  }

  getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 90;
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'canvas_unavailable';

      const gradient = ctx.createLinearGradient(0, 0, 280, 90);
      gradient.addColorStop(0, '#1f6feb');
      gradient.addColorStop(1, '#d97706');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, 280, 90);

      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#111827';
      ctx.font = '18px Arial';
      ctx.fillText('DeviceID :: بصمة الجهاز :: مرحبا', 8, 28);
      ctx.fillStyle = 'rgba(255,255,255,0.9)';
      ctx.font = '20px Tahoma';
      ctx.fillText('Fingerprint 12345 !@#$', 12, 58);
      ctx.strokeStyle = '#10b981';
      ctx.beginPath();
      ctx.arc(230, 30, 18, 0, Math.PI * 2);
      ctx.stroke();

      return canvas.toDataURL();
    } catch {
      return 'canvas_error';
    }
  }

  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl_unavailable';

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

      return {
        vendor,
        renderer,
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
        antialias: !!gl.getContextAttributes()?.antialias,
      };
    } catch {
      return 'webgl_error';
    }
  }

  async getAudioFingerprint() {
    try {
      const OfflineAudioContextCtor = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OfflineAudioContextCtor) return 'audio_unavailable';

      const context = new OfflineAudioContextCtor(1, 44100, 44100);
      const oscillator = context.createOscillator();
      const compressor = context.createDynamicsCompressor();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;

      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;

      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);
      const rendered = await context.startRendering();
      const channelData = rendered.getChannelData(0).slice(4500, 5000);
      let sum = 0;
      for (let index = 0; index < channelData.length; index += 1) {
        sum += Math.abs(channelData[index]);
      }

      return {
        sample: Array.from(channelData.slice(0, 25)).map((value) => Number(value.toFixed(6))),
        energy: Number(sum.toFixed(6)),
      };
    } catch {
      return 'audio_error';
    }
  }

  getScreenInfo() {
    const orientation = screen.orientation || {};
    return {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      devicePixelRatio: window.devicePixelRatio || 1,
      orientationType: orientation.type || 'unknown',
      orientationAngle: orientation.angle || 0,
      colorGamut: this.matchMediaValue([
        ['rec2020', '(color-gamut: rec2020)'],
        ['p3', '(color-gamut: p3)'],
        ['srgb', '(color-gamut: srgb)'],
      ]),
      reducedMotion: this.matchesMedia('(prefers-reduced-motion: reduce)'),
      contrast: this.matchMediaValue([
        ['more', '(prefers-contrast: more)'],
        ['less', '(prefers-contrast: less)'],
      ]),
      colorScheme: this.matchMediaValue([
        ['dark', '(prefers-color-scheme: dark)'],
        ['light', '(prefers-color-scheme: light)'],
      ]),
      hover: this.matchesMedia('(hover: hover)'),
      pointerFine: this.matchesMedia('(pointer: fine)'),
    };
  }

  matchesMedia(query) {
    try {
      return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
        ? window.matchMedia(query).matches
        : false;
    } catch {
      return false;
    }
  }

  matchMediaValue(entries) {
    for (const [label, query] of entries) {
      if (this.matchesMedia(query)) {
        return label;
      }
    }
    return 'unknown';
  }

  getInstalledFonts() {
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testFonts = [
      'Arial',
      'Verdana',
      'Georgia',
      'Times New Roman',
      'Courier New',
      'Comic Sans MS',
      'Tahoma',
      'Segoe UI',
      'Calibri',
      'Noto Sans Arabic',
      'Noto Naskh Arabic',
      'Noto Kufi Arabic',
      'Amiri',
      'Scheherazade New',
      'Geeza Pro',
      'Dubai',
      'Droid Arabic Naskh',
      'Traditional Arabic',
      'Arial Unicode MS',
    ];
    const sampleText = 'mmmmmmmmmmlliمرحباالسلام12345';
    const defaultSize = '72px';
    const body = document.body || document.documentElement;
    if (!body) return [];

    const getMetrics = (fontFamily) => {
      const element = document.createElement('span');
      element.style.position = 'absolute';
      element.style.left = '-9999px';
      element.style.fontSize = defaultSize;
      element.style.fontFamily = fontFamily;
      element.textContent = sampleText;
      body.appendChild(element);
      const metrics = { width: element.offsetWidth, height: element.offsetHeight };
      element.remove();
      return metrics;
    };

    const baselines = {};
    for (const baseFont of baseFonts) {
      baselines[baseFont] = getMetrics(baseFont);
    }

    const detected = [];
    for (const font of testFonts) {
      let matched = false;
      for (const baseFont of baseFonts) {
        const metrics = getMetrics(`"${font}", ${baseFont}`);
        if (
          metrics.width !== baselines[baseFont].width ||
          metrics.height !== baselines[baseFont].height
        ) {
          matched = true;
          break;
        }
      }
      if (matched) {
        detected.push(font);
      }
    }
    return detected;
  }

  getBrowserInfo() {
    const nav = navigator;
    const uaData = nav.userAgentData;
    return {
      userAgent: nav.userAgent,
      language: nav.language,
      languages: nav.languages || [],
      platform: nav.platform,
      vendor: nav.vendor,
      pluginCount: (nav.plugins || []).length,
      mimeTypeCount: (nav.mimeTypes || []).length,
      cookieEnabled: nav.cookieEnabled,
      doNotTrack: nav.doNotTrack || window.doNotTrack || navigator.msDoNotTrack || 'unknown',
      pdfViewerEnabled: !!nav.pdfViewerEnabled,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      uaDataBrands: uaData && uaData.brands ? uaData.brands : [],
      uaDataMobile: !!(uaData && uaData.mobile),
      historyLength: typeof history !== 'undefined' ? history.length : 0,
      storage: this.getStorageCapabilities(),
    };
  }

  getStorageCapabilities() {
    return {
      localStorage: this.storageAvailable('localStorage'),
      sessionStorage: this.storageAvailable('sessionStorage'),
      indexedDb: typeof indexedDB !== 'undefined',
    };
  }

  storageAvailable(type) {
    try {
      const storage = window[type];
      const key = '__deviceid_test__';
      storage.setItem(key, key);
      storage.removeItem(key);
      return true;
    } catch {
      return false;
    }
  }

  getHardwareInfo() {
    return {
      cores: navigator.hardwareConcurrency || 0,
      memory: navigator.deviceMemory || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      touchSupported: 'ontouchstart' in window,
      pointerCoarse: this.matchesMedia('(pointer: coarse)'),
      anyHover: this.matchesMedia('(any-hover: hover)'),
      mathFingerprint: this.getMathFingerprint(),
    };
  }

  getMathFingerprint() {
    try {
      return {
        acos: Number(Math.acos(0.12312423423423424).toFixed(12)),
        asinh: Number(Math.asinh(1).toFixed(12)),
        tanh: Number(Math.tanh(1).toFixed(12)),
        expm1: Number(Math.expm1(1).toFixed(12)),
      };
    } catch {
      return 'math_error';
    }
  }

  detectHeadless() {
    let score = 0;
    if (!window.chrome) score += 0.15;
    if (navigator.webdriver) score += 0.45;
    if (!navigator.languages || navigator.languages.length === 0) score += 0.15;
    if (!navigator.plugins || navigator.plugins.length === 0) score += 0.1;
    if (!navigator.permissions || !navigator.permissions.query) score += 0.15;
    return Math.min(1, score);
  }

  async detectPrivate() {
    try {
      if (navigator.storage && navigator.storage.estimate) {
        const estimate = await navigator.storage.estimate();
        if (estimate.quota && estimate.quota < 120000000) {
          return true;
        }
      }

      const fs = window.RequestFileSystem || window.webkitRequestFileSystem;
      if (!fs) return false;
      return await new Promise((resolve) => {
        fs(window.TEMPORARY, 1, () => resolve(false), () => resolve(true));
      });
    } catch {
      return false;
    }
  }

  detectBot() {
    return {
      phantom: !!window.callPhantom,
      headless: !!navigator.webdriver,
      nightmare: !!window.__nightmare,
      selenium: !!window.document && !!document.documentElement.getAttribute('webdriver'),
      domAutomation: !!window.domAutomation || !!window.domAutomationController,
    };
  }

  getStoredIds() {
    try {
      return {
        localStorage: localStorage.getItem('deviceid_visitor_id') || undefined,
        sessionStorage: sessionStorage.getItem('deviceid_visitor_id') || undefined,
      };
    } catch {
      return {};
    }
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DeviceID;
}

if (typeof window !== 'undefined') {
  window.DeviceID = DeviceID;
}
