/**
 * DeviceID Browser SDK
 * Collects browser signals and identifies unique devices
 * @version 1.0.0
 */

class DeviceID {
  constructor(options = {}) {
    this.apiKey = options.apiKey;
    this.apiEndpoint = options.apiEndpoint || 'https://api.arch-hayder.workers.dev/v1/fingerprint';
    this.debug = options.debug || false;
  }

  /**
   * Main method: collect signals and identify device
   */
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
      
      // Store visitor ID for future requests
      if (result.visitorId) {
        try {
          localStorage.setItem('deviceid_visitor_id', result.visitorId);
          sessionStorage.setItem('deviceid_visitor_id', result.visitorId);
        } catch (e) {
          // Storage may be disabled in private mode
        }
      }

      return result;
    } catch (err) {
      console.error('DeviceID.identify() error:', err);
      throw err;
    }
  }

  /**
   * Collect all browser signals
   */
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
      storedIds: this.getStoredIds(),
    };
  }

  /**
   * Canvas fingerprinting
   */
  getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px "Arial"';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('DeviceID', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('DeviceID', 4, 17);
      return canvas.toDataURL().substring(0, 100); // first 100 chars
    } catch (e) {
      return 'canvas_error';
    }
  }

  /**
   * WebGL fingerprinting
   */
  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl_unavailable';
      const renderer = gl.getParameter(gl.RENDERER);
      const vendor = gl.getParameter(gl.VENDOR);
      return `${vendor}:${renderer}`.substring(0, 100);
    } catch (e) {
      return 'webgl_error';
    }
  }

  /**
   * Audio fingerprinting
   */
  async getAudioFingerprint() {
    try {
      const audioContext = window.AudioContext || window.webkitAudioContext;
      if (!audioContext) return 'audio_unavailable';
      
      const ctx = new audioContext();
      const oscillator = ctx.createOscillator();
      const analyser = ctx.createAnalyser();
      const scriptProcessor = ctx.createScriptProcessor(4096, 1, 1);
      
      oscillator.connect(analyser);
      analyser.connect(scriptProcessor);
      scriptProcessor.connect(ctx.destination);
      oscillator.start(0);
      
      const data = new Uint8Array(analyser.frequencyBinCount);
      analyser.getByteFrequencyData(data);
      oscillator.stop();
      
      return Array.from(data.slice(0, 20)).join(',');
    } catch (e) {
      return 'audio_error';
    }
  }

  /**
   * Screen info
   */
  getScreenInfo() {
    return {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      devicePixelRatio: window.devicePixelRatio || 1,
    };
  }

  /**
   * Detect installed fonts
   */
  getInstalledFonts() {
    const testFonts = ['Arial', 'Verdana', 'Georgia', 'Times New Roman', 'Courier New', 'Comic Sans MS'];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const detected = [];
    
    for (const font of testFonts) {
      try {
        for (const baseFont of baseFonts) {
          const el = document.createElement('span');
          el.style.fontFamily = `"${font}", ${baseFont}`;
          el.style.fontSize = '14px';
          el.textContent = 'mmmmmmmmmmlli';
          el.style.visibility = 'hidden';
          el.style.position = 'absolute';
          document.body.appendChild(el);
          const width = el.offsetWidth;
          el.remove();
          
          if (width > 0 && width !== 100) {
            detected.push(font);
            break;
          }
        }
      } catch (e) {
        // continue
      }
    }
    return detected;
  }

  /**
   * Browser info
   */
  getBrowserInfo() {
    return {
      userAgent: navigator.userAgent.substring(0, 100),
      language: navigator.language,
      platform: navigator.platform,
      pluginCount: (navigator.plugins || []).length,
    };
  }

  /**
   * Hardware info
   */
  getHardwareInfo() {
    return {
      cores: navigator.hardwareConcurrency || 0,
      memory: navigator.deviceMemory || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
    };
  }

  /**
   * Detect headless browser
   */
  detectHeadless() {
    let score = 0;
    if (!window.chrome) score += 0.25;
    if (navigator.webdriver) score += 0.5;
    if (!navigator.permissions || !navigator.permissions.query) score += 0.25;
    return Math.min(1, score);
  }

  /**
   * Detect private/incognito mode
   */
  async detectPrivate() {
    try {
      const fs = window.RequestFileSystem || window.webkitRequestFileSystem;
      if (!fs) return false;
      
      return new Promise(resolve => {
        fs(window.TEMPORARY, 1, 
          () => resolve(false),  // Regular mode
          () => resolve(true)    // Private mode
        );
      });
    } catch (e) {
      return false;
    }
  }

  /**
   * Detect bot
   */
  detectBot() {
    return {
      phantom: !!window.callPhantom,
      headless: !!navigator.webdriver,
      zombie: !!window.__nightmare,
    };
  }

  /**
   * Get stored IDs from previous visits
   */
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

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DeviceID;
}

// For IIFE bundle (global)
if (typeof window !== 'undefined') {
  window.DeviceID = DeviceID;
}