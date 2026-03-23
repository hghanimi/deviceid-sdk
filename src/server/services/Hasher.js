const crypto = require('crypto');

class SignalHasher {

  hashSignals(signals) {
    const hashes = {
      canvas:   this._hashCanvas(signals.canvas),
      webgl:    this._hashWebGL(signals.webgl),
      audio:    this._hashAudio(signals.audio),
      screen:   this._hashScreen(signals.screen),
      hardware: this._hashHardware(signals.hardware),
      browser:  this._hashBrowser(signals.browser),
      fonts:    this._hashFonts(signals.fonts),
    };
    hashes.composite = this._compositeHash(hashes);
    return hashes;
  }

  _hash(input) {
    if (input === null || input === undefined) return null;
    return crypto
      .createHash('sha256')
      .update(typeof input === 'string' ? input : JSON.stringify(input))
      .digest('hex')
      .substring(0, 32);
  }

  _hashCanvas(dataUrl) {
    return dataUrl ? this._hash(dataUrl) : null;
  }

  _hashWebGL(webgl) {
    if (!webgl) return null;
    return this._hash({
      vendor: webgl.vendor,
      renderer: webgl.renderer,
      maxTextureSize: webgl.maxTextureSize,
      maxRenderbufferSize: webgl.maxRenderbufferSize,
      extensions: (webgl.extensions || []).filter(e => !e.includes('WEBGL_')).sort(),
    });
  }

  _hashAudio(audioSum) {
    if (audioSum === null || audioSum === undefined) return null;
    return this._hash(Math.round(audioSum * 10000) / 10000);
  }

  _hashScreen(screen) {
    if (!screen) return null;
    return this._hash({
      w: screen.width,
      h: screen.height,
      cd: screen.colorDepth,
      pr: Math.round(screen.pixelRatio * 10) / 10,
      tp: screen.maxTouchPoints,
    });
  }

  _hashHardware(hw) {
    if (!hw) return null;
    return this._hash({
      cores: hw.cpuCores,
      mem: hw.deviceMemory,
      platform: hw.platform,
    });
  }

  _hashBrowser(browser) {
    if (!browser) return null;
    return this._hash({
      browserFamily: this._extractBrowserFamily(browser.userAgent),
      lang: browser.language,
      tz: browser.timezone,
      plugins: browser.plugins,
    });
  }

  _extractBrowserFamily(ua) {
    if (!ua) return 'unknown';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Edg/')) return 'Edge';
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
    return 'other';
  }

  _hashFonts(fonts) {
    if (!fonts || fonts.length === 0) return null;
    return this._hash([...fonts].sort());
  }

  _compositeHash(hashes) {
    const parts = [
      hashes.canvas, hashes.webgl, hashes.audio,
      hashes.screen, hashes.hardware, hashes.fonts,
    ].filter(Boolean);
    return this._hash(parts.join('|'));
  }
}

module.exports = new SignalHasher();