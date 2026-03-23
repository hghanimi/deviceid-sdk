class FuzzyMatcher {

  static WEIGHTS = {
    canvas:   0.25,
    webgl:    0.20,
    audio:    0.15,
    screen:   0.10,
    hardware: 0.10,
    fonts:    0.10,
    browser:  0.05,
    storedId: 0.05,
  };

  static MATCH_THRESHOLD = 0.65;

  constructor(db) {
    this.db = db;
  }

  async findMatch(hashes, storedIds, apiKeyId) {
    // Priority 1: stored IDs
    const storedMatch = await this._checkStoredIds(storedIds, apiKeyId);
    if (storedMatch && storedMatch.confidence > 0.90) return storedMatch;

    // Priority 2: exact composite
    const exactMatch = await this._exactMatch(hashes.composite, apiKeyId);
    if (exactMatch) {
      return {
        visitorId: exactMatch.visitor_id,
        confidence: 1.0,
        isNew: false,
        matchType: 'exact',
      };
    }

    // Priority 3: fuzzy match
    const candidates = await this._getCandidates(hashes, apiKeyId);
    if (candidates.length === 0) {
      return { visitorId: null, confidence: 0, isNew: true };
    }

    let bestMatch = null;
    let bestScore = 0;

    for (const candidate of candidates) {
      const score = this._scoreMatch(hashes, candidate);
      if (score > bestScore) {
        bestScore = score;
        bestMatch = candidate;
      }
    }

    if (bestScore >= FuzzyMatcher.MATCH_THRESHOLD) {
      return {
        visitorId: bestMatch.visitor_id,
        confidence: Math.round(bestScore * 100) / 100,
        isNew: false,
        matchType: 'fuzzy',
        matchedSignals: this._getMatchedSignals(hashes, bestMatch),
        originalVisitorId: bestMatch.visitor_id,
      };
    }

    return { visitorId: null, confidence: bestScore, isNew: true };
  }

  async _getCandidates(hashes, apiKeyId) {
    const result = await this.db.query(`
      SELECT * FROM fingerprints
      WHERE api_key_id = $1
        AND (canvas_hash = $2 OR webgl_hash = $3 OR audio_hash = $4
             OR screen_hash = $5 OR hardware_hash = $6)
      ORDER BY last_seen DESC
      LIMIT 50
    `, [apiKeyId, hashes.canvas, hashes.webgl, hashes.audio,
        hashes.screen, hashes.hardware]);
    return result.rows;
  }

  _scoreMatch(incoming, candidate) {
    let totalWeight = 0;
    let matchedWeight = 0;

    const comparisons = [
      { key: 'canvas',   a: incoming.canvas,   b: candidate.canvas_hash },
      { key: 'webgl',    a: incoming.webgl,    b: candidate.webgl_hash },
      { key: 'audio',    a: incoming.audio,    b: candidate.audio_hash },
      { key: 'screen',   a: incoming.screen,   b: candidate.screen_hash },
      { key: 'hardware', a: incoming.hardware, b: candidate.hardware_hash },
      { key: 'fonts',    a: incoming.fonts,    b: candidate.font_hash },
      { key: 'browser',  a: incoming.browser,  b: candidate.browser_hash },
    ];

    for (const { key, a, b } of comparisons) {
      const weight = FuzzyMatcher.WEIGHTS[key];
      if (!a || !b) continue;
      totalWeight += weight;
      if (a === b) matchedWeight += weight;
    }

    return totalWeight === 0 ? 0 : matchedWeight / totalWeight;
  }

  async _checkStoredIds(storedIds, apiKeyId) {
    if (!storedIds) return null;
    const ids = [storedIds.ls, storedIds.ss, storedIds.cookie].filter(Boolean);
    if (ids.length === 0) return null;

    const result = await this.db.query(`
      SELECT visitor_id, COUNT(*) as match_count
      FROM fingerprints
      WHERE visitor_id = ANY($1) AND api_key_id = $2
      GROUP BY visitor_id ORDER BY match_count DESC LIMIT 1
    `, [ids, apiKeyId]);

    if (result.rows.length > 0) {
      return {
        visitorId: result.rows[0].visitor_id,
        confidence: 0.95,
        isNew: false,
        matchType: 'stored_id',
      };
    }
    return null;
  }

  async _exactMatch(compositeHash, apiKeyId) {
    const result = await this.db.query(
      `SELECT visitor_id FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1`,
      [compositeHash, apiKeyId]
    );
    return result.rows[0] || null;
  }

  _getMatchedSignals(hashes, candidate) {
    const matched = [];
    if (hashes.canvas === candidate.canvas_hash) matched.push('canvas');
    if (hashes.webgl === candidate.webgl_hash) matched.push('webgl');
    if (hashes.audio === candidate.audio_hash) matched.push('audio');
    if (hashes.screen === candidate.screen_hash) matched.push('screen');
    if (hashes.hardware === candidate.hardware_hash) matched.push('hardware');
    if (hashes.fonts === candidate.font_hash) matched.push('fonts');
    if (hashes.browser === candidate.browser_hash) matched.push('browser');
    return matched;
  }
}

module.exports = FuzzyMatcher;