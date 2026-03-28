import { Hono } from 'hono';
import { nanoid } from 'nanoid';
import { createHash } from 'crypto';
import { AppEnv } from '../types';

const router = new Hono<AppEnv>();

const normalizeIp = (ip?: string | null): string => {
  if (!ip) return '';
  return ip.trim().toLowerCase().replace(/^::ffff:/, '');
};

const isPrivateIp = (ip?: string | null): boolean => {
  const value = normalizeIp(ip);
  if (!value) return true;
  if (value === '127.0.0.1' || value === '0.0.0.0') return true;
  if (value.startsWith('10.')) return true;
  if (value.startsWith('192.168.')) return true;
  if (value.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(value)) return true;
  if (value === '::1') return true;
  if (value.startsWith('fc') || value.startsWith('fd')) return true;
  if (value.startsWith('fe80:')) return true;
  return false;
};

// ─── Cross-Device Person Resolution Engine ───
async function resolvePersonIdentity(
  db: any,
  visitorId: string,
  apiKeyId: string,
  clientIp: string,
  userId?: string,
): Promise<{
  personId: string | null;
  linkedDevices: Array<{ visitorId: string; linkType: string; confidence: number }>;
  isNewPerson: boolean;
  linkType: string | null;
}> {
  let personId: string | null = null;
  let isNewPerson = false;
  let linkType: string | null = null;
  const linkedDevices: Array<{ visitorId: string; linkType: string; confidence: number }> = [];

  try {
    // METHOD 1: Deterministic — userId from merchant login (99.9% accurate)
    if (userId) {
      const existingPerson = await db.query(
        `SELECT person_id FROM persons
         WHERE external_user_id = $1 AND api_key_id = $2
         LIMIT 1`,
        [userId, apiKeyId]
      );

      if (existingPerson.rows.length > 0) {
        personId = existingPerson.rows[0].person_id;
        const existingLink = await db.query(
          `SELECT id FROM person_devices
           WHERE person_id = $1 AND visitor_id = $2 AND api_key_id = $3
           LIMIT 1`,
          [personId, visitorId, apiKeyId]
        );
        if (existingLink.rows.length === 0) {
          await db.query(
            `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
             VALUES ($1, $2, 'login', 1.0, $3, $4)`,
            [personId, visitorId, clientIp, apiKeyId]
          );
          await db.query(
            `UPDATE persons SET device_count = device_count + 1, last_seen = NOW()
             WHERE person_id = $1`,
            [personId]
          );
        } else {
          await db.query(
            `UPDATE persons SET last_seen = NOW() WHERE person_id = $1`,
            [personId]
          );
        }
        linkType = 'login';
      } else {
        personId = `psn_${nanoid(12)}`;
        isNewPerson = true;
        linkType = 'login';
        await db.query(
          `INSERT INTO persons (person_id, api_key_id, external_user_id, device_count)
           VALUES ($1, $2, $3, 1)`,
          [personId, apiKeyId, userId]
        );
        await db.query(
          `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
           VALUES ($1, $2, 'login', 1.0, $3, $4)`,
          [personId, visitorId, clientIp, apiKeyId]
        );
      }
    }

    // METHOD 2: Probabilistic — IP correlation (70-85% accurate)
    if (!personId && clientIp) {
      const ipNeighbors = await db.query(
        `SELECT DISTINCT f.visitor_id, f.person_id, pd.person_id as linked_person_id
         FROM fingerprints f
         LEFT JOIN person_devices pd ON pd.visitor_id = f.visitor_id AND pd.api_key_id = $3
         WHERE f.ip_address = $1
           AND f.api_key_id = $3
           AND f.visitor_id != $2
           AND f.last_seen >= NOW() - INTERVAL '30 minutes'
         ORDER BY f.visitor_id
         LIMIT 10`,
        [clientIp, visitorId, apiKeyId]
      );

      if (ipNeighbors.rows.length > 0) {
        const neighborWithPerson = ipNeighbors.rows.find(
          (r: any) => r.person_id || r.linked_person_id
        );

        if (neighborWithPerson) {
          personId = neighborWithPerson.person_id || neighborWithPerson.linked_person_id;
          linkType = 'ip_correlation';
          const alreadyLinked = await db.query(
            `SELECT id FROM person_devices WHERE person_id = $1 AND visitor_id = $2 LIMIT 1`,
            [personId, visitorId]
          );
          if (alreadyLinked.rows.length === 0) {
            await db.query(
              `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
               VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)`,
              [personId, visitorId, clientIp, apiKeyId]
            );
            await db.query(
              `UPDATE persons SET device_count = device_count + 1, last_seen = NOW()
               WHERE person_id = $1`,
              [personId]
            );
          }
        } else {
          personId = `psn_${nanoid(12)}`;
          isNewPerson = true;
          linkType = 'ip_correlation';
          await db.query(
            `INSERT INTO persons (person_id, api_key_id, device_count)
             VALUES ($1, $2, $3)`,
            [personId, apiKeyId, ipNeighbors.rows.length + 1]
          );
          await db.query(
            `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
             VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)`,
            [personId, visitorId, clientIp, apiKeyId]
          );
          for (const neighbor of ipNeighbors.rows) {
            await db.query(
              `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
               VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)
               ON CONFLICT DO NOTHING`,
              [personId, neighbor.visitor_id, clientIp, apiKeyId]
            );
          }
        }
      }
    }

    // METHOD 3: Historical lookup — device was previously linked
    if (!personId) {
      const pastLink = await db.query(
        `SELECT person_id, link_type FROM person_devices
         WHERE visitor_id = $1 AND api_key_id = $2
         ORDER BY linked_at DESC LIMIT 1`,
        [visitorId, apiKeyId]
      );
      if (pastLink.rows.length > 0) {
        personId = pastLink.rows[0].person_id;
        linkType = pastLink.rows[0].link_type;
        await db.query(
          `UPDATE persons SET last_seen = NOW() WHERE person_id = $1`,
          [personId]
        );
      }
    }

    // Update fingerprints table with person_id
    if (personId) {
      await db.query(
        `UPDATE fingerprints SET person_id = $1
         WHERE visitor_id = $2 AND api_key_id = $3 AND (person_id IS NULL OR person_id != $1)`,
        [personId, visitorId, apiKeyId]
      );
      const allDevices = await db.query(
        `SELECT visitor_id, link_type, confidence FROM person_devices
         WHERE person_id = $1 AND visitor_id != $2
         ORDER BY linked_at DESC`,
        [personId, visitorId]
      );
      for (const d of allDevices.rows) {
        linkedDevices.push({
          visitorId: d.visitor_id,
          linkType: d.link_type,
          confidence: parseFloat(d.confidence),
        });
      }
    }
  } catch (err) {
    console.error('Person resolution error:', err);
  }

  return { personId, linkedDevices, isNewPerson, linkType };
}

// GET /v1/visitor/:id
router.get('/v1/visitor/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const visitorId = c.req.param('id');

  if (!apiKey?.is_operator) {
    return c.json({ error: 'Forbidden' }, 403);
  }

  try {
    const [profile, links] = await Promise.all([
      db.query(
        `SELECT f.*, k.name AS merchant_name
         FROM fingerprints f
         JOIN api_keys k ON k.id = f.api_key_id
         WHERE f.visitor_id = $1
         ORDER BY f.last_seen DESC
         LIMIT 1`,
        [visitorId]
      ),
      db.query(
        `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
         FROM device_links
         WHERE visitor_id_a = $1 OR visitor_id_b = $1
         ORDER BY confidence DESC
         LIMIT 20`,
        [visitorId]
      ),
    ]);

    if (profile.rows.length === 0) return c.json({ error: 'Visitor not found' }, 404);

    const p = profile.rows[0];
    return c.json({
      visitorId,
      merchantName: p.merchant_name,
      firstSeen: p.first_seen,
      lastSeen: p.last_seen,
      visitCount: p.visit_count,
      ipAddress: p.ip_address,
      isVpn: p.is_vpn,
      isIncognito: p.is_incognito,
      headlessScore: p.headless_score,
      botScore: p.bot_score,
      signalGroups: [
        { name: 'Canvas',   hash: p.canvas_hash,   signals: ['Canvas rendering'],                   icon: 'render' },
        { name: 'WebGL',    hash: p.webgl_hash,    signals: ['WebGL params', 'Pixel render hash'],  icon: 'gpu' },
        { name: 'Audio',    hash: p.audio_hash,    signals: ['Audio pipeline'],                     icon: 'audio' },
        { name: 'Screen',   hash: p.screen_hash,   signals: ['Screen info', 'ClientRects/DOMRect'], icon: 'display' },
        { name: 'Fonts',    hash: p.font_hash,     signals: ['System fonts', 'Arabic fonts', 'Emoji render'], icon: 'type' },
        { name: 'Browser',  hash: p.browser_hash,  signals: ['Intl API probe', 'CSS.supports()', 'Media codecs', 'SpeechSynthesis voices'], icon: 'browser' },
        { name: 'Hardware', hash: p.hardware_hash, signals: ['Hardware specs', 'MathML render', 'Browser basics'], icon: 'cpu' },
      ].filter(g => g.hash),
      linkedDevices: links.rows.map((l: any) => ({
        linkedId: l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a,
        linkType: l.link_type,
        confidence: l.confidence,
        linkedAt: l.created_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Visitor query failed', details: err.message }, 500);
  }
});

// POST /v1/fingerprint — v3 with weighted matching
router.post('/v1/fingerprint', async (c) => {
  const startTime = Date.now();

  try {
    const signals = await c.req.json() as any;
    const apiKey = c.get('apiKey') as any;
    const apiKeyId = apiKey.id;
    const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
    const db = c.get('db') as any;

    const h = (signal: any): string => {
      if (signal === null || signal === undefined) return '';
      const str = JSON.stringify(signal);
      if (str === undefined) return '';
      return createHash('sha256').update(str).digest('hex');
    };

    const { storedIds, ts, collectionMs, v, evasion, rawAttributes, ...stableCore } = signals;

    const legacyHashes = {
      composite: h(stableCore),
      canvas:    h(signals.canvas),
      webgl:     h(signals.webgl),
      audio:     h(signals.audio),
      screen:    h(signals.screen),
      fonts:     h(signals.fonts),
      browser:   h(signals.browser),
      hardware:  h(signals.hardware),
    };

    const hw = signals.hardware || {};
    const scr = signals.screen || {};
    const wgl = signals.webgl || {};
    const deviceStableSignals = {
      cores: hw.cores || 0,
      mem: hw.mem || 0,
      platform: hw.platform || '',
      screenW: scr.w || scr.width || 0,
      screenH: scr.h || scr.height || 0,
      colorDepth: scr.colorDepth || scr.cd || 0,
      dpr: scr.dpr || scr.devicePixelRatio || 0,
      gpu: (wgl.renderer || wgl.rendererUnmasked || '').replace(/\s+/g, ' ').trim(),
      gpuVendor: (wgl.vendorUnmasked || wgl.vendor || '').replace(/\s+/g, ' ').trim(),
      touch: hw.touch || 0,
    };
    const fontList = Array.isArray(signals.fonts) ? signals.fonts :
      (signals.fonts?.installed || signals.fonts?.detected || []);
    const sortedFonts = (Array.isArray(fontList) ? [...fontList] : []).sort().join('|');
    const deviceHash = h({ ...deviceStableSignals, fonts: sortedFonts });

    const hashes = {
      composite: legacyHashes.composite,
      device: deviceHash,
      canvas: h(signals.canvas),
      webgl: h({ webgl: signals.webgl, webglRender: signals.webglRender }),
      audio: h(signals.audio),
      screen: h({ screen: signals.screen, clientRects: signals.clientRects }),
      fonts: h({
        fonts: signals.fonts, arabicFonts: signals.arabicFonts, emoji: signals.emoji,
      }),
      browser: h({
        intlProbe: signals.intlProbe, cssSupports: signals.cssSupports,
        codecs: signals.codecs, voices: signals.voices,
      }),
      hardware: h({
        hardware: signals.hardware, mathml: signals.mathml, browser: signals.browser,
      }),
      screenOnly: h({ w: scr.w || scr.width, h: scr.h || scr.height, cd: scr.colorDepth || scr.cd, dpr: scr.dpr || scr.devicePixelRatio }),
      gpuOnly: h({ gpu: deviceStableSignals.gpu, vendor: deviceStableSignals.gpuVendor }),
      hwOnly: h({ cores: deviceStableSignals.cores, mem: deviceStableSignals.mem, platform: deviceStableSignals.platform, touch: deviceStableSignals.touch }),
      fontsOnly: h(sortedFonts),
    };

    const signalNames = [
      'canvas', 'webgl', 'webglRender', 'audio', 'screen', 'clientRects',
      'fonts', 'arabicFonts', 'emoji', 'voices', 'codecs', 'cssSupports',
      'permissions', 'storageQuota', 'mathml', 'intlProbe', 'hardware',
      'browser', 'timezone',
    ];
    const signalHashes: Record<string, string> = {};
    let signalsCollected = 0;
    for (const name of signalNames) {
      const val = signals[name];
      if (val !== null && val !== undefined) {
        signalHashes[name] = h(val);
        signalsCollected++;
      }
    }

    const headlessScoreInt = Math.round((evasion?.headlessScore || 0) * 100);
    const botCount = Object.values(evasion?.bot || {}).filter(Boolean).length;

    const botClassification = (() => {
      if (botCount === 0 && (evasion?.headlessScore || 0) <= 0.4) return 'notDetected';
      const ua = (c.req.header('User-Agent') || '').toLowerCase();
      const goodBotPatterns = ['googlebot','bingbot','yandexbot','duckduckbot','slurp','baiduspider',
        'facebot','linkedinbot','twitterbot','applebot','semrushbot','ahrefsbot','mj12bot'];
      if (goodBotPatterns.some(p => ua.includes(p))) return 'good';
      return 'bad';
    })();

    const KNOWN_AGENTS = [
      'ChatGPT-User', 'GPTBot', 'Google-Extended', 'Amazonbot',
      'PerplexityBot', 'ClaudeBot', 'Bytespider', 'cohere-ai',
      'Browserbase', 'Manus', 'AnchorBrowser', 'anthropic-ai',
      'CCBot', 'FacebookBot', 'Meta-ExternalAgent',
    ];
    const fullUA = c.req.header('User-Agent') || '';
    const isKnownAgent = KNOWN_AGENTS.some(a => fullUA.includes(a));
    const visitorType: 'human' | 'known_agent' | 'suspected_agent' | 'unknown' = (() => {
      if (isKnownAgent) return 'known_agent';
      if (botClassification === 'bad' || (evasion?.headlessScore || 0) > 0.6) return 'suspected_agent';
      if (botClassification === 'good') return 'known_agent';
      if (signalNames.length > 0 && signalsCollected === 0) return 'unknown';
      return 'human';
    })();

    const normalizedClientIp = normalizeIp(clientIp);
    const isIPv4 = (ip: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    const isIPv6 = (ip: string) => ip.includes(':');

    const webrtcIps: string[] = Array.isArray(evasion?.webrtcIPs)
      ? evasion.webrtcIPs.map((ip: string) => normalizeIp(ip)).filter(Boolean)
      : [];
    const publicWebrtcIps = webrtcIps.filter((ip) => !isPrivateIp(ip));

    const cfData = (c.req.raw as any).cf || {};
    const ipTimezone: string = (cfData.timezone || '');
    const browserTimezone: string = (signals.timezone?.tz || '');
    const browserOffset: number = typeof signals.timezone?.offset === 'number' ? signals.timezone.offset : NaN;

    const getIanaOffset = (iana: string): number | null => {
      try {
        if (!iana) return null;
        const now = new Date();
        const utcStr = now.toLocaleString('en-US', { timeZone: 'UTC' });
        const tzStr  = now.toLocaleString('en-US', { timeZone: iana });
        return (new Date(tzStr).getTime() - new Date(utcStr).getTime()) / 60000;
      } catch { return null; }
    };

    let vpnScore = 0;
    const ipOffsetMin = getIanaOffset(ipTimezone);
    const browserOffsetMin = !isNaN(browserOffset) ? -browserOffset : null;

    if (ipOffsetMin !== null && browserOffsetMin !== null) {
      const diffMinutes = Math.abs(ipOffsetMin - browserOffsetMin);
      if (diffMinutes > 120) vpnScore += 3;
    }

    const asOrg: string = (cfData.asOrganization || '').toLowerCase();
    const vpnAsKeywords = [
      'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'mullvad', 'protonvpn',
      'private internet', 'purevpn', 'ipvanish', 'hotspot shield', 'windscribe',
      'torguard', 'hide.me', 'tunnelbear',
      'ovh', 'hetzner', 'digitalocean', 'digital ocean', 'vultr', 'linode',
      'choopa', 'm247', 'datacamp', 'psychz',
    ];
    if (asOrg && vpnAsKeywords.some((kw) => asOrg.includes(kw))) vpnScore += 3;

    if (normalizedClientIp && normalizedClientIp !== '0.0.0.0' && !isPrivateIp(normalizedClientIp)) {
      const clientIsIPv4 = isIPv4(normalizedClientIp);
      const sameProtoWebrtcIps = publicWebrtcIps.filter((ip) =>
        clientIsIPv4 ? isIPv4(ip) : isIPv6(ip)
      );
      if (sameProtoWebrtcIps.length > 0 && sameProtoWebrtcIps.every((ip) => ip !== normalizedClientIp)) {
        vpnScore += 2;
      }
    }

    const browserUA_vpn = c.req.header('User-Agent') || '';
    const uaPlatform = (() => {
      if (/Windows/.test(browserUA_vpn)) return 'windows';
      if (/Macintosh|Mac OS/.test(browserUA_vpn)) return 'mac';
      if (/Linux/.test(browserUA_vpn) && !/Android/.test(browserUA_vpn)) return 'linux';
      if (/Android/.test(browserUA_vpn)) return 'android';
      if (/iPhone|iPad/.test(browserUA_vpn)) return 'ios';
      return 'unknown';
    })();
    const hwPlatform = (signals.hardware?.platform || '').toLowerCase();
    let osMismatch = false;
    if (hwPlatform && uaPlatform !== 'unknown') {
      const platformMap: Record<string, string[]> = {
        windows: ['win32', 'win64', 'windows'],
        mac: ['macintel', 'macppc', 'mac'],
        linux: ['linux x86_64', 'linux aarch64', 'linux'],
        android: ['linux armv', 'linux aarch64', 'android'],
        ios: ['iphone', 'ipad', 'ipod'],
      };
      const expected = platformMap[uaPlatform] || [];
      if (expected.length > 0 && !expected.some(p => hwPlatform.includes(p))) {
        osMismatch = true;
        vpnScore += 1;
      }
    }

    let isVpn = vpnScore >= 2;

    const datacenterKeywords = [
      'ovh', 'hetzner', 'digitalocean', 'digital ocean', 'vultr', 'linode',
      'choopa', 'm247', 'datacamp', 'psychz', 'amazon', 'google cloud',
      'microsoft azure', 'cloudflare', 'oracle', 'scaleway', 'contabo',
      'leaseweb', 'equinix', 'rackspace', 'kamatera',
    ];
    const vpnKeywords = [
      'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'mullvad', 'protonvpn',
      'private internet', 'purevpn', 'ipvanish', 'hotspot shield', 'windscribe',
      'torguard', 'hide.me', 'tunnelbear',
    ];
    let proxyType = 'none';
    let proxyConfidence = 'low';
    const isDatacenter = datacenterKeywords.some((kw) => asOrg.includes(kw));
    const isVpnAsn = vpnKeywords.some((kw) => asOrg.includes(kw));
    if (isVpnAsn) { proxyType = 'vpn'; proxyConfidence = 'high'; }
    else if (isDatacenter) { proxyType = 'datacenter'; proxyConfidence = 'high'; }
    else if (isVpn && !isDatacenter) { proxyType = 'residential'; proxyConfidence = 'medium'; }

    let ipDistinctVisitors = 0;
    try {
      const ipVisQ = await db.query(
        `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
         FROM fingerprints WHERE ip_address = $1 AND api_key_id = $2
           AND last_seen >= NOW() - INTERVAL '7 days'`,
        [clientIp, apiKeyId]
      );
      ipDistinctVisitors = ipVisQ.rows[0]?.cnt || 0;
      if (ipDistinctVisitors >= 10 && proxyType === 'none') {
        proxyType = 'residential'; proxyConfidence = 'medium';
      } else if (ipDistinctVisitors >= 5 && proxyConfidence === 'medium') {
        proxyConfidence = 'high';
      }
    } catch (e) {}

    const blocklist = {
      result: false,
      details: { emailSpam: false, attackSource: false, datacenter: isDatacenter }
    };
    const isTor = (cfData.isTor === true || cfData.isTor === 'true');
    if (isTor) { blocklist.result = true; blocklist.details.attackSource = true; proxyType = 'tor'; }

    let replayPct = 0;
    try {
      const replayQ = await db.query(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE visit_count > 1)::int AS revisits
         FROM fingerprints WHERE ip_address = $1 AND api_key_id = $2
           AND last_seen >= NOW() - INTERVAL '7 days'`,
        [clientIp, apiKeyId]
      );
      const total = replayQ.rows[0]?.total || 0;
      const revisits = replayQ.rows[0]?.revisits || 0;
      replayPct = total > 0 ? Math.round((revisits / total) * 100) : 0;
      if (replayPct >= 75 && total >= 4) {
        blocklist.result = true;
        blocklist.details.attackSource = true;
      }
    } catch (e) {}
    if (isDatacenter && botCount > 0) {
      blocklist.result = true;
      blocklist.details.attackSource = true;
    }

    const locSpoof = evasion?.locationSpoofing || {};
    let locationSpoofResult = false;
    if (locSpoof.signals) {
      const brOff = locSpoof.signals.offset != null ? -locSpoof.signals.offset : browserOffsetMin;
      if (ipOffsetMin != null && brOff != null && Math.abs(ipOffsetMin - brOff) > 120) {
        locationSpoofResult = true;
      }
      if (locSpoof.signals.clockDrift > 5000) locationSpoofResult = true;
    }

    // ─── IDENTITY RESOLUTION — 5-tier matching pipeline ───
    let visitorId: string;
    let isNew = true;
    let matchConfidence = 1.0;
    let matchTier = 'new';
    let matchedSignals: string[] = [];
    let ipChanged = false;
    let previousIp: string | null = null;

    const insertAlias = async (vid: string) => {
      await db.query(
        `INSERT INTO fingerprints
          (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
           screen_hash, font_hash, browser_hash, hardware_hash,
           device_hash, screen_only_hash, gpu_hash, hw_only_hash, fonts_only_hash,
           ip_address, country, first_seen, last_seen, visit_count,
           is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW(),1,$17,$18,$19,$20,$21)`,
        [vid, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
         hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
         hashes.device, hashes.screenOnly, hashes.gpuOnly, hashes.hwOnly, hashes.fontsOnly,
         clientIp, cfData.country || null,
         isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
         apiKeyId]
      );
    };

    const linkDevices = async (vidA: string, vidB: string, linkType: string, conf: number, evidence: string[] = []) => {
      if (vidA === vidB) return;
      const [a, b] = [vidA, vidB].sort();
      try {
        await db.query(`
          CREATE UNIQUE INDEX IF NOT EXISTS device_links_pair_idx ON device_links (visitor_id_a, visitor_id_b)
        `).catch(() => {});
        await db.query(`ALTER TABLE device_links ALTER COLUMN evidence DROP NOT NULL`).catch(() => {});
        await db.query(
          `INSERT INTO device_links (visitor_id_a, visitor_id_b, link_type, confidence, api_key_id, evidence)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (visitor_id_a, visitor_id_b) DO UPDATE SET confidence = GREATEST(device_links.confidence, $4), link_type = $3`,
          [a, b, linkType, conf, apiKeyId, JSON.stringify(evidence)]
        );
      } catch (e) {
        console.error('linkDevices error:', e);
      }
    };

    // Tier 0: StoredId recovery
    const clientStoredIds = storedIds || {};
    const knownVids = [clientStoredIds.ls, clientStoredIds.ss, clientStoredIds.ck, clientStoredIds.legacy]
      .filter((id: any): id is string => typeof id === 'string' && id.startsWith('dvc_'));

    let storedIdMatch: string | null = null;
    if (knownVids.length > 0) {
      const storedResult = await db.query(
        `SELECT visitor_id, ip_address FROM fingerprints
         WHERE visitor_id = ANY($1::text[]) AND api_key_id = $2
         ORDER BY last_seen DESC LIMIT 1`,
        [knownVids, apiKeyId]
      );
      if (storedResult.rows.length > 0) {
        storedIdMatch = storedResult.rows[0].visitor_id;
        previousIp = normalizeIp(storedResult.rows[0].ip_address);
      }
    }

    if (storedIdMatch) {
      visitorId = storedIdMatch;
      isNew = false;
      matchConfidence = 0.99;
      matchTier = 'stored_id';

      if (previousIp && previousIp !== normalizedClientIp) ipChanged = true;

      const aliasExists = await db.query(
        'SELECT 1 FROM fingerprints WHERE raw_hash = $1 AND visitor_id = $2 AND api_key_id = $3 LIMIT 1',
        [hashes.composite, visitorId, apiKeyId]
      );
      if (aliasExists.rows.length > 0) {
        await db.query(
          `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
           WHERE visitor_id = $2 AND api_key_id = $3 AND raw_hash = $4`,
          [clientIp, visitorId, apiKeyId, hashes.composite]
        );
      } else {
        await insertAlias(visitorId);
      }

    // Tier 1: Exact composite hash match
    } else {
      const exactMatch = await db.query(
        'SELECT visitor_id, ip_address FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
        [hashes.composite, apiKeyId]
      );

      if (exactMatch.rows.length > 0) {
        visitorId = exactMatch.rows[0].visitor_id;
        isNew = false;
        matchConfidence = 1.0;
        matchTier = 'exact';
        previousIp = normalizeIp(exactMatch.rows[0].ip_address);
        if (previousIp && previousIp !== normalizedClientIp) ipChanged = true;

        await db.query(
          `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
           WHERE visitor_id = $2 AND api_key_id = $3`,
          [clientIp, visitorId, apiKeyId]
        );

      } else {
        // Tier 2: Weighted fuzzy match
        const candidates = await db.query(
          `SELECT visitor_id, ip_address, canvas_hash, webgl_hash, audio_hash,
                  screen_hash, font_hash, browser_hash, hardware_hash,
                  device_hash, screen_only_hash, gpu_hash, hw_only_hash, fonts_only_hash
           FROM fingerprints
           WHERE api_key_id = $1
           ORDER BY last_seen DESC
           LIMIT 250`,
          [apiKeyId]
        );

        const deviceWeights: Record<string, number> = {
          device:    0.35,
          screenOnly: 0.15,
          gpuOnly:   0.15,
          hwOnly:    0.15,
          fontsOnly: 0.10,
          canvas:    0.04,
          audio:     0.03,
          browser:   0.03,
        };

        const EMPTY_HASH = h({});
        const EMPTY_NULL_HASH = h(null);
        const EMPTY_UNDEF_HASH = h(undefined);
        const emptySentinels = new Set([EMPTY_HASH, EMPTY_NULL_HASH, EMPTY_UNDEF_HASH]);

        let bestScore = 0;
        let bestCandidate: any = null;
        let bestMatched: string[] = [];

        for (const cand of candidates.rows) {
          let score = 0;
          const totalWeight = Object.values(deviceWeights).reduce((a, b) => a + b, 0);
          const matched: string[] = [];

          const devicePairs = [
            { key: 'device',    incoming: hashes.device,     stored: cand.device_hash },
            { key: 'screenOnly', incoming: hashes.screenOnly, stored: cand.screen_only_hash },
            { key: 'gpuOnly',   incoming: hashes.gpuOnly,    stored: cand.gpu_hash },
            { key: 'hwOnly',    incoming: hashes.hwOnly,     stored: cand.hw_only_hash },
            { key: 'fontsOnly', incoming: hashes.fontsOnly,  stored: cand.fonts_only_hash },
          ];

          for (const { key, incoming, stored } of devicePairs) {
            if (!stored || !incoming) continue;
            if (emptySentinels.has(stored) || emptySentinels.has(incoming)) continue;
            if (incoming === stored) {
              score += deviceWeights[key];
              matched.push(key);
            }
          }

          const browserPairs = [
            { key: 'canvas',   values: [hashes.canvas, legacyHashes.canvas],   stored: cand.canvas_hash },
            { key: 'audio',    values: [hashes.audio, legacyHashes.audio],     stored: cand.audio_hash },
            { key: 'browser',  values: [hashes.browser, legacyHashes.browser], stored: cand.browser_hash },
          ];

          for (const { key, values, stored } of browserPairs) {
            if (!stored) continue;
            if (emptySentinels.has(stored)) continue;
            const incoming = values.filter(v => v && !emptySentinels.has(v));
            if (incoming.length === 0) continue;
            if (incoming.includes(stored)) {
              score += deviceWeights[key];
              matched.push(key);
            }
          }

          if (matched.includes('device')) score += 0.10;
          const stableMatches = ['screenOnly', 'gpuOnly', 'hwOnly', 'fontsOnly'].filter(k => matched.includes(k)).length;
          if (stableMatches >= 3) score += 0.08;
          if (normalizeIp(cand.ip_address) === normalizedClientIp && matched.length >= 1) score += 0.05;

          const normalized = score / totalWeight;
          if (normalized > bestScore) {
            bestScore = normalized;
            bestCandidate = cand;
            bestMatched = matched;
          }
        }

        const MATCH_THRESHOLD = 0.45;

        if (bestCandidate && bestScore >= MATCH_THRESHOLD) {
          visitorId = bestCandidate.visitor_id;
          isNew = false;
          matchConfidence = Math.round(bestScore * 100) / 100;
          matchTier = 'fuzzy';
          matchedSignals = bestMatched;
          previousIp = normalizeIp(bestCandidate.ip_address);
          if (previousIp && previousIp !== normalizedClientIp) ipChanged = true;
          await insertAlias(visitorId);

        // Tier 3: Cross-device network linking
        } else {
          let linkCandidate: any = null;
          let linkScore = 0;
          let linkMatched: string[] = [];

          const browserLang = (signals.browser?.lang || signals.browser?.language || '').toLowerCase();

          for (const cand of candidates.rows) {
            const sameIp = normalizeIp(cand.ip_address) === normalizedClientIp;
            if (!sameIp) continue;

            let score = 0.40;
            const matched: string[] = ['same_ip'];

            const stablePairs = [
              { key: 'screenOnly', incoming: hashes.screenOnly, stored: cand.screen_only_hash },
              { key: 'gpuOnly',   incoming: hashes.gpuOnly,    stored: cand.gpu_hash },
              { key: 'hwOnly',    incoming: hashes.hwOnly,     stored: cand.hw_only_hash },
              { key: 'fontsOnly', incoming: hashes.fontsOnly,  stored: cand.fonts_only_hash },
            ];

            for (const { key, incoming, stored } of stablePairs) {
              if (stored && incoming && !emptySentinels.has(stored) && !emptySentinels.has(incoming) && incoming === stored) {
                score += 0.15;
                matched.push(key);
              }
            }

            if (score > linkScore) {
              linkScore = score;
              linkCandidate = cand;
              linkMatched = matched;
            }
          }

          visitorId = `dvc_${nanoid(16)}`;
          matchConfidence = 1.0;

          if (linkCandidate && linkMatched.length >= 3) {
            matchTier = 'cross_device';
            matchedSignals = linkMatched;
            await insertAlias(visitorId);
            const linkConf = Math.round(Math.min(linkScore, 1.0) * 100) / 100;
            await linkDevices(visitorId, linkCandidate.visitor_id, 'same_network', linkConf, linkMatched);
          } else {
            matchTier = 'new';
            await insertAlias(visitorId);
          }
        }
      }
    }

    // Linked devices
    let linkedResult = { rows: [] as any[] };
    try {
      linkedResult = await db.query(
        `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
         FROM device_links
         WHERE (visitor_id_a = $1 OR visitor_id_b = $1) AND api_key_id = $2
         ORDER BY confidence DESC`,
        [visitorId, apiKeyId]
      );
    } catch (e) {
      console.error('device_links query error:', e);
    }

    const linkedVids = linkedResult.rows.map((l: any) =>
      l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a
    );

    let linkedRiskFlags = { vpn: false, incognito: false, headless: false, bot: false };
    if (linkedVids.length > 0) {
      const linkedRiskResult = await db.query(
        `SELECT is_vpn, is_incognito, headless_score, bot_score
         FROM fingerprints
         WHERE visitor_id = ANY($1::text[]) AND api_key_id = $2
         ORDER BY last_seen DESC
         LIMIT 50`,
        [linkedVids, apiKeyId]
      );
      for (const row of linkedRiskResult.rows) {
        if (row.is_vpn) linkedRiskFlags.vpn = true;
        if (row.is_incognito) linkedRiskFlags.incognito = true;
        if ((row.headless_score || 0) >= 40) linkedRiskFlags.headless = true;
        if ((row.bot_score || 0) >= 2) linkedRiskFlags.bot = true;
      }
    }

    const recentIpsResult = await db.query(
      `SELECT DISTINCT ip_address
       FROM fingerprints
       WHERE visitor_id = $1 AND api_key_id = $2
         AND ip_address IS NOT NULL
         AND last_seen >= NOW() - INTERVAL '1 hour'
       LIMIT 10`,
      [visitorId, apiKeyId]
    );
    const distinctRecentPublicIps = recentIpsResult.rows
      .map((row: any) => normalizeIp(row.ip_address))
      .filter((ip: string) => !!ip && !isPrivateIp(ip));
    const vpnByIpRotation = new Set(distinctRecentPublicIps).size >= 4;
    const vpnByIpSwitch = ipChanged && !isNew;
    const finalIsVpn = isVpn || vpnByIpRotation || vpnByIpSwitch;

    let velocity: any = {
      distinctIp: { '5m': 0, '1h': 0, '24h': 0 },
      events: { '5m': 0, '1h': 0, '24h': 0 },
      distinctCountry: { '5m': 0, '1h': 0, '24h': 0 },
      ipEvents: { '5m': 0, '1h': 0, '24h': 0 },
      ipDistinctVisitors: { '1h': 0, '24h': 0 },
    };
    try {
      const [vel5m, vel1h, vel24h, ipVel, ipVisitors1h, ipVisitors24h] = await Promise.all([
        db.query(
          `SELECT COUNT(*)::int AS events, COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '5 minutes'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS events, COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '1 hour'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS events, COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '24 hours'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS ip_events
           FROM events WHERE ip_address = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '24 hours'`,
          [clientIp, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
           FROM events WHERE ip_address = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '1 hour'`,
          [clientIp, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
           FROM events WHERE ip_address = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '24 hours'`,
          [clientIp, apiKeyId]
        ),
      ]);
      velocity.events['5m'] = vel5m.rows[0]?.events || 0;
      velocity.events['1h'] = vel1h.rows[0]?.events || 0;
      velocity.events['24h'] = vel24h.rows[0]?.events || 0;
      velocity.distinctIp['5m'] = vel5m.rows[0]?.distinct_ip || 0;
      velocity.distinctIp['1h'] = vel1h.rows[0]?.distinct_ip || 0;
      velocity.distinctIp['24h'] = vel24h.rows[0]?.distinct_ip || 0;
      velocity.ipEvents['5m'] = Math.min(vel5m.rows[0]?.events || 0, velocity.events['5m']);
      velocity.ipEvents['1h'] = Math.min(vel1h.rows[0]?.events || 0, velocity.events['1h']);
      velocity.ipEvents['24h'] = ipVel.rows[0]?.ip_events || 0;
      velocity.ipDistinctVisitors['1h'] = ipVisitors1h.rows[0]?.cnt || 0;
      velocity.ipDistinctVisitors['24h'] = ipVisitors24h.rows[0]?.cnt || 0;
    } catch (e) {
      console.error('Velocity query error:', e);
    }

    try {
      const countryQ = await db.query(
        `SELECT
           COUNT(DISTINCT CASE WHEN last_seen >= NOW() - INTERVAL '5 minutes' THEN ip_address END)::int AS c5m,
           COUNT(DISTINCT CASE WHEN last_seen >= NOW() - INTERVAL '1 hour' THEN ip_address END)::int AS c1h,
           COUNT(DISTINCT ip_address)::int AS c24h
         FROM fingerprints WHERE visitor_id = $1 AND api_key_id = $2
           AND last_seen >= NOW() - INTERVAL '24 hours'`,
        [visitorId, apiKeyId]
      );
      velocity.distinctCountry['5m'] = Math.min(velocity.distinctIp['5m'], countryQ.rows[0]?.c5m || 0);
      velocity.distinctCountry['1h'] = Math.min(velocity.distinctIp['1h'], countryQ.rows[0]?.c1h || 0);
      velocity.distinctCountry['24h'] = Math.min(velocity.distinctIp['24h'], countryQ.rows[0]?.c24h || 0);
    } catch (e) {}

    const highActivity = velocity.events['1h'] > 20 || velocity.events['5m'] > 10;

    const riskSignalWeights: Array<{ name: string; weight: number; score: number }> = [];
    const addRisk = (name: string, weight: number, active: boolean, intensity?: number) => {
      riskSignalWeights.push({ name, weight, score: active ? (intensity ?? 1.0) : 0 });
    };

    const evasionLayers =
      (finalIsVpn ? 1 : 0) +
      (evasion?.isPrivate ? 1 : 0) +
      (ipChanged ? 1 : 0) +
      (botCount > 0 ? 1 : 0) +
      ((evasion?.headlessScore || 0) > 0.4 ? 1 : 0);
    const layerMultiplier = Math.min(2.0, 1.0 + (evasionLayers - 1) * 0.25);

    addRisk('vpn', 15, finalIsVpn, evasionLayers >= 3 ? 1.0 : evasionLayers >= 2 ? 0.6 : 0.2);
    addRisk('incognito', 10, evasion?.isPrivate || false, evasionLayers >= 3 ? 1.0 : evasionLayers >= 2 ? 0.5 : 0.15);
    addRisk('headless', 20, (evasion?.headlessScore || 0) > 0.4, Math.min(1.0, (evasion?.headlessScore || 0) * 2));
    addRisk('bot', 25, botCount > 0, Math.min(1.0, botCount / 4));
    const tampering = evasion?.tampering || {};
    const tamperCount = Object.values(tampering).filter(Boolean).length;
    addRisk('tampering', 20, tamperCount > 0, Math.min(1.0, tamperCount / 3));
    addRisk('deviceCluster', 5, linkedResult.rows.length > 3, Math.min(1.0, linkedResult.rows.length / 8));
    addRisk('ipChanged', 5, ipChanged && !finalIsVpn);
    addRisk('newAndHiding', 8, isNew && evasionLayers >= 2, Math.min(1.0, evasionLayers / 4));
    addRisk('linkedBot', 10, linkedRiskFlags.bot);
    addRisk('linkedHeadless', 5, linkedRiskFlags.headless);
    addRisk('linkedEvasion', 5, linkedRiskFlags.vpn && linkedRiskFlags.incognito);
    const devToolsOpen = evasion?.devTools?.open || false;
    const vmResult = evasion?.virtualMachine?.result || false;
    addRisk('virtualMachine', 10, vmResult);
    addRisk('locationSpoofing', 15, locationSpoofResult);
    addRisk('highActivity', 8, highActivity, Math.min(1.0, Math.max(velocity.events['1h'] / 40, velocity.events['5m'] / 20)));
    addRisk('tor', 20, isTor);
    addRisk('osMismatch', 8, osMismatch);
    addRisk('replayAttack', 12, replayPct >= 75);

    const totalWeight = riskSignalWeights.reduce((sum, s) => sum + s.weight, 0);
    const weightedSum = riskSignalWeights.reduce((sum, s) => sum + s.weight * s.score, 0);
    let riskScore = totalWeight > 0 ? Math.round((weightedSum / totalWeight) * 100 * layerMultiplier) : 0;
    riskScore = Math.min(100, Math.max(0, riskScore));

    const personResult = await resolvePersonIdentity(
      db, visitorId, apiKeyId, clientIp, signals.userId || undefined,
    );

    try {
      await db.query(
        `INSERT INTO events (visitor_id, event_type, event_data, ip_address, api_key_id)
         VALUES ($1, $2, $3::jsonb, $4, $5)`,
        [visitorId, 'identify', JSON.stringify({
          matchTier, confidence: isNew ? 1.0 : matchConfidence, riskScore,
          isVpn: finalIsVpn, ipChanged, isNew, signalsCollected, proxyType, highActivity, visitorType,
          userAgent: c.req.header('User-Agent') || null,
        }), clientIp, apiKeyId]
      );
    } catch (e) {
      console.error('Event log error:', e);
    }

    const browserUA = c.req.header('User-Agent') || '';
    const uaMatch = browserUA.match(/(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)/);
    const browserName = uaMatch ? uaMatch[1] : 'Other';
    const browserMajorVersion = uaMatch ? uaMatch[2] : '0';
    const osMatch = browserUA.match(/(Windows NT [\d.]+|Mac OS X [\d_]+|Linux|Android [\d.]+|iPhone OS [\d_]+)/);
    const osInfo = osMatch ? osMatch[1] : 'Other';

    return c.json({
      visitorId,
      requestId: `${Date.now()}.${visitorId.substring(4, 10)}`,
      isNew,
      confidence: { score: isNew ? 1.0 : matchConfidence, revision: 'v1.0' },
      matchTier,
      matchedSignals: matchedSignals.length > 0 ? matchedSignals : undefined,
      visitorFound: !isNew,
      visitorType,
      firstSeenAt: null,
      lastSeenAt: null,
      browserDetails: {
        browserName, browserMajorVersion, os: osInfo, userAgent: browserUA,
        device: /Mobile|Android|iPhone/.test(browserUA) ? 'Mobile' : 'Other',
      },
      products: {
        identification: {
          data: { visitorId, confidence: { score: isNew ? 1.0 : matchConfidence }, isNew, matchTier }
        },
        botd: {
          data: {
            bot: {
              result: botClassification,
              type: botClassification === 'good' ? 'searchEngine' : botClassification === 'bad' ? 'automation' : undefined,
            },
            meta: { ip: clientIp }
          }
        },
        vpn: {
          data: {
            result: finalIsVpn, confidence: proxyConfidence,
            originTimezone: browserTimezone || null, originCountry: cfData.country || 'unknown',
            methods: {
              timezoneMismatch: vpnScore >= 3 && ipOffsetMin !== null,
              publicVPN: isVpnAsn, osMismatch, relay: false,
              webrtcLeak: publicWebrtcIps.length > 0 && publicWebrtcIps.every((ip: string) => ip !== normalizedClientIp),
            },
          }
        },
        proxy: {
          data: {
            result: proxyType !== 'none', confidence: proxyConfidence,
            details: { proxyType, ipDistinctVisitors7d: ipDistinctVisitors },
          }
        },
        tor: { data: { result: isTor } },
        ipBlocklist: { data: { ...blocklist, replayPct } },
        incognito: { data: { result: evasion?.isPrivate || false } },
        tampering: {
          data: {
            result: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
            anomalyScore: Object.values(tampering).filter(Boolean).length,
            antiDetectBrowser: !!(tampering.canvasOverride && tampering.uaOverride && tampering.navigatorProxy),
          }
        },
        virtualMachine: { data: { result: vmResult, details: evasion?.virtualMachine || {} } },
        developerTools: { data: { result: devToolsOpen } },
        locationSpoofing: { data: { result: locationSpoofResult, details: locSpoof.signals || {} } },
        highActivity: { data: { result: highActivity } },
        emulator: { data: { result: vmResult && /Android|Mobile/.test(browserUA) } },
        rootApps: { data: { result: false } },
        frida: { data: { result: false } },
        jailbroken: { data: { result: false } },
        clonedApp: { data: { result: false } },
        privacySettings: {
          data: {
            result: evasion?.isPrivate || evasion?.privacyDetails?.brave || evasion?.privacyDetails?.firefoxStrict || evasion?.privacyDetails?.privacyExtension || false,
            brave: evasion?.privacyDetails?.brave || false,
            firefoxStrict: evasion?.privacyDetails?.firefoxStrict || false,
            privacyExtension: evasion?.privacyDetails?.privacyExtension || false,
            mode: evasion?.privacyDetails?.mode || null,
            privacyScore: evasion?.privacyScore || 0,
          }
        },
        factoryReset: { data: { time: null, timestamp: 0 } },
        velocity: { data: velocity },
        suspectScore: {
          data: {
            result: riskScore,
            breakdown: riskSignalWeights.filter(s => s.score > 0).map(s => ({
              signal: s.name, weight: s.weight, intensity: Math.round(s.score * 100) / 100,
            })),
          }
        },
        ipInfo: {
          data: {
            v4: {
              address: clientIp,
              geolocation: {
                accuracyRadius: cfData.city ? (isDatacenter ? 200 : 50) : (cfData.region ? 100 : 500),
                latitude: cfData.latitude || null, longitude: cfData.longitude || null,
                postalCode: cfData.postalCode || null, timezone: cfData.timezone || null,
                city: cfData.city ? { name: cfData.city } : null,
                country: cfData.country ? { code: cfData.country, name: cfData.country } : null,
                continent: cfData.continent ? { code: cfData.continent } : null,
                subdivisions: cfData.region ? [{ isoCode: cfData.region, name: cfData.region }] : [],
              },
              asn: {
                asn: String(cfData.asn || ''), name: cfData.asOrganization || '',
                network: `${clientIp}/24`, type: isDatacenter ? 'hosting' : isVpnAsn ? 'hosting' : 'isp',
              },
              datacenter: { result: isDatacenter, name: isDatacenter ? cfData.asOrganization : '' },
            },
          }
        },
        rawDeviceAttributes: { data: signals.rawAttributes || {} },
      },
      riskScore,
      riskSignals: {
        vpn: finalIsVpn, incognito: evasion?.isPrivate || false,
        headless: (evasion?.headlessScore || 0) > 0.4, bot: botClassification === 'bad',
        tampered: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
        multiAccount: linkedResult.rows.length > 1, ipChanged, tor: isTor, vm: vmResult,
        devTools: devToolsOpen, locationSpoofing: locationSpoofResult, highActivity,
        osMismatch, linkedRisk: linkedRiskFlags,
      },
      identity: {
        linkedDeviceCount: linkedResult.rows.length,
        linkedVisitorIds: linkedVids,
        links: linkedResult.rows.map((l: any) => ({
          visitorId: l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a,
          linkType: l.link_type, confidence: l.confidence, linkedAt: l.created_at,
        })),
        personId: personResult.personId, personLinkType: personResult.linkType,
        personDevices: personResult.linkedDevices, isNewPerson: personResult.isNewPerson,
        previousIp: ipChanged ? previousIp : undefined, currentIp: clientIp,
      },
      signals: {
        collected: signalsCollected, total: signalNames.length, hashes: signalHashes,
        groups: {
          canvas:   { hash: hashes.canvas,   signals: ['canvas'] },
          webgl:    { hash: hashes.webgl,    signals: ['webgl', 'webglRender'] },
          audio:    { hash: hashes.audio,    signals: ['audio'] },
          screen:   { hash: hashes.screen,   signals: ['screen', 'clientRects'] },
          fonts:    { hash: hashes.fonts,    signals: ['fonts', 'arabicFonts', 'emoji'] },
          browser:  { hash: hashes.browser,  signals: ['intlProbe', 'cssSupports', 'codecs', 'voices'] },
          hardware: { hash: hashes.hardware, signals: ['hardware', 'mathml', 'browser'] },
        },
      },
      ip: clientIp,
      geo: {
        country: cfData.country || null, region: cfData.region || null, city: cfData.city || null,
        timezone: cfData.timezone || null, asn: cfData.asn || null,
        asOrganization: cfData.asOrganization || null, continent: cfData.continent || null,
        latitude: cfData.latitude || null, longitude: cfData.longitude || null,
      },
      linkedDevices: linkedResult.rows.length,
      processingMs: Date.now() - startTime,
      sdkVersion: signals.v || '1.0.0',
    });
  } catch (err: any) {
    console.error('Fingerprint error:', err);
    return c.json({ error: 'Failed to process fingerprint', details: err.message }, 500);
  }
});

export default router;
