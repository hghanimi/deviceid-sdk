// api/src/screening.ts — Sanctions Screening Engine for Cloudflare Workers
// Checks against OFAC SDN, UN Consolidated, and EU Financial Sanctions lists

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface SanctionsEntry {
  name: string;
  nameNormalized: string;
  aliases: string[];
  listSource: 'OFAC' | 'UN' | 'EU';
  entityId: string;
  programs: string[];
  dateOfBirth?: string;
  nationality?: string;
}

export interface ScreenMatch {
  matchScore: number;
  matchedName: string;
  queriedName: string;
  listSource: string;
  entityId: string;
  programs: string[];
}

export interface ScreenEntityInput {
  name: string;
  nameAr?: string;
  aliases?: string[];
  dateOfBirth?: string;
  nationality?: string;
}

export interface OwnerScreenResult {
  ownerId: string;
  ownerName: string;
  status: 'clear' | 'flagged';
  matches: ScreenMatch[];
}

export interface ScreeningResult {
  merchantId: string;
  screeningStatus: 'clear' | 'flagged';
  merchantMatches: ScreenMatch[];
  ownerResults: OwnerScreenResult[];
  alertsCreated: number;
  screenedAt: string;
}

// ─── Arabic Text Normalization ─────────────────────────────────────────────────

const ARABIC_DIACRITICS = /[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06DC\u06DF-\u06E4\u06E7\u06E8\u06EA-\u06ED]/g;
const TATWEEL = /\u0640/g;

export function normalizeArabic(text: string): string {
  let r = text;
  r = r.replace(ARABIC_DIACRITICS, '');
  r = r.replace(TATWEEL, '');
  // Hamza normalization: أ إ آ ٱ → ا
  r = r.replace(/[\u0623\u0625\u0622\u0671]/g, '\u0627');
  // ؤ → و
  r = r.replace(/\u0624/g, '\u0648');
  // ئ → ي
  r = r.replace(/\u0626/g, '\u064A');
  // Teh marbuta → heh: ة → ه
  r = r.replace(/\u0629/g, '\u0647');
  // Alef maqsura → ya: ى → ي
  r = r.replace(/\u0649/g, '\u064A');
  return r.trim().replace(/\s+/g, ' ');
}

// ─── Latin Text Normalization ──────────────────────────────────────────────────

export function normalizeLatin(text: string): string {
  let r = text.toLowerCase().trim();
  // Remove al-/el-/ul- prefixes (with optional hyphen or space)
  r = r.replace(/\b(al|el|ul)[-\s]?/g, '');
  // Normalize abd variants → abd
  r = r.replace(/\b(abdul|abdel|abd[- ]?ul|abd[- ]?el|abdu)\b/g, 'abd');
  // Remove ibn/bin/ben particles
  r = r.replace(/\b(ibn|bin|ben)\b/g, '');
  return r.trim().replace(/\s+/g, ' ');
}

// ─── Arabic → Latin Transliteration ────────────────────────────────────────────

// Common Iraqi/Arabic name tokens → canonical Latin
const NAME_TRANSLIT: Record<string, string> = {
  '\u0645\u062D\u0645\u062F': 'muhammad',   // محمد
  '\u0623\u062D\u0645\u062F': 'ahmad',       // أحمد
  '\u0627\u062D\u0645\u062F': 'ahmad',       // احمد (normalized)
  '\u0639\u0644\u064A': 'ali',               // علي
  '\u062D\u0633\u064A\u0646': 'hussein',     // حسين
  '\u062D\u0633\u0646': 'hassan',            // حسن
  '\u0639\u0628\u062F\u0627\u0644\u0644\u0647': 'abdullah', // عبدالله
  '\u0639\u0628\u062F': 'abd',               // عبد
  '\u0627\u0644\u0644\u0647': 'allah',       // الله
  '\u0627\u0644\u0631\u062D\u0645\u0646': 'rahman', // الرحمن
  '\u0639\u0645\u0631': 'omar',              // عمر
  '\u0639\u062B\u0645\u0627\u0646': 'othman', // عثمان
  '\u0625\u0628\u0631\u0627\u0647\u064A\u0645': 'ibrahim', // إبراهيم
  '\u0627\u0628\u0631\u0627\u0647\u064A\u0645': 'ibrahim', // ابراهيم
  '\u064A\u0648\u0633\u0641': 'yusuf',       // يوسف
  '\u0645\u0635\u0637\u0641\u0649': 'mustafa', // مصطفى
  '\u0645\u0635\u0637\u0641\u064A': 'mustafa', // مصطفي (normalized)
  '\u0635\u062F\u0627\u0645': 'saddam',      // صدام
  '\u062E\u0627\u0644\u062F': 'khalid',      // خالد
  '\u0637\u0627\u0631\u0642': 'tariq',       // طارق
  '\u0641\u0627\u0637\u0645\u0647': 'fatima', // فاطمه (normalized)
  '\u0641\u0627\u0637\u0645\u0629': 'fatima', // فاطمة
  '\u0632\u064A\u0646\u0628': 'zainab',      // زينب
  '\u0645\u0631\u064A\u0645': 'mariam',      // مريم
  '\u0646\u0648\u0631': 'noor',              // نور
  '\u0643\u0631\u064A\u0645': 'karim',       // كريم
  '\u0646\u0627\u0635\u0631': 'nasser',      // ناصر
  '\u0633\u0639\u062F': 'saad',              // سعد
  '\u062C\u0639\u0641\u0631': 'jaafar',      // جعفر
  '\u0639\u0628\u0627\u0633': 'abbas',       // عباس
  '\u0631\u0634\u064A\u062F': 'rashid',      // رشيد
  '\u0633\u0639\u064A\u062F': 'saeed',       // سعيد
  '\u0645\u0627\u062C\u062F': 'majid',       // ماجد
  '\u0639\u0627\u062F\u0644': 'adil',        // عادل
  '\u0639\u0644\u0627\u0621': 'alaa',        // علاء
  '\u0639\u0644\u0627': 'alaa',              // علا (normalized)
  '\u062D\u064A\u062F\u0631': 'haider',      // حيدر
  '\u0642\u0627\u0633\u0645': 'qasim',       // قاسم
  '\u0639\u0632\u064A\u0632': 'aziz',        // عزيز
  '\u0647\u0627\u0634\u0645': 'hashim',      // هاشم
  '\u0628\u0643\u0631': 'bakr',              // بكر
  '\u0639\u0645\u0627\u0631': 'ammar',       // عمار
  '\u0633\u0644\u0645\u0627\u0646': 'salman', // سلمان
  '\u0633\u0644\u064A\u0645': 'salim',       // سليم
  '\u0631\u0636\u0627': 'rida',              // رضا
  '\u0645\u0647\u062F\u064A': 'mahdi',       // مهدي
  '\u0628\u0627\u0642\u0631': 'baqir',       // باقر
  '\u0635\u0627\u062F\u0642': 'sadiq',       // صادق
  '\u0643\u0627\u0638\u0645': 'kazim',       // كاظم
  '\u0645\u0648\u0633\u0649': 'musa',        // موسى
  '\u0645\u0648\u0633\u064A': 'musa',        // موسي (normalized)
  '\u0639\u064A\u0633\u0649': 'isa',         // عيسى
  '\u0639\u064A\u0633\u064A': 'isa',         // عيسي (normalized)
  '\u062F\u0627\u0648\u062F': 'dawood',      // داود
  '\u0633\u0644\u064A\u0645\u0627\u0646': 'sulaiman', // سليمان
};

// Character-level Arabic → Latin transliteration fallback
const CHAR_TRANSLIT: Record<string, string> = {
  '\u0627': 'a',  // ا
  '\u0628': 'b',  // ب
  '\u062A': 't',  // ت
  '\u062B': 'th', // ث
  '\u062C': 'j',  // ج
  '\u062D': 'h',  // ح
  '\u062E': 'kh', // خ
  '\u062F': 'd',  // د
  '\u0630': 'dh', // ذ
  '\u0631': 'r',  // ر
  '\u0632': 'z',  // ز
  '\u0633': 's',  // س
  '\u0634': 'sh', // ش
  '\u0635': 's',  // ص
  '\u0636': 'd',  // ض
  '\u0637': 't',  // ط
  '\u0638': 'z',  // ظ
  '\u0639': 'a',  // ع
  '\u063A': 'gh', // غ
  '\u0641': 'f',  // ف
  '\u0642': 'q',  // ق
  '\u0643': 'k',  // ك
  '\u0644': 'l',  // ل
  '\u0645': 'm',  // م
  '\u0646': 'n',  // ن
  '\u0647': 'h',  // ه
  '\u0648': 'w',  // و
  '\u064A': 'y',  // ي
  '\u0649': 'a',  // ى (alef maqsura)
  '\u0629': 'a',  // ة (teh marbuta)
};

export function transliterateArabic(text: string): string {
  const normalized = normalizeArabic(text);
  const tokens = normalized.split(/\s+/);
  const result: string[] = [];

  for (const token of tokens) {
    // Try whole-token lookup first
    if (NAME_TRANSLIT[token]) {
      result.push(NAME_TRANSLIT[token]);
      continue;
    }
    // Character-by-character fallback
    let latin = '';
    for (const ch of token) {
      latin += CHAR_TRANSLIT[ch] || ch;
    }
    result.push(latin);
  }

  return normalizeLatin(result.join(' '));
}

function isArabic(text: string): boolean {
  return /[\u0600-\u06FF]/.test(text);
}

// ─── Jaro-Winkler Similarity ──────────────────────────────────────────────────

function jaro(s1: string, s2: string): number {
  if (s1 === s2) return 1.0;
  const len1 = s1.length;
  const len2 = s2.length;
  if (len1 === 0 || len2 === 0) return 0.0;

  const matchDist = Math.floor(Math.max(len1, len2) / 2) - 1;
  const s1Matches = new Array(len1).fill(false);
  const s2Matches = new Array(len2).fill(false);

  let matches = 0;
  let transpositions = 0;

  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDist);
    const end = Math.min(i + matchDist + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0.0;

  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  return (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3;
}

export function jaroWinkler(s1: string, s2: string): number {
  const jaroSim = jaro(s1, s2);
  let prefix = 0;
  const maxPrefix = Math.min(4, Math.min(s1.length, s2.length));
  for (let i = 0; i < maxPrefix; i++) {
    if (s1[i] === s2[i]) prefix++;
    else break;
  }
  return jaroSim + prefix * 0.1 * (1 - jaroSim);
}

// ─── Name Matching ─────────────────────────────────────────────────────────────

/**
 * Compare two names with cross-script support. Returns best similarity score.
 * Handles: Arabic↔Arabic, Latin↔Latin, Arabic↔Latin (via transliteration).
 */
export function compareNames(query: string, target: string): number {
  const qIsArabic = isArabic(query);
  const tIsArabic = isArabic(target);

  // Same script comparison
  if (qIsArabic && tIsArabic) {
    return jaroWinkler(normalizeArabic(query), normalizeArabic(target));
  }
  if (!qIsArabic && !tIsArabic) {
    return jaroWinkler(normalizeLatin(query), normalizeLatin(target));
  }

  // Cross-script: transliterate Arabic to Latin, compare
  const qLatin = qIsArabic ? transliterateArabic(query) : normalizeLatin(query);
  const tLatin = tIsArabic ? transliterateArabic(target) : normalizeLatin(target);
  return jaroWinkler(qLatin, tLatin);
}

// ─── CSV / XML Parsing ────────────────────────────────────────────────────────

function parseCSVRow(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        fields.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
  }
  fields.push(current.trim());
  return fields;
}

function extractAKAs(remarks: string): string[] {
  const aliases: string[] = [];
  const akaPattern = /a\.k\.a\.\s*'([^']+)'/gi;
  let match;
  while ((match = akaPattern.exec(remarks)) !== null) {
    aliases.push(match[1].trim());
  }
  // Also try without quotes
  const akaPattern2 = /a\.k\.a\.\s+"([^"]+)"/gi;
  while ((match = akaPattern2.exec(remarks)) !== null) {
    aliases.push(match[1].trim());
  }
  return aliases;
}

function parseOFAC(csv: string): SanctionsEntry[] {
  const entries: SanctionsEntry[] = [];
  const lines = csv.split('\n');

  for (const line of lines) {
    if (!line.trim()) continue;
    const fields = parseCSVRow(line);
    if (fields.length < 12) continue;

    const entNum = fields[0];
    const name = fields[1];
    const programs = fields[3] ? fields[3].split(';').map(p => p.trim()).filter(Boolean) : [];
    const remarks = fields[11] || '';

    if (!name || !entNum) continue;
    // Skip header if present
    if (entNum.toLowerCase() === 'ent_num') continue;

    const aliases = extractAKAs(remarks);
    const normalized = isArabic(name) ? normalizeArabic(name) : normalizeLatin(name);

    entries.push({
      name,
      nameNormalized: normalized,
      aliases,
      listSource: 'OFAC',
      entityId: `OFAC-${entNum}`,
      programs,
    });
  }

  return entries;
}

function xmlText(xml: string, tag: string): string {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, 'i');
  const m = xml.match(re);
  return m ? m[1].trim() : '';
}

function xmlAll(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, 'gi');
  const results: string[] = [];
  let m;
  while ((m = re.exec(xml)) !== null) {
    if (m[1].trim()) results.push(m[1].trim());
  }
  return results;
}

function xmlBlocks(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'gi');
  const results: string[] = [];
  let m;
  while ((m = re.exec(xml)) !== null) {
    results.push(m[1]);
  }
  return results;
}

function parseUNXML(xml: string): SanctionsEntry[] {
  const entries: SanctionsEntry[] = [];

  // Parse INDIVIDUALS
  const individuals = xmlBlocks(xml, 'INDIVIDUAL');
  for (const ind of individuals) {
    const dataId = xmlText(ind, 'DATAID');
    const firstName = xmlText(ind, 'FIRST_NAME');
    const secondName = xmlText(ind, 'SECOND_NAME');
    const thirdName = xmlText(ind, 'THIRD_NAME');
    const fourthName = xmlText(ind, 'FOURTH_NAME');
    const listType = xmlText(ind, 'UN_LIST_TYPE');
    const refNum = xmlText(ind, 'REFERENCE_NUMBER');

    const nameParts = [firstName, secondName, thirdName, fourthName].filter(Boolean);
    const fullName = nameParts.join(' ');
    if (!fullName) continue;

    // Extract aliases
    const aliasBlocks = xmlBlocks(ind, 'INDIVIDUAL_ALIAS');
    const aliases = aliasBlocks.map(a => xmlText(a, 'ALIAS_NAME')).filter(Boolean);

    // Extract DOB
    const dobBlocks = xmlBlocks(ind, 'INDIVIDUAL_DATE_OF_BIRTH');
    const dob = dobBlocks.length > 0 ? (xmlText(dobBlocks[0], 'DATE') || xmlText(dobBlocks[0], 'YEAR')) : undefined;

    // Extract nationality
    const natBlocks = xmlBlocks(ind, 'NATIONALITY');
    const nationality = natBlocks.length > 0 ? xmlText(natBlocks[0], 'VALUE') : undefined;

    const normalized = isArabic(fullName) ? normalizeArabic(fullName) : normalizeLatin(fullName);

    entries.push({
      name: fullName,
      nameNormalized: normalized,
      aliases,
      listSource: 'UN',
      entityId: refNum || `UN-${dataId}`,
      programs: listType ? [listType] : [],
      dateOfBirth: dob,
      nationality,
    });
  }

  // Parse ENTITIES
  const entities = xmlBlocks(xml, 'ENTITY');
  for (const ent of entities) {
    const dataId = xmlText(ent, 'DATAID');
    const firstName = xmlText(ent, 'FIRST_NAME');
    const listType = xmlText(ent, 'UN_LIST_TYPE');
    const refNum = xmlText(ent, 'REFERENCE_NUMBER');

    if (!firstName) continue;

    const aliasBlocks = xmlBlocks(ent, 'ENTITY_ALIAS');
    const aliases = aliasBlocks.map(a => xmlText(a, 'ALIAS_NAME')).filter(Boolean);

    const normalized = isArabic(firstName) ? normalizeArabic(firstName) : normalizeLatin(firstName);

    entries.push({
      name: firstName,
      nameNormalized: normalized,
      aliases,
      listSource: 'UN',
      entityId: refNum || `UN-${dataId}`,
      programs: listType ? [listType] : [],
    });
  }

  return entries;
}

// ─── SanctionsScreener (Singleton with Memory Cache) ──────────────────────────

const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

const LIST_URLS = {
  OFAC: 'https://www.treasury.gov/ofac/downloads/sdn.csv',
  UN: 'https://scsanctions.un.org/resources/xml/en/consolidated.xml',
  EU: 'https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content',
};

export class SanctionsScreener {
  private static instance: SanctionsScreener;
  private entries: SanctionsEntry[] = [];
  private lastRefresh = 0;
  private refreshPromise: Promise<void> | null = null;

  static getInstance(): SanctionsScreener {
    if (!SanctionsScreener.instance) {
      SanctionsScreener.instance = new SanctionsScreener();
    }
    return SanctionsScreener.instance;
  }

  private isStale(): boolean {
    return Date.now() - this.lastRefresh > CACHE_TTL;
  }

  async ensureLoaded(): Promise<void> {
    if (!this.isStale() && this.entries.length > 0) return;
    // Deduplicate concurrent refreshes
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.refresh();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async refresh(): Promise<void> {
    const results = await Promise.allSettled([
      this.fetchOFAC(),
      this.fetchUN(),
      this.fetchEU(),
    ]);

    const newEntries: SanctionsEntry[] = [];
    for (const r of results) {
      if (r.status === 'fulfilled') {
        newEntries.push(...r.value);
      } else {
        console.error('Sanctions list fetch failed:', r.reason);
      }
    }

    if (newEntries.length > 0) {
      this.entries = newEntries;
      this.lastRefresh = Date.now();
      console.log(`Sanctions cache refreshed: ${newEntries.length} entries`);
    } else if (this.entries.length === 0) {
      console.error('All sanctions list fetches failed, cache is empty');
    }
    // If some failed but we had old data, keep old data and update timestamp
    // to avoid hammering failing endpoints
    if (newEntries.length === 0 && this.entries.length > 0) {
      this.lastRefresh = Date.now();
    }
  }

  private async fetchOFAC(): Promise<SanctionsEntry[]> {
    const resp = await fetch(LIST_URLS.OFAC, {
      headers: { 'User-Agent': 'Athar-Compliance/1.0' },
    });
    if (!resp.ok) throw new Error(`OFAC fetch failed: ${resp.status}`);
    const csv = await resp.text();
    return parseOFAC(csv);
  }

  private async fetchUN(): Promise<SanctionsEntry[]> {
    const resp = await fetch(LIST_URLS.UN, {
      headers: { 'User-Agent': 'Athar-Compliance/1.0' },
    });
    if (!resp.ok) throw new Error(`UN fetch failed: ${resp.status}`);
    const xml = await resp.text();
    return parseUNXML(xml);
  }

  private async fetchEU(): Promise<SanctionsEntry[]> {
    try {
      const resp = await fetch(LIST_URLS.EU, {
        headers: { 'User-Agent': 'Athar-Compliance/1.0' },
      });
      if (!resp.ok) throw new Error(`EU fetch failed: ${resp.status}`);
      const csv = await resp.text();
      return this.parseEUCSV(csv);
    } catch (e) {
      console.error('EU sanctions list unavailable, skipping:', e);
      return [];
    }
  }

  private parseEUCSV(csv: string): SanctionsEntry[] {
    const entries: SanctionsEntry[] = [];
    const lines = csv.split('\n');
    if (lines.length < 2) return entries;

    // Detect header columns
    const header = parseCSVRow(lines[0]);
    const nameIdx = header.findIndex(h => /^(name|subject)/i.test(h.replace(/^["']|["']$/g, '')));
    const idIdx = header.findIndex(h => /^(id|entity_id|logical_id)/i.test(h.replace(/^["']|["']$/g, '')));
    const progIdx = header.findIndex(h => /programme|program|regime/i.test(h.replace(/^["']|["']$/g, '')));
    const aliasIdx = header.findIndex(h => /alias/i.test(h.replace(/^["']|["']$/g, '')));

    if (nameIdx === -1) return entries; // Can't parse without name column

    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const fields = parseCSVRow(lines[i]);
      const name = fields[nameIdx];
      if (!name) continue;

      const entityId = idIdx >= 0 ? `EU-${fields[idIdx]}` : `EU-${i}`;
      const programs = progIdx >= 0 && fields[progIdx] ? [fields[progIdx]] : [];
      const aliases = aliasIdx >= 0 && fields[aliasIdx]
        ? fields[aliasIdx].split(';').map(a => a.trim()).filter(Boolean)
        : [];

      const normalized = isArabic(name) ? normalizeArabic(name) : normalizeLatin(name);

      entries.push({
        name,
        nameNormalized: normalized,
        aliases,
        listSource: 'EU',
        entityId,
        programs,
      });
    }

    return entries;
  }

  getEntries(): SanctionsEntry[] {
    return this.entries;
  }

  getStats(): { total: number; byList: Record<string, number>; lastRefresh: number } {
    const byList: Record<string, number> = {};
    for (const e of this.entries) {
      byList[e.listSource] = (byList[e.listSource] || 0) + 1;
    }
    return { total: this.entries.length, byList, lastRefresh: this.lastRefresh };
  }
}

// ─── screenEntity ──────────────────────────────────────────────────────────────

const MATCH_THRESHOLD = 0.85;

export async function screenEntity(
  input: ScreenEntityInput,
  screener?: SanctionsScreener,
): Promise<ScreenMatch[]> {
  const sc = screener || SanctionsScreener.getInstance();
  await sc.ensureLoaded();

  const entries = sc.getEntries();
  const matches: ScreenMatch[] = [];

  // Build list of query names to check
  const queryNames: string[] = [input.name];
  if (input.nameAr) queryNames.push(input.nameAr);
  if (input.aliases) queryNames.push(...input.aliases);

  for (const entry of entries) {
    let bestScore = 0;
    let bestQueryName = '';

    // Compare each query name against primary name + aliases
    const targetNames = [entry.name, ...entry.aliases];

    for (const qName of queryNames) {
      for (const tName of targetNames) {
        const score = compareNames(qName, tName);
        if (score > bestScore) {
          bestScore = score;
          bestQueryName = qName;
        }
      }
    }

    // Apply DOB/nationality boosting
    if (bestScore >= MATCH_THRESHOLD * 0.9) { // Check near-threshold too
      if (input.dateOfBirth && entry.dateOfBirth) {
        if (input.dateOfBirth === entry.dateOfBirth) {
          bestScore = Math.min(1.0, bestScore + 0.05); // DOB match boosts
        } else {
          bestScore -= 0.03; // DOB mismatch reduces confidence slightly
        }
      }
      if (input.nationality && entry.nationality) {
        const qNat = input.nationality.toLowerCase();
        const tNat = entry.nationality.toLowerCase();
        if (qNat === tNat || qNat.includes(tNat) || tNat.includes(qNat)) {
          bestScore = Math.min(1.0, bestScore + 0.03);
        }
      }
    }

    if (bestScore >= MATCH_THRESHOLD) {
      matches.push({
        matchScore: Math.round(bestScore * 10000) / 10000,
        matchedName: entry.name,
        queriedName: bestQueryName,
        listSource: entry.listSource,
        entityId: entry.entityId,
        programs: entry.programs,
      });
    }
  }

  // Sort by score descending
  matches.sort((a, b) => b.matchScore - a.matchScore);
  return matches;
}

// ─── screenMerchant (DB-integrated) ───────────────────────────────────────────

const ALERT_THRESHOLD = 0.75;

export async function screenMerchant(
  db: any,
  merchantId: string,
  apiKey: any,
  clientIp: string,
): Promise<ScreeningResult> {
  // 1. Get merchant + owners
  const mResult = await db.query(
    `SELECT * FROM merchants WHERE id = $1 AND api_key_id = $2`,
    [merchantId, apiKey.id],
  );
  if (mResult.rows.length === 0) throw new Error('MERCHANT_NOT_FOUND');
  const merchant = mResult.rows[0];

  const ownersResult = await db.query(
    `SELECT * FROM merchant_owners WHERE merchant_id = $1`,
    [merchantId],
  );
  const owners = ownersResult.rows;

  // 2. Mark in-progress
  await db.query(
    `UPDATE merchants SET screening_status = 'in_progress', updated_at = NOW() WHERE id = $1`,
    [merchantId],
  );
  await db.query(
    `UPDATE merchant_owners SET screening_status = 'in_progress' WHERE merchant_id = $1`,
    [merchantId],
  );

  // 3. Ensure sanctions lists are loaded
  const screener = SanctionsScreener.getInstance();
  await screener.ensureLoaded();

  // 4. Screen merchant legal name
  const merchantInput: ScreenEntityInput = {
    name: merchant.legal_name_en || merchant.legal_name_ar,
    nameAr: merchant.legal_name_ar,
    aliases: merchant.trade_name ? [merchant.trade_name] : [],
  };
  const merchantMatches = await screenEntity(merchantInput, screener);

  // 5. Store merchant screening results
  for (const match of merchantMatches) {
    await db.query(
      `INSERT INTO screening_results (merchant_id, owner_id, entity_name, matched_name, match_score, list_source, entity_id, programs, details)
       VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
      [
        merchantId,
        merchantInput.name,
        match.matchedName,
        match.matchScore,
        match.listSource,
        match.entityId,
        JSON.stringify(match.programs),
        JSON.stringify({ queriedName: match.queriedName }),
      ],
    );
  }

  // 6. Screen each owner
  const ownerResults: OwnerScreenResult[] = [];
  let alertsCreated = 0;

  for (const owner of owners) {
    // Build all name variants for this owner
    const nameVariants: string[] = [];
    if (owner.full_name_en) nameVariants.push(owner.full_name_en);
    if (owner.full_name_ar) nameVariants.push(owner.full_name_ar);

    // Build full Arabic name from components if available
    const arParts = [
      owner.full_name_ar,
      owner.father_name_ar,
      owner.grandfather_name_ar,
      owner.family_name_ar,
    ].filter(Boolean);
    if (arParts.length > 1) {
      nameVariants.push(arParts.join(' '));
    }

    const input: ScreenEntityInput = {
      name: owner.full_name_en || owner.full_name_ar,
      nameAr: owner.full_name_ar,
      aliases: nameVariants,
      dateOfBirth: owner.date_of_birth
        ? (typeof owner.date_of_birth === 'string' ? owner.date_of_birth.slice(0, 10) : owner.date_of_birth.toISOString().slice(0, 10))
        : undefined,
      nationality: owner.nationality,
    };

    const ownerMatches = await screenEntity(input, screener);
    const ownerStatus = ownerMatches.length > 0 ? 'flagged' : 'clear';

    // Store owner screening results
    for (const match of ownerMatches) {
      await db.query(
        `INSERT INTO screening_results (merchant_id, owner_id, entity_name, matched_name, match_score, list_source, entity_id, programs, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
        [
          merchantId,
          owner.id,
          input.name,
          match.matchedName,
          match.matchScore,
          match.listSource,
          match.entityId,
          JSON.stringify(match.programs),
          JSON.stringify({ queriedName: match.queriedName, dateOfBirth: input.dateOfBirth }),
        ],
      );
    }

    // Create alerts for matches above alert threshold
    const alertableMatches = ownerMatches.filter(m => m.matchScore >= ALERT_THRESHOLD);
    for (const match of alertableMatches) {
      // actually we need to check ALL matches >= ALERT_THRESHOLD, the screenEntity already uses 0.85 threshold
      // so all returned matches are >= 0.85 which is > 0.75, so all will be alerted
    }

    // Create alerts (all returned matches from screenEntity are >= 0.85 > ALERT_THRESHOLD)
    for (const match of ownerMatches) {
      await db.query(
        `INSERT INTO merchant_alerts (merchant_id, owner_id, alert_type, severity, details)
         VALUES ($1, $2, 'sanctions_match', $3, $4::jsonb)`,
        [
          merchantId,
          owner.id,
          match.matchScore >= 0.95 ? 'critical' : match.matchScore >= 0.90 ? 'high' : 'medium',
          JSON.stringify({
            matchScore: match.matchScore,
            matchedName: match.matchedName,
            queriedName: match.queriedName,
            listSource: match.listSource,
            entityId: match.entityId,
            programs: match.programs,
          }),
        ],
      );
      alertsCreated++;
    }

    // Update owner screening status
    await db.query(
      `UPDATE merchant_owners
       SET screening_status = $1,
           screening_result = $2::jsonb,
           last_screened_at = NOW()
       WHERE id = $3`,
      [
        ownerStatus,
        JSON.stringify({ matches: ownerMatches, screenedAt: new Date().toISOString() }),
        owner.id,
      ],
    );

    ownerResults.push({
      ownerId: owner.id,
      ownerName: owner.full_name_en || owner.full_name_ar,
      status: ownerStatus,
      matches: ownerMatches,
    });
  }

  // 7. Create merchant-level alerts
  for (const match of merchantMatches) {
    await db.query(
      `INSERT INTO merchant_alerts (merchant_id, owner_id, alert_type, severity, details)
       VALUES ($1, NULL, 'sanctions_match', $2, $3::jsonb)`,
      [
        merchantId,
        match.matchScore >= 0.95 ? 'critical' : match.matchScore >= 0.90 ? 'high' : 'medium',
        JSON.stringify({
          matchScore: match.matchScore,
          matchedName: match.matchedName,
          queriedName: match.queriedName,
          listSource: match.listSource,
          entityId: match.entityId,
          programs: match.programs,
        }),
      ],
    );
    alertsCreated++;
  }

  // 8. Update merchant screening status
  const merchantStatus = merchantMatches.length > 0 || ownerResults.some(o => o.status === 'flagged')
    ? 'flagged' : 'clear';

  await db.query(
    `UPDATE merchants
     SET screening_status = $1, last_screened_at = NOW(), updated_at = NOW()
     WHERE id = $2`,
    [merchantStatus, merchantId],
  );

  // 9. Audit log
  const screenedAt = new Date().toISOString();
  await db.query(
    `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
     VALUES ($1, 'screening_completed', $2, $3::jsonb, $4)`,
    [
      merchantId,
      apiKey.public_key,
      JSON.stringify({
        screeningStatus: merchantStatus,
        merchantMatches: merchantMatches.length,
        ownersScreened: owners.length,
        ownersFlagged: ownerResults.filter(o => o.status === 'flagged').length,
        alertsCreated,
        sanctionsStats: screener.getStats(),
      }),
      clientIp,
    ],
  );

  return {
    merchantId,
    screeningStatus: merchantStatus,
    merchantMatches,
    ownerResults,
    alertsCreated,
    screenedAt,
  };
}
