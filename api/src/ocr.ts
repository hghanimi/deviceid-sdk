// KYC Document OCR via Claude API
// Extracts structured data from Iraqi national IDs, passports, business licenses, resident IDs

export interface OcrField {
  value: string | null;
  confidence: number; // 0-1
}

export interface NationalIdExtraction {
  doc_type: 'national_id';
  doc_side: OcrField;
  // Front side fields
  first_name_ar: OcrField;
  father_name_ar: OcrField;
  grandfather_name_ar: OcrField;
  surname_ar: OcrField;
  mother_name_ar: OcrField;
  full_name_ar: OcrField;
  full_name_en: OcrField;
  national_id_number: OcrField;
  civil_status_number: OcrField;
  gender: OcrField;
  blood_type: OcrField;
  nationality: OcrField;
  // Back side fields
  date_of_birth: OcrField;
  place_of_birth: OcrField;
  issue_date: OcrField;
  expiry_date: OcrField;
  issuing_authority: OcrField;
  family_number: OcrField;
  mrz_line_1: OcrField;
  mrz_line_2: OcrField;
  mrz_line_3: OcrField;
}

export interface PassportExtraction {
  doc_type: 'passport';
  full_name_ar: OcrField;
  full_name_en: OcrField;
  passport_number: OcrField;
  nationality: OcrField;
  date_of_birth: OcrField;
  issue_date: OcrField;
  expiry_date: OcrField;
}

export interface BusinessLicenseExtraction {
  doc_type: 'business_license';
  business_name_ar: OcrField;
  business_name_en: OcrField;
  registration_number: OcrField;
  business_type: OcrField;
  address: OcrField;
  issue_date: OcrField;
  expiry_date: OcrField;
  owner_names: OcrField;
}

export interface ResidentIdExtraction {
  doc_type: 'resident_id';
  head_of_household_ar: OcrField;
  head_of_household_en: OcrField;
  information_office: OcrField;
  residential_address: OcrField;
  form_number: OcrField;
  district: OcrField;
  neighborhood: OcrField;
  alley: OcrField;
  house_number: OcrField;
  family_members: OcrField;
  issue_date: OcrField;
}

export type DocumentExtraction = NationalIdExtraction | PassportExtraction | BusinessLicenseExtraction | ResidentIdExtraction;

export interface OcrResult {
  success: boolean;
  extraction: DocumentExtraction | null;
  raw_text: string | null;
  error?: string;
  model: string;
  processed_at: string;
}

export interface ValidationIssue {
  field: string;
  expected: string | null;
  extracted: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
}

export interface ValidationReport {
  is_valid: boolean;
  issues: ValidationIssue[];
  checked_at: string;
}

const EXTRACTION_PROMPTS: Record<string, string> = {
  national_id_front: `You are an expert OCR system specialized in Iraqi national identity cards (البطاقة الوطنية / کارتی نیشتمانی). This is the FRONT side of the card.

The Iraqi national ID front side has this EXACT layout (Arabic right-to-left with Kurdish translations):
- Header: جمهورية العراق / وزارة الداخلية / مديرية الجنسية العامة
- البطاقة الوطنية / کارتی نیشتمانی followed by a long number (e.g. 199040310180)
- A photo on the left side
- الاسم / ناو : [first name in Arabic]
- الأب / باوك : [father name]
- الجد / بابير : [grandfather name]
- اللقب / نازناو : [surname/family name]
- الأم / داك : [mother first name]
- الجد / بابير : [maternal grandfather]
- الجنس / رەگەز : [gender - ذكر or أنثى]
- فصيلة الدم / گروپی خوین : [blood type like AB+, O+, etc.]
- Bottom left: a serial like AM5002278
- Bottom right: a number like 839791

Return ONLY valid JSON (no markdown, no explanation):
{
  "doc_type": "national_id",
  "doc_side": {"value": "front", "confidence": 1.0},
  "first_name_ar": {"value": "حيدر", "confidence": 0.95},
  "father_name_ar": {"value": "عزيز", "confidence": 0.95},
  "grandfather_name_ar": {"value": "كاظم", "confidence": 0.95},
  "surname_ar": {"value": "غانمي", "confidence": 0.95},
  "mother_name_ar": {"value": "ابتسام", "confidence": 0.90},
  "full_name_ar": {"value": "حيدر عزيز كاظم غانمي", "confidence": 0.95},
  "national_id_number": {"value": "199040310180", "confidence": 0.99},
  "civil_status_number": {"value": "AM5002278", "confidence": 0.95},
  "gender": {"value": "ذكر", "confidence": 0.99},
  "blood_type": {"value": "AB+", "confidence": 0.95},
  "nationality": {"value": "عراقي", "confidence": 0.95},
  "raw_text": "every piece of text on the front"
}

Rules:
- The long number after البطاقة الوطنية is the national_id_number
- Combine first_name + father_name + grandfather_name + surname_ar into full_name_ar
- The serial at bottom-left (like AM5002278) is civil_status_number
- The front side ONLY has: Arabic names, gender, blood type, ID number, civil status number, nationality
- front side does NOT have dates (DOB, issue, expiry), English name, MRZ, family number — do NOT include those fields
- The national ID card has NO English name anywhere — do NOT translate or transliterate Arabic names to English
- Gender: ذكر = Male, أنثى = Female
- Read Arabic text carefully, each field has a label followed by : then the value
- Include ALL text in raw_text`,

  national_id_back: `You are an expert OCR system specialized in Iraqi national identity cards (البطاقة الوطنية). This is the BACK side of the card.

The Iraqi national ID back side has this EXACT layout (fields appear in this order from top):
- جهة الاصدار / لایەنی دەرچوون : [issuing authority — usually a directorate name like مديرية الجنسية والمعلومات المدنية]
- تأريخ الاصدار / ڕۆژی دەرچوون : [issue date in YYYY/MM/DD or DD/MM/YYYY format]
- تأريخ النفاذ / ڕۆژی بەسەرچوون : [expiry date — same format as issue date]
- محل الولادة / شوێنی لەدایک بوون : [place of birth — an Iraqi city/province name like بغداد, كربلاء, البصرة]
- تاريخ الولادة / ڕۆژی لەدایک بوون : [date of birth — same format]
- الرقم العائلي / ژمارەی خێزانی : [family number — a NUMERIC code, typically all digits like 10110054320019001]
- MRZ zone at the bottom: 3 lines of machine-readable text

MRZ FORMAT for Iraqi national ID (TD1 format, 3 lines of 30 characters):
- Line 1: IDIRQ[document_number][check][optional_data]<<<
- Line 2: [YYMMDD_dob][check][sex][YYMMDD_expiry][check][nationality][optional]<<<[check]
- Line 3: [SURNAME]<<[GIVEN_NAMES]<<<...

Return ONLY valid JSON (no markdown, no explanation):
{
  "doc_type": "national_id",
  "doc_side": {"value": "back", "confidence": 1.0},
  "date_of_birth": {"value": "1990-05-13", "confidence": 0.99},
  "place_of_birth": {"value": "كربلاء", "confidence": 0.95},
  "issue_date": {"value": "2019-01-16", "confidence": 0.99},
  "expiry_date": {"value": "2029-01-15", "confidence": 0.99},
  "issuing_authority": {"value": "مديرية الجنسية والمعلومات المدنية", "confidence": 0.95},
  "family_number": {"value": "10110054320019001", "confidence": 0.90},
  "mrz_line_1": {"value": "IDIRQAM500227861990403101180<<<", "confidence": 0.95},
  "mrz_line_2": {"value": "9005134M2901156IRQ<<<<<<<<<8", "confidence": 0.95},
  "mrz_line_3": {"value": "GANMY<<XHYDR<<<<<<<<<<<<<<<", "confidence": 0.95},
  "raw_text": "every piece of text on the back"
}

Rules:
- DATES: Read the actual printed date text carefully. Convert to YYYY-MM-DD format in output regardless of input format.
- The date after تأريخ الاصدار is the issue_date
- The date after تأريخ النفاذ is the expiry_date
- The date after تاريخ الولادة is date_of_birth
- Read the 3 MRZ lines at the bottom EXACTLY as printed (preserve < characters)
- The national ID has NO English name — do NOT extract or transliterate names from MRZ into full_name_en. The MRZ transliteration is non-standard and may differ from the official passport English name.
- FAMILY NUMBER: This is typically a long NUMERIC code (all digits). If you see letters like L, O, I mixed in, they are likely OCR misreads of digits 1, 0, 1. Prefer digits over letters for this field.
- The back side does NOT have: Arabic name fields, gender, blood type, national_id_number, civil_status_number — do NOT include those fields
- Include ALL text in raw_text`,

  national_id: `You are an expert OCR system specialized in Iraqi national identity cards (البطاقة الوطنية / کارتی نیشتمانی). This image could be either the front or back side.

FRONT side has: photo, Arabic name fields (الاسم, الأب, الجد, اللقب, الأم), gender (الجنس), blood type (فصيلة الدم), and the البطاقة الوطنية number, civil status number.
BACK side has: جهة الاصدار (issuing authority), تأريخ الاصدار (issue date), تأريخ النفاذ (expiry), محل الولادة (birthplace), تاريخ الولادة (DOB), الرقم العائلي (family number), MRZ lines.

IMPORTANT: The Iraqi national ID has NO English name. Do NOT translate or transliterate Arabic names. The MRZ on the back contains a non-standard transliteration that does NOT represent the official English name (that comes from the passport only).

First determine which side this is, then extract ONLY the fields that belong to that side.

For FRONT, return:
{
  "doc_type": "national_id",
  "doc_side": {"value": "front", "confidence": 0.99},
  "first_name_ar": {"value": "...", "confidence": 0.95},
  "father_name_ar": {"value": "...", "confidence": 0.95},
  "grandfather_name_ar": {"value": "...", "confidence": 0.95},
  "surname_ar": {"value": "...", "confidence": 0.95},
  "mother_name_ar": {"value": "...", "confidence": 0.90},
  "full_name_ar": {"value": "first father grandfather surname", "confidence": 0.95},
  "national_id_number": {"value": "...", "confidence": 0.99},
  "civil_status_number": {"value": "...", "confidence": 0.95},
  "gender": {"value": "ذكر or أنثى", "confidence": 0.99},
  "blood_type": {"value": "AB+", "confidence": 0.95},
  "nationality": {"value": "عراقي", "confidence": 0.95},
  "raw_text": "all text"
}

For BACK, return:
{
  "doc_type": "national_id",
  "doc_side": {"value": "back", "confidence": 0.99},
  "date_of_birth": {"value": "YYYY-MM-DD", "confidence": 0.99},
  "place_of_birth": {"value": "...", "confidence": 0.95},
  "issue_date": {"value": "YYYY-MM-DD", "confidence": 0.99},
  "expiry_date": {"value": "YYYY-MM-DD", "confidence": 0.99},
  "issuing_authority": {"value": "...", "confidence": 0.95},
  "family_number": {"value": "...", "confidence": 0.90},
  "mrz_line_1": {"value": "...", "confidence": 0.95},
  "mrz_line_2": {"value": "...", "confidence": 0.95},
  "mrz_line_3": {"value": "...", "confidence": 0.95},
  "raw_text": "all text"
}

Rules:
- ONLY include fields that belong to the detected side — do NOT add null fields for the other side
- DATES: Convert to YYYY-MM-DD regardless of input format
- For front: full_name_ar = first_name + father_name + grandfather_name + surname
- FAMILY NUMBER: Should be all digits. Letters like L, O, I mixed in are likely misreads of 1, 0, 1.
- Read MRZ lines exactly as printed (preserve < characters)
- Do NOT extract English names from MRZ — the national ID has no official English name
- Include ALL text in raw_text`,

  passport: `You are an expert Arabic/English document OCR system. Analyze this passport image and extract ALL text and data.

Return ONLY valid JSON (no markdown, no explanation) in this exact format:
{
  "doc_type": "passport",
  "full_name_ar": {"value": "الاسم بالعربي", "confidence": 0.95},
  "full_name_en": {"value": "Name in English", "confidence": 0.90},
  "passport_number": {"value": "A12345678", "confidence": 0.99},
  "nationality": {"value": "IRAQ", "confidence": 0.95},
  "date_of_birth": {"value": "1990-01-15", "confidence": 0.85},
  "issue_date": {"value": "2020-01-01", "confidence": 0.80},
  "expiry_date": {"value": "2030-01-01", "confidence": 0.80},
  "raw_text": "all visible text from the document"
}

Rules:
- Dates must be in YYYY-MM-DD format
- Set confidence 0.0-1.0 based on legibility
- If a field is not visible, set value to null and confidence to 0
- Read MRZ (Machine Readable Zone) lines at the bottom if present
- Include ALL Arabic text with diacritics when present
- For the raw_text field, include every piece of text you can read from the document`,

  resident_id: `You are an expert Arabic OCR system specialized in reading HANDWRITTEN Arabic text on official Iraqi documents. This is a بطاقة سكن (Resident ID / Housing Card) issued by the Iraqi Ministry of Interior (وزارة الداخلية), General Directorate of Travel and Nationality (المديرية العامة للسفر والجنسية).

IMPORTANT: This document contains HANDWRITTEN Arabic text which is harder to read than printed text. Take extra care:
- Look for connected cursive Arabic script written by hand
- Arabic handwriting often has inconsistent letter shapes — use context to disambiguate
- Numbers may be in Arabic-Indic (٠١٢٣٤٥٦٧٨٩) or Western (0123456789) format
- Read from RIGHT to LEFT for Arabic text
- The form has labeled fields (printed) with handwritten values filled in

Known fields on this document:
- مكتب معلومات (Information Office) — which regional office
- اسم رب الاسرة (Head of Household Name) — full name handwritten
- عنوان السكن (Residential Address) — neighborhood, district, alley, house number
- رقم الاستمارة (Form Number) — registration number

Return ONLY valid JSON (no markdown, no explanation) in this exact format:
{
  "doc_type": "resident_id",
  "head_of_household_ar": {"value": "الاسم المكتوب بخط اليد", "confidence": 0.75},
  "head_of_household_en": {"value": "Transliterated name if possible", "confidence": 0.60},
  "information_office": {"value": "اسم مكتب المعلومات", "confidence": 0.80},
  "residential_address": {"value": "العنوان الكامل", "confidence": 0.70},
  "form_number": {"value": "12345", "confidence": 0.85},
  "district": {"value": "المنطقة", "confidence": 0.70},
  "neighborhood": {"value": "المحلة", "confidence": 0.70},
  "alley": {"value": "الزقاق", "confidence": 0.65},
  "house_number": {"value": "رقم الدار", "confidence": 0.70},
  "family_members": {"value": "عدد افراد الاسرة او اسماءهم", "confidence": 0.65},
  "issue_date": {"value": "2020-01-01", "confidence": 0.60},
  "raw_text": "every single piece of text readable from this document, both printed headers and handwritten content"
}

Rules:
- Confidence for handwritten fields should generally be LOWER (0.5-0.8) unless clearly legible
- Dates must be in YYYY-MM-DD format if identifiable, otherwise put the raw text
- If a field is not visible or truly unreadable, set value to null and confidence to 0
- For head_of_household_en, attempt a best-effort transliteration even if unsure
- Include ALL Arabic diacritics when visible in handwriting
- The raw_text field should contain EVERYTHING you can read — printed labels AND handwritten values
- Report Arabic-Indic numerals (٠-٩) as Western digits (0-9) in structured fields but preserve originals in raw_text`,

  business_license: `You are an expert Arabic/English document OCR system. Analyze this Iraqi business license / trade registration image and extract ALL text and data.

Return ONLY valid JSON (no markdown, no explanation) in this exact format:
{
  "doc_type": "business_license",
  "business_name_ar": {"value": "اسم الشركة بالعربي", "confidence": 0.95},
  "business_name_en": {"value": "Company Name", "confidence": 0.90},
  "registration_number": {"value": "12345", "confidence": 0.99},
  "business_type": {"value": "شركة ذات مسؤولية محدودة", "confidence": 0.85},
  "address": {"value": "بغداد، الكرادة", "confidence": 0.80},
  "issue_date": {"value": "2020-01-01", "confidence": 0.80},
  "expiry_date": {"value": "2025-01-01", "confidence": 0.80},
  "owner_names": {"value": "أحمد محمد, علي حسين", "confidence": 0.85},
  "raw_text": "all visible text from the document"
}

Rules:
- Dates must be in YYYY-MM-DD format
- Set confidence 0.0-1.0 based on legibility
- If a field is not visible, set value to null and confidence to 0
- owner_names should be comma-separated if multiple
- Include ALL Arabic text with diacritics when present
- For the raw_text field, include every piece of text you can read from the document`,
};

/**
 * Download a document from Supabase Storage using the storage path.
 * Returns the file bytes and content type.
 */
async function downloadDocument(
  supabaseUrl: string,
  serviceKey: string,
  bucket: string,
  storagePath: string,
): Promise<{ bytes: ArrayBuffer; contentType: string }> {
  const url = `${supabaseUrl}/storage/v1/object/${bucket}/${storagePath}`;
  const resp = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${serviceKey}`,
      'apikey': serviceKey,
    },
  });
  if (!resp.ok) {
    throw new Error(`Failed to download document (${resp.status}): ${await resp.text()}`);
  }
  const contentType = resp.headers.get('content-type') || 'application/octet-stream';
  const bytes = await resp.arrayBuffer();
  return { bytes, contentType };
}

/**
 * Send a document to Claude API for OCR extraction.
 */
export async function processDocument(
  anthropicApiKey: string,
  supabaseUrl: string,
  supabaseServiceKey: string,
  bucket: string,
  storagePath: string,
  docType: string,
  mimeType: string,
  docSide?: string,
): Promise<OcrResult> {
  const now = new Date().toISOString();
  // Choose the best prompt: side-specific if available, else generic
  const sideKey = docSide ? `${docType}_${docSide}` : null;
  const prompt = (sideKey && EXTRACTION_PROMPTS[sideKey]) || EXTRACTION_PROMPTS[docType];
  if (!prompt) {
    return {
      success: false,
      extraction: null,
      raw_text: null,
      error: `Unsupported document type for OCR: ${docType}`,
      model: 'claude-sonnet-4-20250514',
      processed_at: now,
    };
  }

  try {
    // Download the file from Supabase Storage
    const { bytes, contentType } = await downloadDocument(supabaseUrl, supabaseServiceKey, bucket, storagePath);
    // Convert to base64 in chunks to avoid stack overflow on large files
    const uint8 = new Uint8Array(bytes);
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < uint8.length; i += chunkSize) {
      binary += String.fromCharCode(...uint8.subarray(i, Math.min(i + chunkSize, uint8.length)));
    }
    const base64 = btoa(binary);

    // Determine media type for Claude
    const mediaType = mimeType === 'application/pdf' ? 'application/pdf' : contentType;

    // Build the content array for Claude
    const content: any[] = [];
    if (mimeType === 'application/pdf') {
      content.push({
        type: 'document',
        source: { type: 'base64', media_type: 'application/pdf', data: base64 },
      });
    } else {
      content.push({
        type: 'image',
        source: { type: 'base64', media_type: mediaType, data: base64 },
      });
    }
    content.push({ type: 'text', text: prompt });

    // Call Claude API
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': anthropicApiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2048,
        messages: [{ role: 'user', content }],
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return {
        success: false,
        extraction: null,
        raw_text: null,
        error: `Claude API error (${resp.status}): ${errText}`,
        model: 'claude-sonnet-4-20250514',
        processed_at: now,
      };
    }

    const data: any = await resp.json();
    const textBlock = data.content?.find((b: any) => b.type === 'text');
    if (!textBlock?.text) {
      return {
        success: false,
        extraction: null,
        raw_text: null,
        error: 'Claude returned no text content',
        model: 'claude-sonnet-4-20250514',
        processed_at: now,
      };
    }

    // Parse the JSON response — strip any accidental markdown fences
    let jsonStr = textBlock.text.trim();
    if (jsonStr.startsWith('```')) {
      jsonStr = jsonStr.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '');
    }

    const parsed = JSON.parse(jsonStr);
    const rawText = parsed.raw_text || null;
    delete parsed.raw_text;

    return {
      success: true,
      extraction: parsed as DocumentExtraction,
      raw_text: rawText,
      model: 'claude-sonnet-4-20250514',
      processed_at: now,
    };
  } catch (err: any) {
    return {
      success: false,
      extraction: null,
      raw_text: null,
      error: err.message || 'Unknown OCR error',
      model: 'claude-sonnet-4-20250514',
      processed_at: now,
    };
  }
}

/**
 * Normalize Arabic text for comparison — strip diacritics, normalize forms.
 */
function normalizeForCompare(text: string): string {
  return text
    .normalize('NFKD')
    .replace(/[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]/g, '') // strip diacritics
    .replace(/[ أإآ]/g, 'ا') // normalize alef
    .replace(/ة/g, 'ه')     // taa marbuta → ha
    .replace(/ى/g, 'ي')     // alef maqsura → ya
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Compare two strings loosely for Arabic/English names.
 * Returns true if they are a reasonable match.
 */
function namesMatch(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  const na = normalizeForCompare(a);
  const nb = normalizeForCompare(b);
  if (na === nb) return true;
  // Check if one contains the other (partial match for Arabic names with patronymics)
  if (na.includes(nb) || nb.includes(na)) return true;
  // Check word overlap — at least 2 common words
  const wa = new Set(na.split(' '));
  const wb = new Set(nb.split(' '));
  let overlap = 0;
  for (const w of wa) { if (wb.has(w)) overlap++; }
  return overlap >= 2;
}

/**
 * Cross-reference extracted OCR data with merchant/owner submitted data.
 * Returns a validation report with any discrepancies found.
 */
export function validateExtraction(
  extraction: DocumentExtraction,
  ownerData: {
    full_name_ar?: string | null;
    full_name_en?: string | null;
    date_of_birth?: string | null;
    national_id?: string | null;
    passport_number?: string | null;
    nationality?: string | null;
  },
  merchantData?: {
    legal_name_ar?: string | null;
    legal_name_en?: string | null;
    registration_number?: string | null;
    business_type?: string | null;
  },
): ValidationReport {
  const issues: ValidationIssue[] = [];
  const now = new Date().toISOString();

  if (extraction.doc_type === 'national_id') {
    const ext = extraction as NationalIdExtraction;
    // Name check (front side only — back side won't have this field)
    if (ext.full_name_ar && ext.full_name_ar.value && ownerData.full_name_ar) {
      if (!namesMatch(ext.full_name_ar.value, ownerData.full_name_ar)) {
        issues.push({
          field: 'full_name_ar',
          expected: ownerData.full_name_ar,
          extracted: ext.full_name_ar.value,
          severity: 'critical',
          message: 'Arabic name on ID does not match submitted name',
        });
      }
    }
    // English name check — only if extracted (e.g. from passport, not from national_id MRZ)
    if (ext.full_name_en && ext.full_name_en.value && ownerData.full_name_en) {
      // Skip EN name validation for national_id — the card has no official English name
      // MRZ transliteration is non-standard and should not be compared
    }
    // National ID number (front side only)
    if (ext.national_id_number && ext.national_id_number.value && ownerData.national_id) {
      if (ext.national_id_number.value.replace(/\s/g, '') !== ownerData.national_id.replace(/\s/g, '')) {
        issues.push({
          field: 'national_id_number',
          expected: ownerData.national_id,
          extracted: ext.national_id_number.value,
          severity: 'critical',
          message: 'National ID number on document does not match submitted ID',
        });
      }
    }
    // Date of birth (back side only)
    if (ext.date_of_birth && ext.date_of_birth.value && ownerData.date_of_birth) {
      const extDob = ext.date_of_birth.value.substring(0, 10);
      const ownerDob = ownerData.date_of_birth.substring(0, 10);
      if (extDob !== ownerDob) {
        issues.push({
          field: 'date_of_birth',
          expected: ownerDob,
          extracted: extDob,
          severity: 'high',
          message: 'Date of birth on ID does not match submitted DOB',
        });
      }
    }
    // Expiry check (back side only)
    if (ext.expiry_date && ext.expiry_date.value) {
      const expiry = new Date(ext.expiry_date.value);
      if (expiry < new Date()) {
        issues.push({
          field: 'expiry_date',
          expected: 'valid (not expired)',
          extracted: ext.expiry_date.value,
          severity: 'critical',
          message: 'National ID card has expired',
        });
      }
    }
  }

  if (extraction.doc_type === 'passport') {
    const ext = extraction as PassportExtraction;
    if (ext.full_name_ar.value && ownerData.full_name_ar) {
      if (!namesMatch(ext.full_name_ar.value, ownerData.full_name_ar)) {
        issues.push({
          field: 'full_name_ar',
          expected: ownerData.full_name_ar,
          extracted: ext.full_name_ar.value,
          severity: 'critical',
          message: 'Arabic name on passport does not match submitted name',
        });
      }
    }
    if (ext.full_name_en.value && ownerData.full_name_en) {
      if (!namesMatch(ext.full_name_en.value, ownerData.full_name_en)) {
        issues.push({
          field: 'full_name_en',
          expected: ownerData.full_name_en,
          extracted: ext.full_name_en.value,
          severity: 'high',
          message: 'English name on passport does not match submitted name',
        });
      }
    }
    if (ext.passport_number.value && ownerData.passport_number) {
      if (ext.passport_number.value.replace(/\s/g, '') !== ownerData.passport_number.replace(/\s/g, '')) {
        issues.push({
          field: 'passport_number',
          expected: ownerData.passport_number,
          extracted: ext.passport_number.value,
          severity: 'critical',
          message: 'Passport number on document does not match submitted number',
        });
      }
    }
    if (ext.date_of_birth.value && ownerData.date_of_birth) {
      const extDob = ext.date_of_birth.value.substring(0, 10);
      const ownerDob = ownerData.date_of_birth.substring(0, 10);
      if (extDob !== ownerDob) {
        issues.push({
          field: 'date_of_birth',
          expected: ownerDob,
          extracted: extDob,
          severity: 'high',
          message: 'Date of birth on passport does not match submitted DOB',
        });
      }
    }
    if (ext.expiry_date.value) {
      const expiry = new Date(ext.expiry_date.value);
      if (expiry < new Date()) {
        issues.push({
          field: 'expiry_date',
          expected: 'valid (not expired)',
          extracted: ext.expiry_date.value,
          severity: 'critical',
          message: 'Passport has expired',
        });
      }
    }
  }

  if (extraction.doc_type === 'resident_id') {
    const ext = extraction as ResidentIdExtraction;
    // Name check — match head of household against owner name
    if (ext.head_of_household_ar.value && ownerData.full_name_ar) {
      if (!namesMatch(ext.head_of_household_ar.value, ownerData.full_name_ar)) {
        issues.push({
          field: 'head_of_household_ar',
          expected: ownerData.full_name_ar,
          extracted: ext.head_of_household_ar.value,
          severity: ext.head_of_household_ar.confidence < 0.6 ? 'medium' : 'critical',
          message: ext.head_of_household_ar.confidence < 0.6
            ? 'Handwritten name on resident ID may not match (low OCR confidence) — manual review recommended'
            : 'Head of household name on resident ID does not match submitted name',
        });
      }
    }
    if (ext.head_of_household_en.value && ownerData.full_name_en) {
      if (!namesMatch(ext.head_of_household_en.value, ownerData.full_name_en)) {
        issues.push({
          field: 'head_of_household_en',
          expected: ownerData.full_name_en,
          extracted: ext.head_of_household_en.value,
          severity: 'medium',
          message: 'Transliterated name on resident ID does not match submitted English name (handwritten — verify manually)',
        });
      }
    }
  }

  if (extraction.doc_type === 'business_license') {
    const ext = extraction as BusinessLicenseExtraction;
    if (ext.business_name_ar.value && merchantData?.legal_name_ar) {
      if (!namesMatch(ext.business_name_ar.value, merchantData.legal_name_ar)) {
        issues.push({
          field: 'business_name_ar',
          expected: merchantData.legal_name_ar,
          extracted: ext.business_name_ar.value,
          severity: 'critical',
          message: 'Arabic business name on license does not match submitted name',
        });
      }
    }
    if (ext.business_name_en.value && merchantData?.legal_name_en) {
      if (!namesMatch(ext.business_name_en.value, merchantData.legal_name_en)) {
        issues.push({
          field: 'business_name_en',
          expected: merchantData.legal_name_en,
          extracted: ext.business_name_en.value,
          severity: 'high',
          message: 'English business name on license does not match submitted name',
        });
      }
    }
    if (ext.registration_number.value && merchantData?.registration_number) {
      if (ext.registration_number.value.replace(/\s/g, '') !== merchantData.registration_number.replace(/\s/g, '')) {
        issues.push({
          field: 'registration_number',
          expected: merchantData.registration_number,
          extracted: ext.registration_number.value,
          severity: 'critical',
          message: 'Registration number on license does not match submitted number',
        });
      }
    }
    if (ext.expiry_date.value) {
      const expiry = new Date(ext.expiry_date.value);
      if (expiry < new Date()) {
        issues.push({
          field: 'expiry_date',
          expected: 'valid (not expired)',
          extracted: ext.expiry_date.value,
          severity: 'critical',
          message: 'Business license has expired',
        });
      }
    }
  }

  return {
    is_valid: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
    issues,
    checked_at: now,
  };
}
