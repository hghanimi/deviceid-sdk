import { Hono } from 'hono';
import { AppEnv } from '../types';
import { getPool } from '../db';
import { processDocument, validateExtraction } from '../ocr';

const router = new Hono<AppEnv>();

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'application/pdf']);
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_DOC_TYPES = new Set(['national_id', 'passport', 'business_license', 'trade_license', 'ubo_declaration', 'resident_id', 'other']);

function extFromMime(mime: string): string {
  switch (mime) {
    case 'image/jpeg': return 'jpg';
    case 'image/png': return 'png';
    case 'application/pdf': return 'pdf';
    default: return 'bin';
  }
}

async function supabaseUpload(
  supabaseUrl: string,
  serviceKey: string,
  bucket: string,
  path: string,
  fileBytes: ArrayBuffer,
  contentType: string,
): Promise<{ data?: any; error?: string }> {
  const url = `${supabaseUrl}/storage/v1/object/${bucket}/${path}`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${serviceKey}`,
      'apikey': serviceKey,
      'Content-Type': contentType,
      'x-upsert': 'true',
    },
    body: fileBytes,
  });
  if (!resp.ok) {
    const text = await resp.text();
    return { error: `Storage upload failed (${resp.status}): ${text}` };
  }
  return { data: await resp.json() };
}

async function supabaseSignedUrl(
  supabaseUrl: string,
  serviceKey: string,
  bucket: string,
  path: string,
  expiresIn = 3600,
): Promise<string | null> {
  const url = `${supabaseUrl}/storage/v1/object/sign/${bucket}/${path}`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${serviceKey}`,
      'apikey': serviceKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ expiresIn }),
  });
  if (!resp.ok) return null;
  const data: any = await resp.json();
  return data.signedURL ? `${supabaseUrl}/storage/v1${data.signedURL}` : null;
}

// POST /v1/merchants/:id/documents — Upload a KYC document
router.post('/v1/merchants/:id/documents', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const mResult = await db.query(
      `SELECT id FROM merchants WHERE id = $1 AND api_key_id = $2`,
      [merchantId, apiKey.id],
    );
    if (mResult.rows.length === 0) return c.json({ error: 'Merchant not found' }, 404);

    const formData = await c.req.formData();
    const file = formData.get('file');
    const docType = ((formData.get('docType') || formData.get('doc_type')) as string || '').trim();
    const ownerId = ((formData.get('ownerId') || formData.get('owner_id')) as string || '').trim() || null;
    const docSide = ((formData.get('docSide') || formData.get('doc_side')) as string || 'front').trim();
    if (!['front', 'back'].includes(docSide)) {
      return c.json({ error: 'docSide must be "front" or "back"' }, 400);
    }
    if (!file || !(file instanceof File)) {
      return c.json({ error: 'Missing file field' }, 400);
    }
    if (!docType || !ALLOWED_DOC_TYPES.has(docType)) {
      return c.json({ error: `Invalid docType. Allowed: ${[...ALLOWED_DOC_TYPES].join(', ')}` }, 400);
    }

    const mime = file.type;
    if (!ALLOWED_MIME.has(mime)) {
      return c.json({ error: `File type not allowed: ${mime}. Allowed: image/jpeg, image/png, application/pdf` }, 400);
    }

    const bytes = await file.arrayBuffer();
    if (bytes.byteLength > MAX_FILE_SIZE) {
      return c.json({ error: `File too large (${Math.round(bytes.byteLength / 1024 / 1024)}MB). Max: 10MB` }, 400);
    }

    if (ownerId) {
      const ownerCheck = await db.query(
        `SELECT id FROM merchant_owners WHERE id = $1 AND merchant_id = $2`,
        [ownerId, merchantId],
      );
      if (ownerCheck.rows.length === 0) return c.json({ error: 'Owner not found for this merchant' }, 400);
    }

    const ext = extFromMime(mime);
    const ts = Date.now();
    const storagePath = `${apiKey.id}/${merchantId}/${docType}_${docSide}_${ts}.${ext}`;

    const uploadResult = await supabaseUpload(
      c.env.SUPABASE_URL,
      c.env.SUPABASE_SERVICE_KEY,
      'kyc-documents',
      storagePath,
      bytes,
      mime,
    );
    if (uploadResult.error) {
      console.error('Supabase upload error:', uploadResult.error);
      return c.json({ error: 'File upload failed', details: uploadResult.error }, 500);
    }

    const signedUrl = await supabaseSignedUrl(
      c.env.SUPABASE_URL,
      c.env.SUPABASE_SERVICE_KEY,
      'kyc-documents',
      storagePath,
    );

    const docResult = await db.query(
      `INSERT INTO merchant_documents (merchant_id, owner_id, doc_type, doc_side, file_name, file_url, storage_path, file_size, mime_type, status, verification_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'uploaded', 'pending')
       RETURNING *`,
      [merchantId, ownerId, docType, docSide, file.name || `${docType}_${ts}.${ext}`, signedUrl, storagePath, bytes.byteLength, mime],
    );
    const doc = docResult.rows[0];

    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'document_uploaded', $2, $3::jsonb, $4)`,
      [merchantId, apiKey.public_key, JSON.stringify({
        documentId: doc.id, docType, fileName: doc.file_name,
        fileSize: bytes.byteLength, mimeType: mime, ownerId,
      }), clientIp],
    );

    if (c.env.ANTHROPIC_API_KEY && ['national_id', 'passport', 'business_license', 'resident_id'].includes(docType)) {
      c.executionCtx.waitUntil((async () => {
        const bgDb = getPool(c.env.DATABASE_URL);
        try {
          await bgDb.query(
            `UPDATE merchant_documents SET ocr_status = 'processing' WHERE id = $1`,
            [doc.id],
          );
          const ocrResult = await processDocument(
            c.env.ANTHROPIC_API_KEY!,
            c.env.SUPABASE_URL,
            c.env.SUPABASE_SERVICE_KEY,
            'kyc-documents',
            storagePath,
            docType,
            mime,
            docSide,
          );
          await bgDb.query(
            `UPDATE merchant_documents SET ocr_result = $1::jsonb, ocr_status = $2 WHERE id = $3`,
            [JSON.stringify(ocrResult), ocrResult.success ? 'completed' : 'failed', doc.id],
          );
          if (ocrResult.success && ocrResult.extraction) {
            let ownerData: any = {};
            let merchantDataForValidation: any = {};
            if (ownerId) {
              const ownerQ = await bgDb.query(
                `SELECT full_name_ar, full_name_en, date_of_birth, national_id, passport_number, nationality FROM merchant_owners WHERE id = $1`,
                [ownerId],
              );
              if (ownerQ.rows.length > 0) ownerData = ownerQ.rows[0];
            }
            const merchQ = await bgDb.query(
              `SELECT legal_name_ar, legal_name_en, registration_number, business_type FROM merchants WHERE id = $1`,
              [merchantId],
            );
            if (merchQ.rows.length > 0) merchantDataForValidation = merchQ.rows[0];
            const report = validateExtraction(ocrResult.extraction, ownerData, merchantDataForValidation);
            await bgDb.query(
              `UPDATE merchant_documents SET validation_report = $1::jsonb WHERE id = $2`,
              [JSON.stringify(report), doc.id],
            );
            const severeIssues = report.issues.filter(i => i.severity === 'critical' || i.severity === 'high');
            for (const issue of severeIssues) {
              await bgDb.query(
                `INSERT INTO merchant_alerts (merchant_id, owner_id, alert_type, severity, details, status)
                 VALUES ($1, $2, 'ocr_discrepancy', $3, $4::jsonb, 'open')`,
                [merchantId, ownerId, issue.severity, JSON.stringify({
                  documentId: doc.id, docType, field: issue.field,
                  expected: issue.expected, extracted: issue.extracted, message: issue.message,
                })],
              );
            }
            await bgDb.query(
              `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
               VALUES ($1, 'ocr_completed', $2, $3::jsonb, $4)`,
              [merchantId, 'system', JSON.stringify({
                documentId: doc.id, docType, ocrSuccess: true,
                validationValid: report.is_valid, issuesCount: report.issues.length,
                alertsCreated: severeIssues.length,
              }), clientIp],
            );
          }
        } catch (ocrErr: any) {
          console.error('Background OCR error:', ocrErr);
          try {
            await bgDb.query(
              `UPDATE merchant_documents SET ocr_status = 'failed', ocr_result = $1::jsonb WHERE id = $2`,
              [JSON.stringify({ success: false, error: ocrErr.message, processed_at: new Date().toISOString() }), doc.id],
            );
          } catch (_) { /* best effort */ }
        }
      })());
    }

    return c.json({ document: { ...doc, signedUrl } }, 201);
  } catch (err: any) {
    console.error('Document upload error:', err);
    return c.json({ error: 'Failed to upload document', details: err.message }, 500);
  }
});

// GET /v1/merchants/:id/documents — List documents with signed URLs
router.get('/v1/merchants/:id/documents', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');

  try {
    const mResult = await db.query(
      `SELECT id FROM merchants WHERE id = $1 AND api_key_id = $2`,
      [merchantId, apiKey.id],
    );
    if (mResult.rows.length === 0) return c.json({ error: 'Merchant not found' }, 404);

    const docsResult = await db.query(
      `SELECT * FROM merchant_documents WHERE merchant_id = $1 ORDER BY created_at DESC`,
      [merchantId],
    );

    const documents = await Promise.all(
      docsResult.rows.map(async (doc: any) => {
        let signedUrl: string | null = null;
        if (doc.storage_path) {
          signedUrl = await supabaseSignedUrl(
            c.env.SUPABASE_URL,
            c.env.SUPABASE_SERVICE_KEY,
            'kyc-documents',
            doc.storage_path,
          );
        }
        return { ...doc, signedUrl };
      }),
    );

    return c.json({ documents, total: documents.length });
  } catch (err: any) {
    console.error('List documents error:', err);
    return c.json({ error: 'Failed to list documents', details: err.message }, 500);
  }
});

// PATCH /v1/documents/:id/verify — Verify or reject a document
router.patch('/v1/documents/:id/verify', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const docId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const body = await c.req.json() as any;
    const { status, reason } = body;
    if (!status || !['verified', 'rejected'].includes(status)) {
      return c.json({ error: 'status must be "verified" or "rejected"' }, 400);
    }

    const docResult = await db.query(
      `SELECT d.*, m.api_key_id FROM merchant_documents d
       JOIN merchants m ON m.id = d.merchant_id
       WHERE d.id = $1`,
      [docId],
    );
    if (docResult.rows.length === 0) return c.json({ error: 'Document not found' }, 404);
    const doc = docResult.rows[0];
    if (doc.api_key_id !== apiKey.id) return c.json({ error: 'Document not found' }, 404);

    const updateResult = await db.query(
      `UPDATE merchant_documents
       SET verification_status = $1, verified_by = $2, verified_at = NOW(), status = $1
       WHERE id = $3
       RETURNING *`,
      [status, apiKey.public_key, docId],
    );

    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'document_verified', $2, $3::jsonb, $4)`,
      [doc.merchant_id, apiKey.public_key, JSON.stringify({
        documentId: docId, docType: doc.doc_type,
        verificationStatus: status, reason: reason || null,
      }), clientIp],
    );

    return c.json({ document: updateResult.rows[0] });
  } catch (err: any) {
    console.error('Document verify error:', err);
    return c.json({ error: 'Failed to verify document', details: err.message }, 500);
  }
});

// POST /v1/documents/:id/ocr — Retry OCR on a document
router.post('/v1/documents/:id/ocr', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const docId = c.req.param('id');

  try {
    if (!c.env.ANTHROPIC_API_KEY) {
      return c.json({ error: 'ANTHROPIC_API_KEY not configured' }, 500);
    }

    const docResult = await db.query(
      `SELECT d.*, m.api_key_id FROM merchant_documents d
       JOIN merchants m ON m.id = d.merchant_id
       WHERE d.id = $1`,
      [docId],
    );
    if (docResult.rows.length === 0) return c.json({ error: 'Document not found' }, 404);
    const doc = docResult.rows[0];
    if (doc.api_key_id !== apiKey.id) return c.json({ error: 'Document not found' }, 404);

    if (!doc.storage_path) {
      return c.json({ error: 'Document has no storage path (empty file?)' }, 400);
    }
    if (!['national_id', 'passport', 'business_license', 'resident_id'].includes(doc.doc_type)) {
      return c.json({ error: `OCR not supported for doc type: ${doc.doc_type}` }, 400);
    }

    await db.query(`UPDATE merchant_documents SET ocr_status = 'processing' WHERE id = $1`, [docId]);

    c.executionCtx.waitUntil((async () => {
      const bgDb = getPool(c.env.DATABASE_URL);
      try {
        const ocrResult = await processDocument(
          c.env.ANTHROPIC_API_KEY!,
          c.env.SUPABASE_URL,
          c.env.SUPABASE_SERVICE_KEY,
          'kyc-documents',
          doc.storage_path,
          doc.doc_type,
          doc.mime_type || 'image/jpeg',
          doc.doc_side || undefined,
        );
        await bgDb.query(
          `UPDATE merchant_documents SET ocr_result = $1::jsonb, ocr_status = $2 WHERE id = $3`,
          [JSON.stringify(ocrResult), ocrResult.success ? 'completed' : 'failed', docId],
        );
        if (ocrResult.success && ocrResult.extraction) {
          let ownerData: any = {};
          let merchantDataForValidation: any = {};
          if (doc.owner_id) {
            const ownerQ = await bgDb.query(
              `SELECT full_name_ar, full_name_en, date_of_birth, national_id, passport_number, nationality FROM merchant_owners WHERE id = $1`,
              [doc.owner_id],
            );
            if (ownerQ.rows.length > 0) ownerData = ownerQ.rows[0];
          }
          const merchQ = await bgDb.query(
            `SELECT legal_name_ar, legal_name_en, registration_number, business_type FROM merchants WHERE id = $1`,
            [doc.merchant_id],
          );
          if (merchQ.rows.length > 0) merchantDataForValidation = merchQ.rows[0];
          const report = validateExtraction(ocrResult.extraction, ownerData, merchantDataForValidation);
          await bgDb.query(
            `UPDATE merchant_documents SET validation_report = $1::jsonb WHERE id = $2`,
            [JSON.stringify(report), docId],
          );
        }
      } catch (e) {
        console.error('OCR retry error:', e);
        await bgDb.query(
          `UPDATE merchant_documents SET ocr_status = 'failed', ocr_result = $1::jsonb WHERE id = $2`,
          [JSON.stringify({ error: (e as any).message, success: false, model: 'claude-sonnet-4-20250514', processed_at: new Date().toISOString() }), docId],
        ).catch(() => {});
      }
    })());

    return c.json({ message: 'OCR processing started', ocr_status: 'processing' });
  } catch (err: any) {
    console.error('OCR retry error:', err);
    return c.json({ error: 'Failed to start OCR', details: err.message }, 500);
  }
});

export default router;
