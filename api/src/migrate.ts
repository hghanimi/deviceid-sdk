/**
 * One-time migration script for Athar database.
 * Run manually: npx tsx api/src/migrate.ts
 * Or via: npm run migrate (from api/)
 * Requires DATABASE_URL environment variable.
 */
import { Client } from 'pg';

async function migrate() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('DATABASE_URL environment variable is required');
    process.exit(1);
  }

  const client = new Client({ connectionString });
  await client.connect();
  console.log('Connected to database');

  // 1. Fingerprints — add device-level hash columns
  try {
    await client.query(`
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS device_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS screen_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS gpu_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS hw_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS fonts_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS person_id VARCHAR(32);
    `);
    console.log('✓ fingerprints hash columns');
  } catch (e: any) { console.warn('⚠ fingerprints hash columns:', e.message); }

  // 2. Person resolution tables
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS persons (
        person_id VARCHAR(32) PRIMARY KEY,
        api_key_id UUID NOT NULL REFERENCES api_keys(id),
        external_user_id TEXT,
        device_count INT DEFAULT 1,
        first_seen TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB DEFAULT '{}'::jsonb
      );
      CREATE TABLE IF NOT EXISTS person_devices (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        person_id VARCHAR(32) NOT NULL REFERENCES persons(person_id),
        visitor_id VARCHAR(32) NOT NULL,
        link_type VARCHAR(20) NOT NULL,
        confidence DECIMAL(3,2) NOT NULL,
        ip_at_link TEXT,
        linked_at TIMESTAMPTZ DEFAULT NOW(),
        api_key_id UUID NOT NULL REFERENCES api_keys(id)
      );
      CREATE INDEX IF NOT EXISTS idx_persons_external_uid ON persons(external_user_id, api_key_id);
      CREATE INDEX IF NOT EXISTS idx_person_devices_visitor ON person_devices(visitor_id, api_key_id);
      CREATE INDEX IF NOT EXISTS idx_person_devices_person ON person_devices(person_id);
      CREATE INDEX IF NOT EXISTS idx_fingerprints_person ON fingerprints(person_id);
      CREATE INDEX IF NOT EXISTS idx_fingerprints_ip_recent ON fingerprints(ip_address, api_key_id, last_seen DESC);
    `);
    console.log('✓ persons + person_devices tables');
  } catch (e: any) { console.warn('⚠ persons tables:', e.message); }

  // 3. Merchant KYC / compliance tables
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS merchants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        api_key_id UUID NOT NULL REFERENCES api_keys(id),
        legal_name_ar TEXT NOT NULL,
        legal_name_en TEXT,
        trade_name TEXT,
        registration_number TEXT,
        tax_id TEXT,
        business_type TEXT,
        industry_code TEXT,
        address TEXT,
        city TEXT,
        governorate TEXT,
        phone TEXT,
        email TEXT,
        kyc_status TEXT NOT NULL DEFAULT 'pending',
        screening_status TEXT NOT NULL DEFAULT 'pending',
        risk_rating TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS merchant_owners (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        full_name_ar TEXT NOT NULL,
        full_name_en TEXT,
        father_name_ar TEXT,
        grandfather_name_ar TEXT,
        family_name_ar TEXT,
        date_of_birth DATE,
        nationality TEXT,
        national_id TEXT,
        passport_number TEXT,
        ownership_pct DECIMAL(5,2),
        role TEXT,
        is_ubo BOOLEAN DEFAULT false,
        screening_status TEXT NOT NULL DEFAULT 'pending',
        screening_result JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS compliance_audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID REFERENCES merchants(id),
        action TEXT NOT NULL,
        actor TEXT,
        details JSONB DEFAULT '{}'::jsonb,
        ip_address TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS merchant_documents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        owner_id UUID REFERENCES merchant_owners(id) ON DELETE CASCADE,
        doc_type TEXT NOT NULL,
        file_name TEXT,
        file_url TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS merchant_alerts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        owner_id UUID REFERENCES merchant_owners(id) ON DELETE CASCADE,
        alert_type TEXT NOT NULL,
        severity TEXT DEFAULT 'medium',
        details JSONB DEFAULT '{}'::jsonb,
        resolved BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS screening_results (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
        owner_id UUID REFERENCES merchant_owners(id) ON DELETE CASCADE,
        entity_name TEXT NOT NULL,
        matched_name TEXT,
        match_score DECIMAL(7,4),
        list_source TEXT,
        entity_id TEXT,
        programs TEXT[],
        details JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_merchants_api_key ON merchants(api_key_id);
      CREATE INDEX IF NOT EXISTS idx_merchants_kyc ON merchants(kyc_status);
      CREATE INDEX IF NOT EXISTS idx_merchant_owners_merchant ON merchant_owners(merchant_id);
      CREATE INDEX IF NOT EXISTS idx_compliance_log_merchant ON compliance_audit_log(merchant_id);
      CREATE INDEX IF NOT EXISTS idx_merchant_alerts_merchant ON merchant_alerts(merchant_id);
      CREATE INDEX IF NOT EXISTS idx_screening_results_merchant ON screening_results(merchant_id);
      CREATE INDEX IF NOT EXISTS idx_screening_results_owner ON screening_results(owner_id);
    `);
    console.log('✓ merchant KYC tables + indexes');
  } catch (e: any) { console.warn('⚠ merchant KYC tables:', e.message); }

  // 3b. Fix programs column type if it was created as TEXT instead of TEXT[]
  try {
    const colType = await client.query(`
      SELECT data_type FROM information_schema.columns
      WHERE table_name = 'screening_results' AND column_name = 'programs'
    `);
    if (colType.rows.length > 0 && colType.rows[0].data_type !== 'ARRAY') {
      await client.query(`
        ALTER TABLE screening_results
        ALTER COLUMN programs TYPE text[]
        USING CASE
          WHEN programs IS NULL THEN NULL
          WHEN programs = '' THEN '{}'::text[]
          ELSE string_to_array(trim(both '[]"' from programs), ',')
        END
      `);
      console.log('✓ programs column converted to text[]');
    } else {
      console.log('✓ programs column already text[]');
    }
  } catch (e: any) { console.warn('⚠ programs column fix:', e.message); }

  // 4. Schema evolution — add columns
  try {
    await client.query(`
      ALTER TABLE merchants ADD COLUMN IF NOT EXISTS last_screened_at TIMESTAMPTZ;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS last_screened_at TIMESTAMPTZ;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS pep_status TEXT NOT NULL DEFAULT 'pending';
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'pending';
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS verified_by TEXT;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS file_size INTEGER;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS mime_type TEXT;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS storage_path TEXT;
      ALTER TABLE merchant_alerts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
      ALTER TABLE merchant_alerts ADD COLUMN IF NOT EXISTS resolution_notes TEXT;
      ALTER TABLE merchant_alerts ADD COLUMN IF NOT EXISTS resolved_by TEXT;
      ALTER TABLE merchant_alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS ocr_result JSONB;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS ocr_status TEXT NOT NULL DEFAULT 'pending';
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS validation_report JSONB;
      ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS doc_side TEXT NOT NULL DEFAULT 'front';
    `);
    console.log('✓ schema evolution columns');
  } catch (e: any) { console.warn('⚠ schema evolution:', e.message); }

  // 5. CBI KYC extended fields on merchant_owners
  try {
    await client.query(`
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS mother_name_ar TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS place_of_birth TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS gender TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS secondary_nationality TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS marital_status TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS education_level TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS national_id_issue_date DATE;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS national_id_expiry DATE;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS national_id_issuing_office TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS civil_status_number TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS passport_issue_date DATE;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS passport_expiry DATE;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS full_name_en TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS blood_type TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS family_number TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS residency_card_number TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS governorate TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS district TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS neighborhood TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS street_address TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS phone TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS occupation TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS employer_name TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS monthly_income TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS income_currency TEXT DEFAULT 'IQD';
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS expected_monthly_volume TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS source_of_funds TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS purpose_of_account TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS is_pep_self BOOLEAN DEFAULT false;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS is_pep_family BOOLEAN DEFAULT false;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS pep_details TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS is_beneficial_owner BOOLEAN DEFAULT true;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS ubo_details TEXT;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS kyc_completed BOOLEAN DEFAULT false;
      ALTER TABLE merchant_owners ADD COLUMN IF NOT EXISTS kyc_completed_at TIMESTAMPTZ;
    `);
    console.log('✓ CBI KYC extended fields');
  } catch (e: any) { console.warn('⚠ CBI KYC fields:', e.message); }

  // 6. Users table for login system
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        api_key_id UUID NOT NULL REFERENCES api_keys(id),
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        role TEXT NOT NULL DEFAULT 'operator',
        is_active BOOLEAN DEFAULT true,
        last_login TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key_id);
    `);
    console.log('✓ users table');
  } catch (e: any) { console.warn('⚠ users table:', e.message); }

  // 7. Add is_operator flag to api_keys
  try {
    await client.query(`
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_operator BOOLEAN DEFAULT false;
      UPDATE api_keys SET is_operator = true WHERE public_key LIKE 'pk_live_athar%' AND is_operator = false;
    `);
    console.log('✓ api_keys is_operator column');
  } catch (e: any) { console.warn('⚠ api_keys is_operator:', e.message); }

  await client.end();
  console.log('\nMigration complete');
}

migrate().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
