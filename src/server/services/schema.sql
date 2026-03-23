-- DeviceID SDK — Database Schema
-- PostgreSQL 14+

-- API keys for customers
CREATE TABLE api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key    VARCHAR(64) NOT NULL UNIQUE,
  secret_key    VARCHAR(64) NOT NULL UNIQUE,
  customer_id   UUID NOT NULL,
  name          VARCHAR(255),
  is_active     BOOLEAN DEFAULT TRUE,
  rate_limit    INTEGER DEFAULT 1000,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Core fingerprint storage
CREATE TABLE fingerprints (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id    VARCHAR(32) NOT NULL,
  raw_hash      VARCHAR(128) NOT NULL,

  -- Individual signal hashes for fuzzy matching
  canvas_hash   VARCHAR(64),
  webgl_hash    VARCHAR(64),
  audio_hash    VARCHAR(64),
  screen_hash   VARCHAR(64),
  font_hash     VARCHAR(64),
  browser_hash  VARCHAR(64),
  hardware_hash VARCHAR(64),

  -- Metadata
  ip_address    INET,
  country       VARCHAR(2),
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  visit_count   INTEGER DEFAULT 1,

  -- Risk data
  is_vpn        BOOLEAN DEFAULT FALSE,
  is_incognito  BOOLEAN DEFAULT FALSE,
  headless_score INTEGER DEFAULT 0,
  bot_score     INTEGER DEFAULT 0,

  -- Customer context
  api_key_id    UUID NOT NULL REFERENCES api_keys(id),

  CONSTRAINT unique_raw_hash_per_customer UNIQUE(raw_hash, api_key_id)
);

CREATE INDEX idx_fp_visitor    ON fingerprints(visitor_id);
CREATE INDEX idx_fp_canvas     ON fingerprints(canvas_hash);
CREATE INDEX idx_fp_webgl      ON fingerprints(webgl_hash);
CREATE INDEX idx_fp_audio      ON fingerprints(audio_hash);
CREATE INDEX idx_fp_screen     ON fingerprints(screen_hash);
CREATE INDEX idx_fp_hardware   ON fingerprints(hardware_hash);
CREATE INDEX idx_fp_api_key    ON fingerprints(api_key_id);

-- Identity graph: links multiple fingerprints to same person
CREATE TABLE device_links (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id_a  VARCHAR(32) NOT NULL,
  visitor_id_b  VARCHAR(32) NOT NULL,
  link_type     VARCHAR(20) NOT NULL,
  confidence    DECIMAL(3,2) NOT NULL,
  evidence      JSONB NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  api_key_id    UUID NOT NULL REFERENCES api_keys(id),

  CONSTRAINT unique_link UNIQUE(visitor_id_a, visitor_id_b, api_key_id)
);

CREATE INDEX idx_links_a ON device_links(visitor_id_a, api_key_id);
CREATE INDEX idx_links_b ON device_links(visitor_id_b, api_key_id);

-- Webhook configurations
CREATE TABLE webhooks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key_id    UUID NOT NULL REFERENCES api_keys(id),
  url           VARCHAR(512) NOT NULL,
  events        TEXT[] NOT NULL,
  secret        VARCHAR(128) NOT NULL,
  is_active     BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log
CREATE TABLE events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id    VARCHAR(32),
  event_type    VARCHAR(50) NOT NULL,
  event_data    JSONB,
  ip_address    INET,
  api_key_id    UUID NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_events_visitor ON events(visitor_id, created_at DESC);
CREATE INDEX idx_events_type    ON events(event_type, created_at DESC);
CREATE INDEX idx_events_api_key ON events(api_key_id, created_at DESC);