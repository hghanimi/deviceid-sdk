# DeviceID SDK - Local Development Setup

## Prerequisites

Choose one of the following setups:

### Option A: PostgreSQL locally (Windows)

1. Download PostgreSQL 15+ from https://www.postgresql.org/download/windows/
2. Run the installer and note the password for the `postgres` user
3. Open pgAdmin or psql and create a database:
   ```sql
   CREATE DATABASE deviceid;
   ```
4. Run the schema SQL:
   ```sql
   \c deviceid
   \i src/server/services/schema.sql
   ```
5. Update `.dev.vars`:
   ```
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/deviceid
   CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_DB=postgresql://postgres:YOUR_PASSWORD@localhost:5432/deviceid
   ```

### Option B: Docker + Docker Compose (Recommended)

1. Install Docker Desktop: https://www.docker.com/products/docker-desktop
2. From the project root, run:
   ```bash
   docker-compose up -d
   ```
3. This automatically:
   - Starts PostgreSQL on `localhost:5432`
   - Creates the `deviceid` database
   - Runs the schema migrations

4. `.dev.vars` is already configured for this setup

## Running the Development Server

Once database is ready:

```bash
wrangler dev
```

The server will start on `http://localhost:8787`

### Test the API

```bash
# Health check
curl http://localhost:8787/health

# Test fingerprint endpoint (requires valid API key)
curl -X POST http://localhost:8787/v1/fingerprint \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"canvas":"abc123","webgl":"def456"}'
```

## Stopping the database (Docker)

```bash
docker-compose down
```

To remove data:
```bash
docker-compose down -v
```
