# DeviceID SDK

A browser fingerprinting SDK that identifies devices across sessions, incognito mode, and browser switches.

## Live Endpoints

| | URL |
|---|---|
| **SDK (CDN)** | `https://deviceid-cdn.pages.dev/deviceid.min.js` |
| **Demo page** | `https://deviceid-cdn.pages.dev` |
| **API** | `https://api.arch-hayder.workers.dev` |

## Quick Integration

```html
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>
<script>
  const did = new DeviceID({ apiKey: 'YOUR_API_KEY' });
  const result = await did.identify();
  console.log(result.visitorId); // e.g. "dvc_xxxxxxxxxx"
</script>
```

## API Response

```json
{
  "visitorId": "dvc_xxxxxxxxxx",
  "isNew": false,
  "confidence": 1.0,
  "riskScore": 20,
  "linkedDevices": [],
  "processingTimeMs": 1200
}
```

## Project Structure

```
├── src/client/index.js      # Browser SDK source
├── build.js                 # esbuild config (run: npm run build)
├── dist/
│   ├── deviceid.min.js      # Built SDK (auto-deployed to CDN)
│   └── _redirects           # Cloudflare Pages routing
├── test.html                # Demo/test page
├── api/
│   ├── src/index.ts         # Cloudflare Worker API
│   └── wrangler.jsonc       # Worker config
└── package.json
```

## Development

```bash
# Build SDK
npm run build

# Deploy SDK to CDN
npx wrangler pages deploy dist --project-name deviceid-cdn --branch main

# Deploy Worker API
cd api && npx wrangler deploy src/index.ts --config wrangler.jsonc
```

## Stats

```bash
curl https://api.arch-hayder.workers.dev/stats -H "x-api-key: YOUR_API_KEY"
```

## Stack

- **SDK**: Vanilla JS, esbuild, IIFE bundle
- **API**: Cloudflare Workers + Hono + PostgreSQL (pg)
- **Database**: Supabase PostgreSQL
- **CDN**: Cloudflare Pages
> Browser-based device fingerprinting for fraud detection and device identification

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Status](https://img.shields.io/badge/status-production-brightgreen.svg)

**Live API:** https://api.arch-hayder.workers.dev

---

## 🚀 Features

- ✅ **Browser Fingerprinting** - Canvas, WebGL, Audio, Screen, Fonts, Hardware signals
- ✅ **Device Identification** - Unique visitor IDs (`dvc_*`)
- ✅ **Cross-Browser Linking** - Identify same user across browsers
- ✅ **Fraud Detection** - Risk scores for VPN, bot, incognito, headless browsers
- ✅ **Global Edge Deployment** - Cloudflare Workers on 200+ data centers
- ✅ **PostgreSQL Backend** - Supabase for audit logs and device linking
- ✅ **4.3KB Bundle** - Minified SDK for web integration

---

## 📦 Installation

### Via CDN (Recommended)

```html
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>

<script>
  const did = new DeviceID({ apiKey: 'pk_live_athar_001' });
  const device = await did.identify();
  console.log(device.visitorId);
</script>
```

### Via NPM

```bash
npm install deviceid-sdk
```

```javascript
import DeviceID from 'deviceid-sdk';

const did = new DeviceID({ apiKey: 'pk_live_athar_001' });
const device = await did.identify();
```

---

## 🎯 Quick Start

### 1. Initialize SDK

```javascript
const did = new DeviceID({
  apiKey: 'pk_live_athar_001',           // Your API key
  apiEndpoint: 'https://api.arch-hayder.workers.dev/v1/fingerprint',  // Optional
  debug: false                           // Optional
});
```

### 2. Identify Device

```javascript
const device = await did.identify();
```

### 3. Use Response

```javascript
{
  visitorId: 'dvc_7f3a8b2c1d4e5f6a',   // Unique device ID
  isNew: false,                          // First visit?
  confidence: 0.96,                      // 0.0 - 1.0 match score
  riskScore: 25,                         // 0-100 fraud risk
  linkedDevices: [...],                  // Cross-device links
  processingTimeMs: 145                  // API latency
}
```

---

## 📊 Risk Score Calculation

| Signal | Points | Threshold |
|--------|--------|-----------|
| 🆕 New Device | +20 | Always applied |
| 🌐 VPN Detected | +30 | WebRTC IP leak |
| 🕵️ Incognito Mode | +25 | localStorage test |
| 🤖 Headless Browser | +35 | navigator.webdriver |
| 🦾 Bot Detected | +40 | Phantom/Zombie |
| 🔗 Multi-Device (3+) | +15 | Linked devices >3 |
| ✅ High Confidence | -10 | Match >0.85 |

**Recommended Actions:**
- 0-30: ✅ Allow
- 31-60: ⚠️ Monitor
- 61-80: 🔒 Require Verification
- 81-100: 🚫 Block

---

## 🔧 Configuration

### Options

```javascript
const did = new DeviceID({
  // Your API key from dashboard
  apiKey: 'pk_live_athar_001',
  
  // Custom API endpoint (optional)
  apiEndpoint: 'https://your-domain.com/fingerprint',
  
  // Enable console logging
  debug: false,
  
  // Custom timeout (ms)
  timeout: 5000
});
```

---

## 📝 API Reference

### `identify()`

Collects browser signals and returns device identity.

**Returns:** `Promise<DeviceResponse>`

```typescript
interface DeviceResponse {
  visitorId: string;           // Unique device ID
  isNew: boolean;              // First visit?
  confidence: number;          // Match confidence (0-1)
  riskScore: number;           // Fraud risk (0-100)
  linkedDevices: LinkInfo[];   // Cross-device links
  processingTimeMs: number;    // API response time
}

interface LinkInfo {
  visitorIdA: string;
  visitorIdB: string;
  linkType: 'cross_browser' | 'same_ip' | 'hardware_match';
  confidence: number;
  linkedAt: string;
}
```

---

## 🌍 Browser Support

| Browser | Canvas | WebGL | Audio | Support |
|---------|--------|-------|-------|---------|
| Chrome 90+ | ✅ | ✅ | ✅ | ✅ Full |
| Firefox 88+ | ✅ | ✅ | ✅ | ✅ Full |
| Safari 14+ | ✅ | ✅ | ✅ | ✅ Full |
| Edge 90+ | ✅ | ✅ | ✅ | ✅ Full |
| IE 11 | ❌ | ❌ | ❌ | ❌ No |
| Mobile Chrome | ✅ | ✅ | ✅ | ✅ Full |
| Mobile Safari | ✅ | ⚠️ | ✅ | ✅ Partial |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│     Browser                         │
│  ┌──────────────────────────────┐   │
│  │  DeviceID SDK (4.3KB)        │   │
│  │ Collect signals              │   │
│  └──────────────────┬───────────┘   │
└─────────────────────┼────────────────┘
                      │ HTTPS POST
                      ↓
┌─────────────────────────────────────┐
│  Cloudflare Worker Edge             │
│  https://api.arch-hayder.workers.dev│
│  • Authenticate API key             │
│  • Rate limiting  (1000 req/min)    │
│  • Hash signals (SHA-256)           │
│  • Query fingerprints table         │
└──────────────────┬──────────────────┘
                   │ SQL Query
                   ↓
┌─────────────────────────────────────┐
│  Supabase PostgreSQL                │
│  • fingerprints table               │
│  • device_links table               │
│  • api_keys table                   │
│  • events audit log                 │
└─────────────────────────────────────┘
```

---

## 📁 Project Structure

```
deviceid-sdk/
├── api/                          # Cloudflare Worker API
│   ├── src/index.ts             # Worker entry point
│   ├── wrangler.jsonc           # Worker config
│   └── .dev.vars                # Dev environment
│
├── src/
│   ├── client/index.js          # Browser SDK
│   └── server/
│       ├── services/
│       │   ├── Hasher.js        # Signal hashing
│       │   ├── graph.js         # Device linking
│       │   └── schema.sql       # Database schema
│       └── matcher.js           # Fuzzy matching
│
├── dist/
│   └── deviceid.min.js          # Bundled SDK (4.3KB)
│
├── build.js                      # esbuild configuration
├── test.html                     # Integration test page
├── INTEGRATION_GUIDE.md          # Athar integration docs
└── README.md                     # This file
```

---

## 🔐 Security

### API Keys

Your API key is safe to hardcode in browser code:
- ✅ Can be exposed in client-side JavaScript
- ❌ Never expose your `sk_*` secret key
- ⏱️ Rate limited: 1000 requests/minute per key
- 🔄 Can be rotated anytime in dashboard

### Data Protection

- ✅ All signals are hashed with SHA-256
- ✅ Individual signal hashes stored (not raw values)
- ✅ HTTPS-only communication
- ✅ No cookies or tracking pixels
- ✅ GDPR compliant (signals aren't PII)

---

## 🚨 Troubleshooting

### SDK loads but nothing happens

**Check:** Open DevTools (F12) → Console tab → Look for red errors

**Common Causes:**
- CORS error: Check API endpoint is correct
- API key invalid: Verify `pk_live_athar_001` is active
- Network blocked: Check firewall/proxy settings

**Fix:**
```javascript
const did = new DeviceID({ debug: true });
did.identify().catch(err => console.error(err));
```

### Same visitorId on different devices

**Issue:** Fingerprinting is too weak

**Debugging:**
- Open browser console with `debug: true`
- Check if Canvas/WebGL return different values
- Test on truly different hardware

**Contact support:** arch.hayder@gmail.com

### High risk scores on legitimate users

**Adjust thresholds** based on your fraud data:

```javascript
if (device.riskScore > 40) {  // Changed from 70
  // Your logic
}
```

---

## 📊 Monitoring

### Check API Health

```bash
curl https://api.arch-hayder.workers.dev/health
```

**Response:**
```json
{ "status": "ok", "version": "1.0.0", "edge": true }
```

### View Fingerprints

Log into Supabase dashboard:
- Go to: https://supabase.com/dashboard
- Table: `fingerprints`
- Columns: `visitor_id`, `raw_hash`, `risk_score`, `created_at`

---

## 📈 Performance

- **Bundle Size:** 4.3 KB (minified)
- **API Latency:** ~145ms (Edge optimized)
- **Signal Collection:** ~50ms
- **Database Query:** ~30-50ms

**Globally deployed on 200+ Cloudflare data centers** = <50ms worldwide.

---

## 🛣️ Roadmap

- [ ] WebRTC IP leak detection
- [ ] GPU fingerprinting enhancement
- [ ] Durable Objects for global rate limiting
- [ ] Webhook event delivery
- [ ] Admin dashboard for metrics
- [ ] React component wrapper

---

## 📖 Integration Guides

- **👉 [Athar Checkout Integration](./INTEGRATION_GUIDE.md)** - Full step-by-step guide
- **[Test Page](./test.html)** - Live demo and debugging
- **[API Reference](./API.md)** - Detailed endpoint documentation

---

## 📝 License

MIT - See LICENSE file

---

## 👨‍💻 Author

**Arch Hayder**
- Email: arch.hayder@gmail.com
- GitHub: https://github.com/hghanimi
- Project: https://github.com/hghanimi/deviceid-sdk

---

## 🤝 Support

### Getting Help

1. **Documentation:** Check [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md)
2. **GitHub Issues:** https://github.com/hghanimi/deviceid-sdk/issues
3. **Email:** arch.hayder@gmail.com

### Reporting Bugs

Include:
- Browser and OS version
- Console errors (F12)
- Steps to reproduce
- Your API key (masked)

---

## 🎯 Use Cases

✅ Fraud Detection & Prevention  
✅ Account Takeover Protection  
✅ Multi-Account Abuse Prevention  
✅ Checkout Risk Assessment  
✅ Cross-Device User Tracking  
✅ Bot Detection  
✅ VPN/Proxy Detection  

---

**Version:** 1.0.0  
**Last Updated:** March 2026  
**Status:** Production Ready ✅
