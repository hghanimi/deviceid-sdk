# DeviceID SDK for Wayl - Ready for Integration

**Status:** ✅ Production Ready  
**API Endpoint:** https://api.arch-hayder.workers.dev  
**SDK CDN:** https://deviceid-cdn.pages.dev/deviceid.min.js  
**API Key:** `pk_live_wayl_001`

---

## What You're Getting

DeviceID is a **device fingerprinting service** that:

1. **Uniquely identifies devices** across browsers and sessions
2. **Detects fraud signals** (VPN, bot, incognito mode, multi-account)
3. **Scores risk** from 0-100 for payment processing decisions
4. **Links devices** when the same user uses multiple browsers

### Example Use Case for Wayl

```javascript
// When customer clicks "Pay"
const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });
const device = await did.identify();

// device.riskScore tells you how suspicious this is:
if (device.riskScore > 70) {
  // Require 2FA or email verification
  alert('Please verify your identity');
} else {
  // Safe to process payment
  processPayment(device.visitorId);
}

// Later: check Supabase to see payment + device history
```

---

## How It Works (3 Steps)

### Step 1: Add Script to Checkout
```html
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>
```

### Step 2: Collect Device Fingerprint
```javascript
const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });
const device = await did.identify();
```

### Step 3: Use Result
```javascript
{
  visitorId: "dvc_7f3a8b2c1d4e5f6a",    // Unique device ID
  isNew: false,                          // First time seeing this device?
  confidence: 0.96,                      // How confident are we? (0-1)
  riskScore: 25,                         // Fraud risk (0-100)
  linkedDevices: [...]                   // Other devices from same person
}
```

---

## Risk Score Guide

| Score | What It Means | Action |
|-------|---------------|--------|
| 0-30 | ✅ Safe | Process normally |
| 31-60 | ⚠️ Caution | Log for review |
| 61-80 | 🔒 Suspicious | Require email/2FA |
| 81-100 | 🚫 Dangerous | Block or investigate |

---

## What Signals We Collect

The SDK analyzes these browser properties (none are PII):

✅ **Graphics** - Canvas drawing, WebGL capabilities  
✅ **Audio** - Audio context fingerprint  
✅ **Screen** - Resolution, color depth, pixel ratio  
✅ **Fonts** - Installed system fonts  
✅ **Browser** - User agent, language, platform  
✅ **Hardware** - CPU cores, device memory, touch points  
✅ **Evasion** - Detects VPN, incognito, headless browsers, bots

**Important:** We do NOT collect:
- ❌ GPS location
- ❌ Personal data (name, email, phone)
- ❌ Browsing history
- ❌ Cookies or tracking pixels

---

## Integration Steps

### 1. Add to Your Checkout Page

Find your checkout HTML file. Add this to the `<head>` or before `</body>`:

```html
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>
```

### 2. Add Identification Before Payment

In your payment form handler, call `identify()`:

```javascript
document.getElementById('checkoutForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  // Get device fingerprint
  const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });
  const device = await did.identify();

  // Add device ID to payment request
  const formData = new FormData(e.target);
  formData.append('deviceId', device.visitorId);

  // Check risk
  if (device.riskScore > 65) {
    // Optional: require verification
    alert('Processing with additional verification');
  }

  // Send to your payment processor
  const response = await fetch('/api/process-payment', {
    method: 'POST',
    body: formData
  });

  // Continue with payment flow...
});
```

### 3. (Optional) Log Device to Database

You can store the device ID and risk score:

```javascript
// In your payment success handler
await fetch('/api/payment-log', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    orderId: orderId,
    deviceId: device.visitorId,
    riskScore: device.riskScore,
    isNewDevice: device.isNew,
    timestamp: new Date()
  })
});
```

---

## Production Checklist

Before going live, ensure:

- [ ] SDK script tag added to checkout
- [ ] API key configured: `pk_live_wayl_001`
- [ ] Risk scoring logic implemented
- [ ] Error handling added (SDK may fail on some browsers)
- [ ] Tested on Chrome, Firefox, Safari, Edge
- [ ] Tested on iOS and Android
- [ ] Tested in incognito/private mode
- [ ] Payment flow tested end-to-end

---

## Testing

### Quick Test Page
We've created a test page to verify everything works:

**File:** `test.html` (in project root)

Open it in a browser and click the test button. You should see:
```json
{
  "visitorId": "dvc_...",
  "isNew": true/false,
  "confidence": 0.95,
  "riskScore": 25,
  ...
}
```

### Test Multiple Browsers
1. **Chrome** - Open test.html, click test
2. **Firefox** - Open same test.html, click test
3. **Incognito** - Open in incognito/private mode, click test
   - Should get SAME visitorId (canvas/webgl match)
   - Should have riskScore +25 (private mode detected)
4. **Different Device** - Use phone/different computer
   - Should get DIFFERENT visitorId

---

## API Reference

### `new DeviceID(options)`

Initialize the SDK:

```javascript
const did = new DeviceID({
  apiKey: 'pk_live_wayl_001',                    // Your API key (required)
  apiEndpoint: 'https://api.arch-hayder.workers.dev/v1/fingerprint',  // Optional
  debug: false                                    // Optional: logs to console
});
```

### `identify()`

Collect signals and identify device:

```javascript
const device = await did.identify();
```

**Returns:** Object with these properties:

| Property | Type | Meaning |
|----------|------|---------|
| `visitorId` | string | Unique device ID (format: `dvc_XXXXXXX`) |
| `isNew` | boolean | First time seeing this device? |
| `confidence` | number | 0.0 to 1.0 - match certainty |
| `riskScore` | number | 0 to 100 - fraud likelihood |
| `linkedDevices` | array | Other devices from same person |
| `processingTimeMs` | number | How long the API call took |

---

## Troubleshooting

### "SDK loads but nothing happens"
1. Open browser DevTools (F12)
2. Look in Console tab for red error messages
3. Most common: wrong API key or network issue

### "API error 401"
- Check that `pk_live_wayl_001` is the API key
- Verify it's in the headers, not URL

### "CORS error"
- This shouldn't happen (CORS is enabled)
- If it does, contact support: arch.hayder@gmail.com

### "Same visitorId on different computers"
- This is a bug - should NOT happen
- Contact support with details

---

## Support

**Email:** arch.hayder@gmail.com  
**GitHub:** https://github.com/hghanimi/deviceid-sdk  
**API Status:** https://api.arch-hayder.workers.dev/health  

### Getting Help
1. Check INTEGRATION_GUIDE.md (detailed docs)
2. Check browser console (F12) for errors
3. Email support with error message + API key (masked)

---

## Security Notes

### API Key Safety
- ✅ Your key `pk_live_wayl_001` is SAFE to hardcode in browser
- ✅ It's rate-limited to 1000 requests/minute
- ✅ Rate limit is per-key, so a competitor can't DoS you
- ❌ Never share your secret key (sk_*)
- 🔄 You can regenerate keys anytime

### Data Privacy
- ✅ Signals are hashed (not raw values stored)
- ✅ No cookies or tracking pixels
- ✅ HTTPS-only communication
- ✅ GDPR compliant (signals aren't PII)

---

## Architecture

```
Your Checkout Page
    ↓
    [DeviceID SDK - 4.3 KB]
    ↓ POST /v1/fingerprint
Cloudflare Worker Edge (200+ locations worldwide)
    ↓ SQL Query
Supabase PostgreSQL
    ↓
fingerprints table (stores visitor history)
```

---

## Performance

- **SDK Size:** 4.3 KB (minified)
- **Load Time:** <50ms from CDN
- **API Latency:** ~145ms (global)
- **Total Time:** ~150-200ms from page load

This is fast enough to not block checkout flow.

---

## What Happens to My Data?

Your customer's device fingerprint is:

1. **Collected** by the SDK (runs in browser)
2. **Sent** securely to the API (HTTPS)
3. **Hashed** into a unique ID (SHA-256)
4. **Stored** in our database for future visits
5. **Linked** across devices (cross-browser detection)
6. **Analyzed** for fraud signals
7. **Deleted** after [policy] (configurable)

---

## Next Steps

1. **Add SDK to checkout:** Copy script tag
2. **Test locally:** Open test.html
3. **Implement logic:** Add risk checks before payment
4. **Go live:** Deploy to production
5. **Monitor:** Check DeviceID dashboard for patterns

---

**Ready?** Start with Step 1 above. Questions? Email arch.hayder@gmail.com

---

*Generated: March 23, 2026*  
*DeviceID SDK v1.0.0*  
*Powered by Cloudflare Workers + Supabase*
