# DeviceID Integration Guide for Wayl

**Version:** 1.0.0  
**Last Updated:** March 2026  
**API Endpoint:** https://api.arch-hayder.workers.dev

---

## Overview

DeviceID is a browser-based device fingerprinting service that uniquely identifies users and detects fraud. Integrate it into your checkout page to:

- ✅ Detect multi-account fraud and account takeover attempts
- ✅ Identify returning customers across browsers and devices
- ✅ Get risk scores for suspicious activity
- ✅ Link devices to customer profiles

---

## Quick Start (3 Steps)

### Step 1: Add the SDK to Your Page

Add this single line to the `<head>` or end of `<body>` in your checkout HTML:

```html
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>
```

### Step 2: Identify Device Before Payment

Before processing payment, call `identify()` to get device data:

```javascript
const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });

const device = await did.identify();

console.log('Visitor ID:', device.visitorId);
console.log('Risk Score:', device.riskScore);
console.log('Is New Device:', device.isNew);

// Send device.visitorId with your payment request
```

### Step 3: Check Risk Signals

```javascript
if (device.riskScore > 70) {
  // High risk - require additional verification
  alert('Please verify your identity');
} else {
  // Low risk - proceed with payment
  processPayment(device.visitorId);
}
```

---

## Full Integration Example

Here's a complete checkout page example:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Wayl Checkout</title>
</head>
<body>
    <h1>Secure Checkout</h1>
    
    <form id="checkoutForm">
        <input type="email" placeholder="Email" required>
        <input type="text" placeholder="Card Number" required>
        <button type="submit">Pay Now</button>
    </form>

    <!-- Load DeviceID SDK -->
    <script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>

    <script>
        document.getElementById('checkoutForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            // Identify device
            const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });
            const device = await did.identify();

            console.log('Device:', device);

            // Check risk
            if (device.riskScore > 70) {
                alert('High-risk activity detected. Please verify your identity.');
                return;
            }

            // Attach device ID to form
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = 'deviceId';
            hiddenInput.value = device.visitorId;
            e.target.appendChild(hiddenInput);

            // Submit payment
            console.log('Proceeding with payment for device:', device.visitorId);
            // e.target.submit(); // Uncomment to actually submit
        });
    </script>
</body>
</html>
```

---

## Response Format

The `identify()` method returns:

```json
{
  "visitorId": "dvc_7f3a8b2c1d4e5f6a",
  "isNew": false,
  "confidence": 0.96,
  "riskScore": 25,
  "linkedDevices": [
    {
      "visitorIdA": "dvc_7f3a8b2c1d4e5f6a",
      "visitorIdB": "dvc_abc123def456",
      "linkType": "cross_browser",
      "confidence": 0.89,
      "linkedAt": "2026-03-23T10:30:00Z"
    }
  ],
  "processingTimeMs": 145
}
```

**Field Explanations:**

| Field | Type | Meaning |
|-------|------|---------|
| `visitorId` | string | Unique device identifier (prefix: `dvc_`) |
| `isNew` | boolean | First time seeing this device? |
| `confidence` | number | 0.0 - 1.0 match confidence score |
| `riskScore` | number | 0 - 100 fraud risk (higher = more suspicious) |
| `linkedDevices` | array | Other devices linked to same person |
| `processingTimeMs` | number | API response time in milliseconds |

---

## Risk Score Breakdown

Risk points are calculated from:

- **+20 pts** - New device (first visit)
- **+30 pts** - VPN detected
- **+25 pts** - Incognito/Private mode
- **+35 pts** - Headless browser
- **+40 pts** - Bot signals detected
- **+15 pts** - 3+ linked devices
- **-10 pts** - High confidence match (reduces risk)

**Recommended Actions:**

| Score | Action |
|-------|--------|
| 0-30 | ✅ Allow payment |
| 31-60 | ⚠️ Monitor (log for review) |
| 61-80 | 🚨 Require email verification |
| 81-100 | 🚫 Block or require 2FA |

---

## Advanced Options

### Initialize with Custom Endpoint

If you're using a custom domain:

```javascript
const did = new DeviceID({
  apiKey: 'pk_live_wayl_001',
  apiEndpoint: 'https://your-custom-domain.com/v1/fingerprint'
});
```

### Enable Debug Mode

See detailed signal collection:

```javascript
const did = new DeviceID({
  apiKey: 'pk_live_wayl_001',
  debug: true  // Logs to browser console
});
```

---

## Error Handling

Always wrap `identify()` in try-catch:

```javascript
try {
  const device = await did.identify();
} catch (err) {
  console.error('DeviceID failed:', err);
  // Fallback: allow payment but log issue
  processPayment('unknown');
}
```

**Common Errors:**

| Error | Cause | Solution |
|-------|-------|----------|
| `API error: 401` | Invalid API key | Contact support with your account email |
| `API error: 429` | Rate limit exceeded | Wait 1 minute, then retry |
| `CORS error` | Cross-origin issue | Check that SDK is loaded from correct domain |
| `Request failed` | Network issue | Check internet connection, retry |

---

## Testing

### Test on Multiple Devices

1. **Desktop Browser:** Go to test.html, run test
2. **Phone (Chrome):** Open same test link, should get different `visitorId`
3. **Phone (Firefox):** Open same link, should link via cross-browser logic
4. **Incognito Mode:** Open test link, risk score +25 for private mode

### Monitor in Dashboard

Check fingerprints table in Supabase:

```
Go to: https://supabase.com
Table: fingerprints
Columns: visitor_id, risk_score, is_vpn, is_incognito, created_at
```

---

## API Key Security

**Your API Key:** `pk_live_wayl_001`

⚠️ **IMPORTANT:**
- This key is safe to expose in browser code (public key)
- Rate limit: 1,000 requests/minute per key
- Do NOT share your secret key (`sk_...`)
- Rotate keys if compromised

---

## Support & Troubleshooting

### Common Issues

**Q: "SDK loads but nothing happens in console"**  
A: Open DevTools (F12) and check Console tab for errors. Usually CORS or API key issue.

**Q: "Same visitorId on different computers"**  
A: This is a fingerprinting accuracy issue. Usually means your Canvas/WebGL are too generic. Contact support.

**Q: "riskScore is always 0"**  
A: Check that your browser is allowed to access Canvas/WebGL APIs. Some old browsers may not support fingerprinting.

---

## Production Checklist

- [ ] API key added to checkout page
- [ ] Error handling implemented
- [ ] Risk score logic integrated into payment flow
- [ ] Tested on Chrome, Firefox, Safari, Edge browsers
- [ ] Tested on iOS and Android
- [ ] Tested in incognito mode
- [ ] Rate limiting strategy planned (1000 req/min soft limit)
- [ ] Webhook alerts configured (optional)

---

## Next Steps

1. **Add to Checkout:** Paste SDK script tag into your checkout page
2. **Test Integration:** Open test.html to verify SDK works
3. **Monitor Fraud:** Check Supabase dashboard for suspicious patterns
4. **Optimize Rules:** Adjust risk thresholds based on your fraud data

---

## Contact

**Support Email:** arch.hayder@gmail.com  
**GitHub Repository:** https://github.com/hghanimi/deviceid-sdk  
**API Status:** https://api.arch-hayder.workers.dev/health

---

**Last Updated:** March 23, 2026  
**SDK Version:** 1.0.0  
**Built With:** Cloudflare Workers, Supabase PostgreSQL
