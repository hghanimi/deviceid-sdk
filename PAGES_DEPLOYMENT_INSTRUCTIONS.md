# CLOUDFLARE PAGES MANUAL DEPLOYMENT GUIDE

**Status:** Ready for Final Manual Upload  
**Action Required:** User must upload dist/ folder via Cloudflare Dashboard

## What's Ready

✅ SDK compiled to: `dist/deviceid.min.js` (4.3 KB)  
✅ Build configured in: `package.json` (npm run build)  
✅ Worker API deployed at: `https://api.arch-hayder.workers.dev`  
✅ Database ready: Supabase PostgreSQL  

## Next Step: Manual Cloudflare Pages Upload

### Step 1: Go to Cloudflare Dashboard
Navigate to: https://dash.cloudflare.com/aa303491e6ec0a8273437be1a9e97bad/pages

### Step 2: Access deviceid-cdn Project
- Look for `deviceid-cdn` in your Pages projects
- Click on it

### Step 3: Deploy the SDK
**Option A (Recommended - Manual Upload):**
1. Click "Create Deployment"
2. Click "Upload Assets"
3. Select or drag-and-drop the `dist/` folder from:
   `c:\Users\Global Pc\OneDrive\Desktop\deviceid-sdk\dist\`
4. Click "Deploy"
5. Wait 1-2 minutes for build to complete

**Option B (GitHub Integration - If Set Up):**
1. Click "Create Deployment"
2. Select GitHub repository branch
3. Cloudflare will build automatically

### Step 4: Verify Deployment
Once deployed, your SDK will be available at:
```
https://deviceid-cdn.pages.dev/deviceid.min.js
```

Test it works by opening in browser:
```
https://deviceid-cdn.pages.dev/deviceid.min.js
```

You should see minified JavaScript code (not an error).

## What You'll Have After Upload

✅ **SDK CDN URL:** `https://deviceid-cdn.pages.dev/deviceid.min.js`  
✅ **API Endpoint:** `https://api.arch-hayder.workers.dev/v1/fingerprint`  
✅ **Database:** Supabase PostgreSQL (live)  
✅ **Test Page:** `test.html` (local testing)  

## Complete Integration for Wayl

Once Pages deployment is complete:

```html
<!-- Add to Wayl checkout page -->
<script src="https://deviceid-cdn.pages.dev/deviceid.min.js"></script>

<script>
  const did = new DeviceID({ apiKey: 'pk_live_wayl_001' });
  const device = await did.identify();
  
  if (device.riskScore > 70) {
    // Require verification
  } else {
    // Process payment
  }
</script>
```

## Files You Need

**For the upload:**
- Local folder: `dist/deviceid.min.js`

**For integration:**
- Documentation: `FOR_WAYL.md`
- API Key: `pk_live_wayl_001`
- Support: arch.hayder@gmail.com

## Troubleshooting Pages Deployment

**If upload fails:**
1. Try again - Cloudflare sometimes has temporary issues
2. Use smaller file (deviceid.min.js only, not full dist folder)
3. Check that project name is `deviceid-cdn`
4. Try GitHub integration instead

**If SDK loads but doesn't work:**
1. Check browser console (F12) for errors
2. Verify API endpoint is correct
3. Check API key is set correctly
4. Run test.html locally to debug

---

**Everything else is done. This is the only remaining manual step.**
