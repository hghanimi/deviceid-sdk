const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

// Ensure dist directory exists
const distDir = path.join(__dirname, 'dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir);
}

esbuild.buildSync({
  entryPoints: ['src/client/index.js'],
  bundle: true,
  minify: true,
  outfile: 'dist/deviceid.min.js',
  format: 'iife',
  globalName: 'DeviceID',
  target: ['es2017'],
  logLevel: 'info',
});

console.log('✨ Built: dist/deviceid.min.js');
console.log('📦 File size:', fs.statSync('dist/deviceid.min.js').size, 'bytes');
