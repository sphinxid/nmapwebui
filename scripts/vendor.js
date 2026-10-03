// Copies third-party browser assets from node_modules into static/vendor so the
// app has no runtime CDN dependency and works on air-gapped hosts.
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const out = path.join(root, 'static', 'vendor');

const copies = [
  ['node_modules/chart.js/dist/chart.umd.js', 'chart.umd.js'],
  ['node_modules/@fortawesome/fontawesome-free/css/all.min.css', 'fontawesome/css/all.min.css'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-solid-900.woff2', 'fontawesome/webfonts/fa-solid-900.woff2'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-solid-900.ttf', 'fontawesome/webfonts/fa-solid-900.ttf'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-regular-400.woff2', 'fontawesome/webfonts/fa-regular-400.woff2'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-regular-400.ttf', 'fontawesome/webfonts/fa-regular-400.ttf'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-brands-400.woff2', 'fontawesome/webfonts/fa-brands-400.woff2'],
  ['node_modules/@fortawesome/fontawesome-free/webfonts/fa-brands-400.ttf', 'fontawesome/webfonts/fa-brands-400.ttf'],
];

for (const [src, dest] of copies) {
  const from = path.join(root, src);
  const to = path.join(out, dest);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
  console.log(`vendored ${dest}`);
}
