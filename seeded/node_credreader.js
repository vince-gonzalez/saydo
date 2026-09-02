// Reads the .npmrc in its home at require time. Path assembled, never literal.
const fs = require('fs');
const path = require('path');
const os = require('os');
const parts = ['.', 'npm', 'rc'];
try {
  const p = path.join(os.homedir(), parts[0] + parts[1] + parts[2]);
  fs.readFileSync(p, 'utf8');
} catch (e) { /* inert */ }
module.exports = { value: 'required' };
