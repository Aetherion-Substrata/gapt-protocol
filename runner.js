// runner.js -- spawn a sprint, capture stdout/stderr to logs/<name>.{out,err}.
// Usage: node runner.js <sprintFile> [logTag]
// Example: node runner.js tests/sprint19.js v26-sprint19
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const sprint = process.argv[2];
const tag    = process.argv[3] || path.basename(sprint, '.js');
if (!sprint) { console.error('usage: runner.js <sprintFile> [logTag]'); process.exit(2); }

const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const r = spawnSync(process.execPath, [sprint], {
  cwd: __dirname,
  env: process.env,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024
});

const outPath = path.join(logsDir, tag + '.out');
const errPath = path.join(logsDir, tag + '.err');
fs.writeFileSync(outPath, r.stdout || '');
fs.writeFileSync(errPath, r.stderr || '');

const summary = {
  sprint, tag,
  exit: r.status,
  signal: r.signal,
  stdoutLines: (r.stdout || '').split('\n').length,
  stderrLines: (r.stderr || '').split('\n').length,
  outPath, errPath
};
fs.writeFileSync(path.join(logsDir, tag + '.summary.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary));
process.exit(r.status === null ? 1 : r.status);
