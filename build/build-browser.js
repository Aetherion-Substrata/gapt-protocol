#!/usr/bin/env node
// build/build-browser.js
// Zero-dep browser bundler for @gapt/protocol.
//
// Reads the src/ modules, wraps each in a tiny CommonJS-style closure,
// rewrites require('./persist') -> require('./persist.browser') (the in-mem
// shim), and emits dist/gapt.browser.js + dist/gapt.browser.d.ts.
//
// Run: npm run build:browser

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT    = path.resolve(__dirname, '..');
const SRC     = path.join(ROOT, 'src');
const DIST    = path.join(ROOT, 'dist');
const PKG     = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = PKG.version;

// Modules in dependency order. The id is the require-path used inside src/.
// For the browser bundle, './persist' resolves to the in-mem shim file but
// keeps the same id so gapt.js's require('./persist') is satisfied unchanged.
const MODS = [
  { id: './persist',     file: 'persist.browser.js' },
  { id: './network',     file: 'network.js'        },
  { id: './lexer',       file: 'lexer.js'          },
  { id: './parser',      file: 'parser.js'         },
  { id: './gapt',        file: 'gapt.js'           },
  { id: './interpreter', file: 'interpreter.js'    },
];

function readMod(file) {
  return fs.readFileSync(path.join(SRC, file), 'utf8');
}

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function buildBundle() {
  const parts = [];

  parts.push('/*! gapt-protocol v' + VERSION + ' - browser bundle');
  parts.push(' *  (c) 2026 Kizldn / Aetherion Substrata Ltd - Noncommercial use-only licence, see LICENSE - https://github.com/Aetherion-Substrata/gapt-protocol');
  parts.push(' *  In-memory persistence shim. See src/persist.browser.js for caveats.');
  parts.push(' */');
  parts.push('(function (global) {');
  parts.push('  "use strict";');
  parts.push('  var __mods = {};');
  parts.push('  function __req(id) {');
  parts.push('    if (!__mods[id]) throw new Error("gapt bundle: module not found: " + id);');
  parts.push('    return __mods[id].exports;');
  parts.push('  }');
  parts.push('  function __def(id, fn) {');
  parts.push('    var m = __mods[id] = { exports: {} };');
  parts.push('    fn(m, m.exports, __req);');
  parts.push('  }');
  parts.push('');

  for (const mod of MODS) {
    const src = readMod(mod.file);
    parts.push('  // -- ' + mod.id + ' (from src/' + mod.file + ') --');
    parts.push('  __def(' + JSON.stringify(mod.id) + ', function (module, exports, require) {');
    parts.push(src.split('\n').map(l => l.length ? '    ' + l : l).join('\n'));
    parts.push('  });');
    parts.push('');
  }

  parts.push('  var core = __req("./gapt");');
  parts.push('  var net  = __req("./network");');
  parts.push('  var lex  = __req("./lexer");');
  parts.push('  var par  = __req("./parser");');
  parts.push('  var ip   = __req("./interpreter");');
  parts.push('');
  parts.push('  global.Gapt = {');
  parts.push('    // main API');
  parts.push('    GaptGraph:            core.GaptGraph,');
  parts.push('    GaptEdge:             core.GaptEdge,');
  parts.push('    GaptMemory:           core.GaptMemory,');
  parts.push('    GaptFingerprint:      core.GaptFingerprint,');
  parts.push('    getTrustTier:         core.getTrustTier,');
  parts.push('    DEFAULT_TRUST_CONFIG: core.DEFAULT_TRUST_CONFIG,');
  parts.push('    // network');
  parts.push('    GaptNetwork: net.GaptNetwork,');
  parts.push('    // .gapt lang pipeline (Lexer -> Parser -> Interpreter)');
  parts.push('    GaptLexer:       lex.GaptLexer,');
  parts.push('    Token:           lex.Token,');
  parts.push('    TOKEN_TYPES:     lex.TOKEN_TYPES,');
  parts.push('    GaptParser:      par.GaptParser,');
  parts.push('    GaptInterpreter: ip.GaptInterpreter,');
  parts.push('    // meta');
  parts.push('    version: ' + JSON.stringify(VERSION));
  parts.push('  };');
  parts.push('})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));');
  parts.push('');

  return parts.join('\n');
}

function buildDts() {
  return [
    '// @gapt/protocol v' + VERSION + ' - browser bundle types',
    '// Augments the global Window with the Gapt namespace.',
    '',
    'import type {',
    '  GaptGraph, GaptEdge, GaptMemory, GaptFingerprint',
    "} from '../src/gapt';",
    "import type { GaptNetwork } from '../src/network';",
    "import type { GaptLexer, Token, TOKEN_TYPES as TokenTypes } from '../src/lexer';",
    "import type { GaptParser } from '../src/parser';",
    "import type { GaptInterpreter } from '../src/interpreter';",
    '',
    'export interface GaptBrowserAPI {',
    '  GaptGraph: typeof GaptGraph;',
    '  GaptEdge: typeof GaptEdge;',
    '  GaptMemory: typeof GaptMemory;',
    '  GaptFingerprint: typeof GaptFingerprint;',
    '  getTrustTier: (score: number, config?: any) => any;',
    '  DEFAULT_TRUST_CONFIG: any;',
    '  GaptNetwork: typeof GaptNetwork;',
    '  GaptLexer: typeof GaptLexer;',
    '  Token: typeof Token;',
    '  TOKEN_TYPES: typeof TokenTypes;',
    '  GaptParser: typeof GaptParser;',
    '  GaptInterpreter: typeof GaptInterpreter;',
    '  version: string;',
    '}',
    '',
    'declare global {',
    '  interface Window { Gapt: GaptBrowserAPI; }',
    '  // eslint-disable-next-line no-var',
    '  var Gapt: GaptBrowserAPI;',
    '}',
    '',
    'export {};',
    ''
  ].join('\n');
}

function main() {
  ensureDir(DIST);
  const bundle = buildBundle();
  const dts    = buildDts();
  const outJs  = path.join(DIST, 'gapt.browser.js');
  const outDts = path.join(DIST, 'gapt.browser.d.ts');

  // Atomic write: tmp + rename.
  fs.writeFileSync(outJs + '.tmp', bundle);
  fs.renameSync(outJs + '.tmp', outJs);
  fs.writeFileSync(outDts + '.tmp', dts);
  fs.renameSync(outDts + '.tmp', outDts);

  const jsBytes  = fs.statSync(outJs).size;
  const dtsBytes = fs.statSync(outDts).size;
  console.log('  [build:browser] ' + outJs + ' (' + jsBytes + ' bytes)');
  console.log('  [build:browser] ' + outDts + ' (' + dtsBytes + ' bytes)');
  console.log('  [build:browser] version ' + VERSION + ' OK');
}

main();
