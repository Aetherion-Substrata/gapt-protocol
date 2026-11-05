#!/usr/bin/env node
// ============================================
// GAPT Language Runner
// Usage: node gapt.run.js <file.gapt>
//        node gapt.run.js --ast <file.gapt>
// ============================================

const fs   = require('fs');
const path = require('path');

const { GaptLexer }       = require('./src/lexer');
const { GaptParser }      = require('./src/parser');
const { GaptInterpreter } = require('./src/interpreter');

const args    = process.argv.slice(2);
const showAST = args.includes('--ast');
const file    = args.find(a => !a.startsWith('--'));

if (!file) {
  console.log('\n  GAPT Language Runner\n\n  Usage:\n    node gapt.run.js <file.gapt>\n    node gapt.run.js --ast <file.gapt>\n');
  process.exit(0);
}

const filepath = path.resolve(file);
if (!fs.existsSync(filepath)) {
  console.error(`  File not found: ${filepath}`);
  process.exit(1);
}

const source = fs.readFileSync(filepath, 'utf8');
console.log(`\n  GAPT Runner -- ${path.basename(filepath)}`);
console.log(`  ${'='.repeat(48)}\n`);

const lexer  = new GaptLexer(source);
const tokens = lexer.tokenise();

if (lexer.errors.length > 0) {
  console.error('  Lexer errors:');
  lexer.errors.forEach(e => console.error(`    ${e}`));
  process.exit(1);
}

const parser = new GaptParser(tokens);
const ast    = parser.parse();

if (parser.errors.length > 0) {
  console.error('  Parse errors:');
  parser.errors.forEach(e => console.error(`    ${e}`));
  process.exit(1);
}

if (showAST) {
  console.log('  AST:\n');
  console.log(JSON.stringify(ast, null, 2));
  process.exit(0);
}

const interp  = new GaptInterpreter();
const results = interp.execute(ast);

interp.log.forEach(l => console.log(l));

if (interp.errors.length > 0) {
  console.log('\n  Errors:');
  interp.errors.forEach(e => console.log(`    ${e}`));
}

console.log(`\n  ${'='.repeat(48)}`);
console.log(`  Results: ${results.length} transmission(s)\n`);

results.forEach((r, i) => {
  const icon = r.passed ? 'PASS' : r.predicted ? 'PRED' : 'FAIL';
  console.log(`  ${i+1}. [${icon}] [${r._from} => ${r._to}] -- ${r.reason}`);
  if (r.trustTier) console.log(`     Trust: ${r.trustScore}/100 -- ${r.trustTier}`);
});

const passed = results.filter(r => r.passed).length;
const failed = results.filter(r => !r.passed).length;
console.log(`\n  Passed: ${passed} | Blocked: ${failed}`);
console.log(`  ${'='.repeat(48)}\n`);
