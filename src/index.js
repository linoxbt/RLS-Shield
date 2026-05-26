#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';
import { analyzeFindings, demoFindings, renderMarkdownReport } from './triage.js';

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function parseArgs(argv) {
  const args = {
    demo: false,
    input: null,
    json: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--demo') args.demo = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--input' || arg === '-i') {
      args.input = argv[i + 1];
      i += 1;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    }
  }

  return args;
}

function printHelp() {
  process.stdout.write(`DeFi Security Triage Agent

Usage:
  npm run demo
  node src/index.js --input findings.txt
  cat findings.txt | node src/index.js
  node src/index.js --demo --json

Options:
  --demo          Analyze bundled sample findings
  --input, -i     Read scanner findings from a file
  --json          Emit structured JSON instead of Markdown
  --help, -h      Show this help
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  let input = '';
  if (args.demo) {
    input = demoFindings;
  } else if (args.input) {
    input = fs.readFileSync(args.input, 'utf8');
  } else if (!process.stdin.isTTY) {
    input = await readStdin();
  }

  if (!input.trim()) {
    process.stderr.write('No findings supplied. Use --demo, --input findings.txt, or pipe scanner text into stdin.\n');
    process.exitCode = 1;
    return;
  }

  const result = analyzeFindings(input);
  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  process.stdout.write(`${renderMarkdownReport(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
