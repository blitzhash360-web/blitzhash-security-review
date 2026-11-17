import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { resolve, basename, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from './scan.mjs';
import { runChecks, score, SEVERITIES } from './rules.mjs';
import { npmAudit } from './deps.mjs';
import { toMarkdown, toTerminal, counts } from './report.mjs';
import { buildDemoApp } from './demo.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')).version;

const HELP = `BlitzHash Security Review v${VERSION}
Plain-English security audit for AI-built apps. Read-only; never prints secret values.

Usage:
  security-review [path]                 scan a project (default: current folder)
  security-review demo                   scan a built-in insecure demo app
  security-review install-skill [dir]    show where the agent skill would be installed (dry run)
  security-review install-skill [dir] --yes   actually install it

Options:
  --out FILE          write the full Markdown report (e.g. SECURITY-REVIEW.md)
  --md | --json       print the Markdown report or raw JSON instead of the summary
  --fail-on LEVEL     exit 1 if any finding is at LEVEL or worse (critical|high|medium|low), for CI
  --audit             also run \`npm audit\` (needs network and package-lock.json)
  --ignore PATH       skip a folder (repeatable)
  --no-git            don't ask git which files are committed
  --no-color          plain terminal output
  --target T          install-skill target: claude | cursor | agents | all (default all)
`;

function parseArgs(argv) {
  const o = { _: [], ignore: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') o.out = argv[++i];
    else if (a === '--fail-on') o.failOn = argv[++i];
    else if (a === '--ignore') o.ignore.push(argv[++i]);
    else if (a === '--target') o.target = argv[++i];
    else if (a === '--md') o.md = true;
    else if (a === '--json') o.json = true;
    else if (a === '--audit') o.audit = true;
    else if (a === '--no-git') o.git = false;
    else if (a === '--no-color') o.color = false;
    else if (a === '--yes' || a === '-y') o.yes = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else o._.push(a);
  }
  return o;
}

export function review(root, opts = {}) {
  const scan = scanProject(root, opts);
  const findings = runChecks(scan);
  const s = score(findings);
  const r = { name: opts.name || basename(resolve(root)), date: new Date().toISOString().slice(0, 10), filesScanned: scan.files.length + scan.envFiles.length, ...s, counts: counts(findings), findings };
  if (opts.audit) r.audit = npmAudit(root);
  return r;
}

function installSkill(dir, o) {
  const src = readFileSync(join(HERE, '..', 'skills', 'security-review', 'SKILL.md'), 'utf8');
  const t = o.target || 'all';
  const targets = { claude: '.claude/skills/security-review/SKILL.md', cursor: '.cursor/skills/security-review/SKILL.md', agents: '.agents/skills/security-review/SKILL.md' };
  const pick = t === 'all' ? Object.keys(targets) : t.split(',');
  for (const p of pick) if (!targets[p]) throw new Error(`unknown target ${p}`);
  const paths = pick.map((p) => join(resolve(dir), targets[p]));
  if (!o.yes) {
    console.log('Would write:'); paths.forEach((p) => console.log(`  ${p}${existsSync(p) ? ' (exists, would overwrite)' : ''}`));
    console.log('Dry run: nothing was written. Add --yes to install.');
    return;
  }
  for (const p of paths) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, src); console.log(`wrote ${p}`); }
}

export function main(argv) {
  let o;
  try { o = parseArgs(argv); } catch (e) { console.error(e.message); console.error(HELP); return 2; }
  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log(VERSION); return 0; }
  if (o.failOn && !SEVERITIES.includes(o.failOn)) { console.error(`--fail-on must be one of ${SEVERITIES.join(', ')}`); return 2; }
  if (o._[0] === 'install-skill') { try { installSkill(o._[1] || '.', o); return 0; } catch (e) { console.error(e.message); return 2; } }
  let root = o._[0] || '.';
  let name;
  if (root === 'demo') { root = buildDemoApp(); name = 'demo vibe-coded app (fake keys)'; }
  let r;
  try { r = review(root, { ...o, name }); } catch (e) { console.error(`error: ${e.message}`); return 2; }
  if (o.out) { writeFileSync(o.out, toMarkdown(r)); }
  if (o.json) console.log(JSON.stringify(r, null, 2));
  else if (o.md) console.log(toMarkdown(r));
  else { console.log(toTerminal(r, o.color !== false && process.stdout.isTTY !== false && !process.env.NO_COLOR)); if (o.out) console.log(`\nFull report: ${o.out}`); }
  if (o.failOn) {
    const lim = SEVERITIES.indexOf(o.failOn);
    if (r.findings.some((f) => SEVERITIES.indexOf(f.severity) <= lim)) return 1;
  }
  return 0;
}
