// Read-only project walk. Collects text files; .env files are reduced to variable NAMES immediately.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.svelte-kit', 'dist', 'build', 'out', '.vercel', '.netlify', '.turbo', 'coverage', '.cache', 'vendor', '.venv', 'venv', '__pycache__', '.output', '.expo', '.idea', '.vscode']);
const TEXT_EXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro|sql|py|rb|go|php|json|toml|ya?ml|html|rules)$/i;
export const CODE_EXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro|py|rb|go|php)$/i;
const MAX_FILES = 8000;
const MAX_BYTES = 500_000;

export const isEnvFile = (p) => /(^|\/)\.env(\.[\w-]+)?$/.test(p);
export const isEnvExample = (p) => /(^|\/)\.env\.(example|sample|template|dist|defaults)$/.test(p);

function walk(root, ignore) {
  const out = [];
  const stack = [root];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const abs = join(dir, e.name);
      const rel = relative(root, abs).split(sep).join('/');
      if (ignore.some((g) => rel === g || rel.startsWith(`${g}/`))) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(abs); continue; }
      if (!e.isFile()) continue;
      if (isEnvFile(rel) || TEXT_EXT.test(e.name) || /^(Dockerfile|_headers|\.gitignore)$/.test(e.name)) out.push(rel);
    }
  }
  return out.sort();
}

export function envNames(text) {
  const names = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (m) names.push({ name: m[1], hasValue: m[2].trim().replace(/^['"]|['"]$/g, '').length > 0 });
  }
  return names;
}

function gitTracked(root) {
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
    return new Set(out.split('\0').filter(Boolean));
  } catch { return null; }
}

export function scanProject(root, opts = {}) {
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`not a folder: ${root}`);
  const ignore = (opts.ignore || []).map((g) => g.replace(/^\.\//, '').replace(/\/+$/, ''));
  const files = [];
  const envFiles = [];
  for (const rel of walk(root, ignore)) {
    let text;
    try {
      if (statSync(join(root, rel)).size > MAX_BYTES) continue;
      text = readFileSync(join(root, rel), 'utf8');
    } catch { continue; }
    if (/security-review-ignore-file/.test(text.slice(0, 300))) continue;
    if (isEnvFile(rel)) { envFiles.push({ path: rel, names: envNames(text), example: isEnvExample(rel) }); continue; }
    files.push({ path: rel, text, lines: text.split(/\r?\n/), code: CODE_EXT.test(rel) });
  }
  const tracked = opts.git === false ? null : gitTracked(root);
  const pkgPaths = files.filter((f) => /(^|\/)package\.json$/.test(f.path));
  const pkgs = pkgPaths.map((f) => { try { return { path: f.path, json: JSON.parse(f.text) }; } catch { return null; } }).filter(Boolean);
  const lock = files.find((f) => f.path === 'package-lock.json');
  let lockJson = null;
  if (lock) { try { lockJson = JSON.parse(lock.text); } catch { /* ignore */ } }
  return { root, files, envFiles, tracked, pkgs, lockJson, hasLockfile: files.some((f) => /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/.test(f.path)) || existsSync(join(root, 'yarn.lock')) || existsSync(join(root, 'bun.lockb')) };
}
