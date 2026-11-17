// Offline check for a short list of well-known, high-impact advisories, plus optional `npm audit`.
import { execFileSync } from 'node:child_process';

const parse = (v) => { const m = /(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?/.exec(String(v || '')); return m ? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || '' } : null; };
const lt = (a, b) => a.major !== b.major ? a.major < b.major : a.minor !== b.minor ? a.minor < b.minor : a.patch < b.patch;

// Each advisory: package, list of [line "major.minor" or "major", first fixed version].
export const ADVISORIES = [
  {
    pkg: 'next', id: 'CVE-2025-66478 / CVE-2025-55182 (React2Shell)', severity: 'critical',
    title: 'Next.js version affected by the React Server Components remote code execution bug',
    url: 'https://nextjs.org/blog/CVE-2025-66478',
    fixed: { '15.0': '15.0.5', '15.1': '15.1.9', '15.2': '15.2.6', '15.3': '15.3.6', '15.4': '15.4.8', '15.5': '15.5.7', '16.0': '16.0.7' },
  },
  {
    pkg: 'next', id: 'CVE-2025-29927', severity: 'critical',
    title: 'Next.js version where middleware auth checks can be skipped with one header',
    url: 'https://github.com/advisories/GHSA-f82v-jwr5-mffw',
    fixed: { '15.0': '15.2.3', '15.1': '15.2.3', '15.2': '15.2.3', '14': '14.2.25', '13': '13.5.9', '12': '12.3.5' },
    minMajor: 11,
  },
  {
    pkg: ['react-server-dom-webpack', 'react-server-dom-turbopack', 'react-server-dom-parcel'], id: 'CVE-2025-55182 (React2Shell)', severity: 'critical',
    title: 'React Server Components package with the remote code execution bug',
    url: 'https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components',
    exact: ['19.0.0', '19.1.0', '19.1.1', '19.2.0'], fixedText: '19.0.1, 19.1.2 or 19.2.1',
  },
];

function installedVersions(scan) {
  const out = new Map();
  const lock = scan.lockJson;
  if (lock?.packages) {
    for (const [k, v] of Object.entries(lock.packages)) {
      const m = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(k);
      if (m && v?.version && !out.has(m[1])) out.set(m[1], { version: v.version, source: 'package-lock.json' });
    }
  }
  for (const p of scan.pkgs) {
    for (const deps of [p.json.dependencies, p.json.devDependencies]) {
      for (const [name, range] of Object.entries(deps || {})) {
        if (!out.has(name) && parse(range)) out.set(name, { version: parse(range) && /\d+\.\d+\.\d+[\w.-]*/.exec(range)[0], source: p.path, declared: true });
      }
    }
  }
  return out;
}

export function checkKnownAdvisories(scan) {
  const found = [];
  const versions = installedVersions(scan);
  for (const adv of ADVISORIES) {
    for (const pkg of [].concat(adv.pkg)) {
      const hit = versions.get(pkg);
      if (!hit) continue;
      const v = parse(hit.version);
      if (!v) continue;
      let fixedIn = null;
      if (adv.exact) { if (adv.exact.includes(`${v.major}.${v.minor}.${v.patch}`)) fixedIn = adv.fixedText; }
      else if (!v.pre) {
        const fix = adv.fixed[`${v.major}.${v.minor}`] || adv.fixed[`${v.major}`];
        if (fix && lt(v, parse(fix))) fixedIn = fix;
        else if (!fix && adv.minMajor && v.major >= adv.minMajor && v.major < 12) fixedIn = 'a supported release line (12.3.5+)';
      }
      if (fixedIn) found.push({ ...adv, pkg, version: hit.version, source: hit.source, declared: !!hit.declared, fixedIn });
    }
  }
  return found;
}

/** Optional: runs `npm audit --json` (needs network + package-lock.json). Returns counts or an error string. */
export function npmAudit(root) {
  let raw;
  try {
    raw = execFileSync('npm', ['audit', '--json', '--omit=dev'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
  } catch (e) { raw = e.stdout; if (!raw) return { error: 'npm audit could not run (needs network and a package-lock.json)' }; }
  try {
    const j = JSON.parse(raw);
    if (j.error) return { error: j.error.summary || 'npm audit failed' };
    const v = j.metadata?.vulnerabilities || {};
    const top = Object.entries(j.vulnerabilities || {}).filter(([, x]) => x.severity === 'critical' || x.severity === 'high').map(([name, x]) => ({ name, severity: x.severity, fix: x.fixAvailable ? 'fix available' : 'no fix yet' })).slice(0, 15);
    return { counts: { critical: v.critical || 0, high: v.high || 0, moderate: v.moderate || 0, low: v.low || 0 }, top };
  } catch { return { error: 'npm audit output could not be parsed' }; }
}
