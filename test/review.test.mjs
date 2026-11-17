import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { review } from '../src/cli.mjs';
import { buildDemoApp, FAKE_STRIPE, FAKE_OPENAI } from '../src/demo.mjs';
import { toMarkdown } from '../src/report.mjs';

const BIN = new URL('../bin/security-review.mjs', import.meta.url).pathname;
const SECURE = new URL('./fixtures/secure-app', import.meta.url).pathname;
const ids = (r, sev) => r.findings.filter((f) => !sev || f.severity === sev).map((f) => f.id);

test('insecure demo app: ranked findings for every category', () => {
  const r = review(buildDemoApp());
  const crit = ids(r, 'critical');
  for (const id of ['SR01', 'SR02', 'SR03', 'SR04', 'SR05', 'SR06', 'SR16']) assert.ok(crit.includes(id), `expected critical ${id}`);
  const high = ids(r, 'high');
  for (const id of ['SR06', 'SR07', 'SR09', 'SR11', 'SR12']) assert.ok(high.includes(id), `expected high ${id}`);
  const med = ids(r, 'medium');
  for (const id of ['SR08', 'SR10', 'SR13', 'SR14']) assert.ok(med.includes(id), `expected medium ${id}`);
  // ranked: severities never go back up
  const order = ['critical', 'high', 'medium', 'low'];
  r.findings.reduce((prev, f) => { assert.ok(order.indexOf(f.severity) >= prev); return order.indexOf(f.severity); }, 0);
  assert.equal(r.grade, 'F');
});

test('secret values never appear in any output', () => {
  const app = buildDemoApp();
  const r = review(app);
  const md = toMarkdown(r);
  const json = JSON.stringify(r);
  for (const s of [FAKE_STRIPE, FAKE_OPENAI, 'demo-value-not-real']) {
    assert.ok(!md.includes(s), 'markdown leaked a value');
    assert.ok(!json.includes(s), 'json leaked a value');
  }
  const term = execFileSync('node', [BIN, app, '--no-color'], { encoding: 'utf8' });
  assert.ok(!term.includes(FAKE_STRIPE) && !term.includes(FAKE_OPENAI));
});

test('well-built fixture is clean', () => {
  const r = review(SECURE, { git: false });
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings, null, 2));
  assert.equal(r.score, 100);
});

test('--fail-on gates CI', () => {
  const bad = spawnSync('node', [BIN, buildDemoApp(), '--fail-on', 'high', '--no-color']);
  assert.equal(bad.status, 1);
  const good = spawnSync('node', [BIN, SECURE, '--no-git', '--fail-on', 'low']);
  assert.equal(good.status, 0);
});

test('report has the expected sections', () => {
  const md = toMarkdown(review(buildDemoApp()));
  for (const h of ['# Security review', '## 🔴 Critical', '## 🟠 High', '## 🟡 Medium', "## What this review can't see", "## Going to production? What this doesn't cover"]) assert.ok(md.includes(h), h);
  assert.match(md, /`app\/api\/checkout\/route\.ts:2`/);
});

test('service_role JWT detected by its role claim, anon JWT ignored', () => {
  const d = mkdtempSync(join(tmpdir(), 'bh-jwt-'));
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role, ref: 'demo' })}.${'s'.repeat(43)}`;
  mkdirSync(join(d, 'lib'));
  writeFileSync(join(d, 'lib', 'a.ts'), `export const anon = '${jwt('anon')}';\n`);
  writeFileSync(join(d, 'lib', 'b.ts'), `export const admin = '${jwt('service_role')}';\n`);
  const r = review(d, { git: false });
  const hits = r.findings.filter((f) => f.id === 'SR01');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].file, 'lib/b.ts');
});

test('Next.js advisories: vulnerable vs patched versions', () => {
  const mk = (v) => { const d = mkdtempSync(join(tmpdir(), 'bh-next-')); writeFileSync(join(d, 'package.json'), JSON.stringify({ dependencies: { next: v } })); writeFileSync(join(d, 'package-lock.json'), '{}'); return review(d, { git: false }).findings.filter((f) => f.id === 'SR16').length; };
  assert.equal(mk('15.4.7'), 1);
  assert.equal(mk('15.2.2'), 2);
  assert.equal(mk('14.2.24'), 1);
  assert.equal(mk('16.0.7'), 0);
  assert.equal(mk('15.5.7'), 0);
  assert.equal(mk('14.2.25'), 0);
});

test('install-skill is a dry run unless --yes', () => {
  const d = mkdtempSync(join(tmpdir(), 'bh-skill-'));
  const out = execFileSync('node', [BIN, 'install-skill', d], { encoding: 'utf8' });
  assert.match(out, /Dry run: nothing was written/);
  assert.deepEqual(readdirSync(d), []);
  execFileSync('node', [BIN, 'install-skill', d, '--target', 'claude', '--yes']);
  assert.deepEqual(readdirSync(join(d, '.claude', 'skills', 'security-review')), ['SKILL.md']);
});
