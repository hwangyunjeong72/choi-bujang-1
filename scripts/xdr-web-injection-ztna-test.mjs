import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDenyRules, shouldDeny } from '../xdr/web-injection/ztna-bridge.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const fixture = JSON.parse(
  await readFile(join(root, 'xdr', 'fixtures', 'web-injection.json'), 'utf8'),
);
const now = new Date('2026-10-08T00:00:00.000Z');

const ruleSet = await buildDenyRules(fixture.alerts, now);
const clearAttackIds = new Set(['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-07', 'wi-08']);
const clearAttacks = fixture.alerts.filter((alert) => clearAttackIds.has(alert.id));

assert.equal(
  ruleSet.rules.length,
  clearAttacks.length,
  '명확한 공격만 차단 후보가 되어야 합니다.',
);

for (const rule of ruleSet.rules) {
  assert.equal(rule.action, 'deny');
  assert.ok(rule.expiresAt);
  assert.ok(rule.evidenceAlertId);
  assert.ok(rule.confidence >= 0.85);
}

const normal = fixture.alerts.find((alert) => alert.id === 'wi-18');
assert.equal(
  shouldDeny(
    {
      sourceAddress: normal.data.srcip,
      account: normal.data.srcuser,
    },
    ruleSet,
    now,
  ),
  false,
  '정상 사용자는 차단 규칙에 포함되면 안 됩니다.',
);

const attack = fixture.alerts.find((alert) => alert.id === 'wi-01');
assert.equal(
  shouldDeny(
    { sourceAddress: attack.data.srcip, account: attack.data.srcuser },
    ruleSet,
    now,
  ),
  true,
  '명확한 공격은 차단되어야 합니다.',
);

const expired = { ...ruleSet.rules[0], expiresAt: '2026-10-07T23:59:59.000Z' };
assert.equal(
  shouldDeny(
    { sourceAddress: expired.sourceAddress, account: expired.account },
    { ...ruleSet, rules: [expired] },
    now,
  ),
  false,
  '만료된 거부 규칙은 적용되면 안 됩니다.',
);

process.stdout.write(
  `웹 주입 ZTNA 연결 시험 통과 · 차단 후보 ${ruleSet.rules.length}건 · 정상 요청 통과 · 만료 규칙 무시\n`,
);
