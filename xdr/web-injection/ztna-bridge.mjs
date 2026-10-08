import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_FILE = join(MODULE_DIR, 'deny-rules.json');
const DEFAULT_LOG_FILE = join(MODULE_DIR, '..', 'alerts.log');

const RULE_TTL_MS = 60 * 60 * 1000;

function sourceAddress(alert) {
  return typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '';
}

function account(alert) {
  return typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '';
}

function toIso(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError('유효하지 않은 시각입니다.');
  return date.toISOString();
}

export async function buildDenyRules(alerts, now = new Date(), ttlMs = RULE_TTL_MS) {
  if (!Array.isArray(alerts)) throw new TypeError('경보 배열이 필요합니다.');
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError('규칙 만료 시간이 올바르지 않습니다.');
  }

  const createdAt = toIso(now);
  const expiresAt = toIso(new Date(new Date(createdAt).getTime() + ttlMs));
  const rules = [];

  for (const alert of alerts) {
    const result = await decide(alert);

    // block 후보만 ZTNA 거부 규칙으로 연결합니다.
    if (result.action !== 'block' || result.confidence < 0.85) continue;

    const srcip = sourceAddress(alert);
    if (!alert?.id || !srcip) continue;

    rules.push({
      ruleId: `xdr.web_injection.${alert.id}`,
      action: 'deny',
      sourceAddress: srcip,
      account: account(alert),
      createdAt,
      expiresAt,
      evidenceAlertId: alert.id,
      reason: result.reason,
      confidence: result.confidence,
    });
  }

  return {
    schema: 'aleph.xdr.ztna-deny-rules.v1',
    generatedAt: createdAt,
    rules,
  };
}

export function shouldDeny(request, ruleSet, now = new Date()) {
  const at = new Date(now).getTime();
  if (!Number.isFinite(at) || !ruleSet || !Array.isArray(ruleSet.rules)) return false;

  return ruleSet.rules.some((rule) => {
    const expiresAt = new Date(rule.expiresAt).getTime();
    const sameSource = request?.sourceAddress === rule.sourceAddress;
    const sameAccount =
      !rule.account || request?.account === rule.account;

    return rule.action === 'deny'
      && Number.isFinite(expiresAt)
      && at < expiresAt
      && sameSource
      && sameAccount;
  });
}

export async function appendAlertsLog(alerts, logFile = DEFAULT_LOG_FILE) {
  if (!Array.isArray(alerts)) throw new TypeError('경보 배열이 필요합니다.');

  const lines = [];
  for (const alert of alerts) {
    const result = await decide(alert);

    lines.push(JSON.stringify({
      timestamp: alert?.timestamp ?? null,
      alertId: alert?.id ?? null,
      action: result.action,
      confidence: result.confidence,
      reason: result.reason,
    }));
  }

  if (lines.length) {
    await appendFile(logFile, lines.join('\n') + '\n', 'utf8');
  }
}

export async function connectWebInjection({
  fixtureFile,
  rulesFile = DEFAULT_RULES_FILE,
  logFile = DEFAULT_LOG_FILE,
  now = new Date(),
}) {
  const fixture = JSON.parse(await readFile(fixtureFile, 'utf8'));

  if (
    !fixture
    || fixture.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'web-injection'
    || !Array.isArray(fixture.alerts)
  ) {
    throw new Error('웹 주입 경보 묶음 형식이 아닙니다.');
  }

  const ruleSet = await buildDenyRules(fixture.alerts, now);
  await writeFile(rulesFile, JSON.stringify(ruleSet, null, 2) + '\n', 'utf8');
  await appendAlertsLog(fixture.alerts, logFile);
  return ruleSet;
}
