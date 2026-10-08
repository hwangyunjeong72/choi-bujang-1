import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ALERT_LOG = join(ROOT, 'xdr', 'alerts.log');
const DENY_TTL_MS = 60 * 60 * 1000;

function evidenceId(alert) {
  return typeof alert?.id === 'string' ? alert.id : '(unknown-alert)';
}

function sourceAddress(alert) {
  return alert?.data?.srcip ?? null;
}

function account(alert) {
  return alert?.data?.srcuser ?? null;
}

export function toDenyRule(alert, decision, now = new Date()) {
  if (decision?.action !== 'block') return null;
  const source = sourceAddress(alert);
  if (!source) return null;

  const expiresAt = new Date(now.getTime() + DENY_TTL_MS).toISOString();
  return {
    action: 'deny',
    sourceAddress: source,
    ...(account(alert) ? { account: account(alert) } : {}),
    expiresAt,
    evidenceAlertId: evidenceId(alert),
    confidence: decision.confidence,
    reason: decision.reason,
  };
}

export async function respond(alert, decision, now = new Date()) {
  const denyRule = toDenyRule(alert, decision, now);
  const logLine = JSON.stringify({
    timestamp: alert?.timestamp ?? now.toISOString(),
    alertId: evidenceId(alert),
    action: decision?.action ?? 'record',
    confidence: Number(decision?.confidence ?? 0),
    reason: typeof decision?.reason === 'string' ? decision.reason : '판정 없음',
  });
  await mkdir(dirname(ALERT_LOG), { recursive: true });
  await appendFile(ALERT_LOG, logLine + '\n', 'utf8');
  return denyRule;
}

export function shouldDeny(request, rules, now = new Date()) {
  return Array.isArray(rules) && rules.some((rule) =>
    rule?.action === 'deny' &&
    rule?.expiresAt &&
    new Date(rule.expiresAt).getTime() > now.getTime() &&
    rule.sourceAddress === request?.sourceAddress &&
    (!rule.account || rule.account === request?.account)
  );
}
