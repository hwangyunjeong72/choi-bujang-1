import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);

function safeText(value) {
  if (value === undefined || value === null || value === '') return '(없음)';
  return String(value)
    .replace(/\b(Bearer\s+)\S+/gi, '$1[REDACTED]')
    .replace(/\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/\b[A-F0-9]{32,}\b/gi, '[REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, '[REDACTED]');
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new TypeError('경보 원본에 alerts 배열이 없습니다.');
  return fixture.alerts.map((alert) => ({
    timestamp: safeText(alert.timestamp),
    sourceAddress: safeText(alert.data?.srcip),
    account: safeText(alert.data?.srcuser),
    ruleLevel: alert.rule?.level ?? '(없음)',
    description: safeText(alert.rule?.description),
  }));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  const rows = await readAlerts();
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (rows.length !== fixture.alerts.length) {
    throw new Error(`경보 건수(${fixture.alerts.length})와 추출 줄 수(${rows.length})가 다릅니다.`);
  }
  process.stdout.write(rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''));
}
