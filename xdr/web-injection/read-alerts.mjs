import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);

// 출력 필드에 비밀값처럼 보이는 문자열이 들어오면 가립니다.
function safeText(value) {
  if (value === undefined || value === null || value === '') return '(없음)';
  return String(value)
    .replace(/\b(Bearer\s+)\S+/gi, '$1[REDACTED]')
    .replace(/\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/\b[A-F0-9]{32,}\b/gi, '[REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, '[REDACTED]');
}

/**
 * Wazuh 형태의 web-injection 경보에서 허용된 5개 필드만 읽습니다.
 * 원본 fixture는 수정하지 않습니다.
 */
export async function readAlerts() {
  const raw = await readFile(fixtureUrl, 'utf8');
  const fixture = JSON.parse(raw);

  if (!Array.isArray(fixture.alerts)) {
    throw new TypeError('경보 원본에 alerts 배열이 없습니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: safeText(alert.timestamp),
    sourceAddress: safeText(alert.data?.srcip),
    account: safeText(alert.data?.srcuser),
    ruleLevel: alert.rule?.level ?? '(없음)',
    description: safeText(alert.rule?.description),
  }));
}

// 직접 실행하면 원본 경보 하나당 정확히 한 줄을 출력합니다.
const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const rows = await readAlerts();
    const raw = JSON.parse(await readFile(fixtureUrl, 'utf8'));

    if (rows.length !== raw.alerts.length) {
      throw new Error(
        `경보 건수(${raw.alerts.length})와 추출 줄 수(${rows.length})가 다릅니다.`,
      );
    }

    process.stdout.write(
      rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''),
    );
  } catch (error) {
    console.error(`경보 읽기 실패: ${error.message}`);
    process.exitCode = 1;
  }
}
