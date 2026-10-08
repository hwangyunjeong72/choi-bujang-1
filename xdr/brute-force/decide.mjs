const ALERT_THRESHOLD = 0.5;
const CLEAR_FAILURE_COUNT = 15;

const SHORT_BURST = '짧은 시간 같은 주소의 연속 로그인 실패';
const PASSWORD_SPRAY = '여러 계정에 같은 비밀번호 대입';

function textOf(alert) {
  return String(alert?.rule?.description ?? '');
}

function hasT1110(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
}

function failureCount(alert) {
  const dataCount = Number(alert?.data?.count);
  if (Number.isFinite(dataCount)) return dataCount;
  const match = textOf(alert).match(/실패(?:가| )\s*(\d+)건|실패\s*(\d+)건/);
  return Number(match?.[1] ?? match?.[2] ?? 0);
}

function matchedPattern(alert) {
  const description = textOf(alert);
  if (/같은 비밀번호/.test(description) && /(여러|서로 다른|계정 \d+개)/.test(description)) {
    return PASSWORD_SPRAY;
  }
  if (hasT1110(alert) && /(로그인 실패|실패)/.test(description)) {
    return SHORT_BURST;
  }
  return null;
}

function isClearlyNormal(alert) {
  return !hasT1110(alert) && /성공|로그아웃|유지|열렸습니다/.test(textOf(alert));
}

function isClearlyMalicious(alert, patternName) {
  if (!hasT1110(alert)) return false;
  if (patternName === PASSWORD_SPRAY) return true;
  return failureCount(alert) >= CLEAR_FAILURE_COUNT;
}

export async function decide(alert) {
  const patternName = matchedPattern(alert);

  if (isClearlyNormal(alert)) {
    return { action: 'record', confidence: 0.99, reason: '패턴 불일치' };
  }

  if (isClearlyMalicious(alert, patternName)) {
    return {
      action: 'block',
      confidence: 0.99,
      reason: patternName ?? '명확한 T1110 공격',
    };
  }

  if (patternName) {
    return { action: 'alert', confidence: ALERT_THRESHOLD, reason: patternName };
  }

  return { action: 'record', confidence: 0.1, reason: '패턴 불일치' };
}
