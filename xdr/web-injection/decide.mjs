const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'SQL 구문 반복',
    evidence: 'T1190 공개 애플리케이션 악용에서 SQL injection 신호',
    isMatch: (text) => /(?:SQL 구문|SQL 표기|SQL 표식|데이터베이스 조회|SELECT|UNION|WHERE|\bOR\b).*?(?:반복|번|회)/i.test(text),
  }),
  Object.freeze({
    name: '스크립트 태그 반복',
    evidence: 'T1190 관련 XSS의 스크립트 태그 주입 신호',
    isMatch: (text) => /(?:<script\b|스크립트 (?:삽입|태그|표식)).*?(?:반복|번|회)/i.test(text),
  }),
  Object.freeze({
    name: '경로 상위 이동 반복',
    evidence: 'T1190 관련 path traversal의 상위 경로 이동 신호',
    isMatch: (text) => /(?:\.\.\/|경로 (?:상위 이동|거슬러|이탈)).*?(?:반복|번|회)/i.test(text),
  }),
]);

function textOf(alert) {
  return [alert?.data?.url, alert?.rule?.description, alert?.description]
    .filter(Boolean)
    .join(' ');
}

function hasT1190(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
}

function matchedPattern(alert) {
  const text = textOf(alert);
  return PATTERNS.find((pattern) => pattern.isMatch(text));
}

export async function decide(alert) {
  const pattern = matchedPattern(alert);

  if (!hasT1190(alert) || !pattern) {
    return { action: 'record', confidence: 0.1, reason: '근거 패턴 없음' };
  }

  return {
    action: 'block',
    confidence: 0.95,
    reason: pattern.name,
  };
}
