const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'SQL 구문 반복',
    evidence: 'T1190 공개 애플리케이션 악용에서 SQL injection 신호',
    test: /(?:SQL 구문|SQL 표기|SQL 표식|데이터베이스 조회|SELECT|UNION|WHERE|\bOR\b).*?(?:반복|번|회)/i,
    repeat: (text, count) => count >= 2 || /SQL (?:구문|표기|표식).*?반복/i.test(text) || /데이터베이스 조회.*?(?:반복|번|회)/i.test(text),
    weak: /(?:따옴표|SQL(?:이라는|인)? .*?(?:한 번|1회|1건)|select(?:라는|인)? .*?(?:한 번|1회|1건))/i
  }),
  Object.freeze({
    name: '스크립트 태그 반복',
    evidence: 'T1190 관련 XSS의 스크립트 태그 주입 신호',
    test: /(?:<script\b|스크립트 (?:삽입|태그|표식)).*(?:반복|번|회)/i,
    repeat: (text, count) => count >= 2 || /스크립트 (?:삽입|태그|표식).*?(?:반복|번|회)/i.test(text),
    weak: /(?:스크립트.*?(?:한 번|1회|1건)|주입처럼 보이는 표기)/i
  }),
  Object.freeze({
    name: '경로 상위 이동 반복',
    evidence: 'T1190 관련 path traversal의 상위 경로 이동 신호',
    test: /(?:\.\.\/|경로 (?:상위 이동|거슬러|이탈)).*(?:반복|번|회)/i,
    repeat: (text, count) => count >= 2 || /경로 (?:상위 이동|거슬러|이탈).*?(?:반복|번|회)/i.test(text),
    weak: /(?:\.\.\/|경로에 up)/i
  })
]);

function textOf(alert) {
  return [alert?.data?.url, alert?.rule?.description, alert?.description].filter(Boolean).join(' ');
}

function hasT1190(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
}

function countOf(alert) {
  const n = Number(alert?.data?.count);
  return Number.isFinite(n) ? n : 0;
}

function matchedPattern(alert) {
  const text = textOf(alert);
  const count = countOf(alert);
  return PATTERNS.find((pattern) =>
    pattern.test.test(text) || pattern.weak.test(text) || pattern.repeat(text, count)
  );
}

export async function decide(alert) {
  const pattern = matchedPattern(alert);

  if (!hasT1190(alert) || !pattern) {
    return { action: 'record', confidence: 0.1, reason: '근거 패턴 없음' };
  }

  const text = textOf(alert);
  const count = countOf(alert);

  if (pattern.repeat(text, count)) {
    return { action: 'block', confidence: 0.95, reason: pattern.name };
  }

  return { action: 'alert', confidence: 0.6, reason: pattern.name };
}
