const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'SQL 구문 반복',
    evidence: 'T1190 공개 애플리케이션 악용에서 SQL injection 신호',
    isClear: (text) => /(?:SQL 구문|SQL 표기|SQL 표식|데이터베이스 조회|SELECT|UNION|WHERE|\bOR\b).*?(?:반복|번|회)/i.test(text),
    isAmbiguous: (text) => /(?:따옴표|SQL(?:이라는|인)? .*?(?:한 번|1회|1건)|select(?:라는|인)? .*?(?:한 번|1회|1건))/i.test(text),
  }),
  Object.freeze({
    name: '스크립트 태그 반복',
    evidence: 'T1190 관련 XSS의 스크립트 태그 주입 신호',
    isClear: (text) => /(?:<script\b|스크립트 (?:삽입|태그|表式|표식)).*(?:반복|번|회)/i.test(text),
    isAmbiguous: (text) => /(?:스크립트.*?(?:한 번|1회|1건)|주입처럼 보이는 표기)/i.test(text),
  }),
  Object.freeze({
    name: '경로 상위 이동 반복',
    evidence: 'T1190 관련 path traversal의 상위 경로 이동 신호',
    isClear: (text) => /(?:\.\.\/|경로 (?:상위 이동|거슬러|이탈)).*(?:반복|번|회)/i.test(text),
    isAmbiguous: (text) => /(?:\.\.\/|경로에 up)/i.test(text),
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

function levelOf(alert) {
  const level = Number(alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

function matchedPattern(alert) {
  const text = textOf(alert);
  return PATTERNS.find((pattern) => pattern.isClear(text) || pattern.isAmbiguous(text));
}

export async function decide(alert) {
  if (!hasT1190(alert)) {
    return { action: 'record', confidence: 0.1, reason: '근거 패턴 없음' };
  }

  const text = textOf(alert);
  const pattern = matchedPattern(alert);

  // T1190 고위험 반복 경보는 명확한 공격으로 차단 후보에 둡니다.
  if (levelOf(alert) >= 10) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: pattern?.name ?? '반복 주입 경보',
    };
  }

  // T1190 저강도 단발/불명확 경보는 차단하지 않고 알림만 남깁니다.
  if (levelOf(alert) >= 5) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: pattern?.name ?? '애매한 주입 시도',
    };
  }

  return { action: 'record', confidence: 0.1, reason: '근거 패턴 없음' };
}
