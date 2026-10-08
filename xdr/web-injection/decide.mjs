import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const patternsUrl = new URL('./patterns.json', import.meta.url);

const BLOCK_CONFIDENCE = 0.95;
const ALERT_CONFIDENCE = 0.5;
const RECORD_CONFIDENCE = 0.1;

async function loadPatterns() {
  const raw = await readFile(patternsUrl, 'utf8');
  const data = JSON.parse(raw);

  if (!Array.isArray(data.patterns)) {
    throw new TypeError('patterns.json에 patterns 배열이 없습니다.');
  }

  return data.patterns;
}

function requestText(alert) {
  return [
    alert?.data?.url,
    alert?.rule?.description,
    alert?.description,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function countSignals(alert, patternName) {
  const text = requestText(alert);
  const count = Number.parseInt(alert?.data?.count, 10);

  if (Number.isFinite(count)) return count;

  if (patternName === 'SQL 구문 반복') {
    return (text.match(/sql|select|union|where|\bor\b|데이터베이스\s*조회/gi) || []).length;
  }

  if (patternName === '스크립트 태그 반복') {
    return (text.match(/<script\b|script\s*tag|스크립트.*(?:삽입|태그).*표/gi) || []).length;
  }

  if (patternName === '경로 상위 이동 반복') {
    return (text.match(/\.\.\//g) || []).length;
  }

  return 0;
}

function matchedPatterns(alert, patterns) {
  const text = requestText(alert);

  return patterns.filter((pattern) => {
    if (pattern.name === 'SQL 구문 반복') {
      return /sql\s*(?:구문|표기)|select|union|where|\bor\b|데이터베이스\s*조회/i.test(text);
    }

    if (pattern.name === '스크립트 태그 반복') {
      return /<script\b|script\s*tag|스크립트.*(?:삽입|태그).*표/i.test(text);
    }

    if (pattern.name === '경로 상위 이동 반복') {
      return /\.\.\//.test(text) || /경로.*거슬러|경로.*이탈|상위.*이동/i.test(text);
    }

    return false;
  });
}

async function askJev(alert, matched) {
  try {
    const jev = globalThis.Jev ?? globalThis.jev;

    if (!jev || typeof jev.decide !== 'function') {
      return null;
    }

    const response = await jev.decide({
      alert,
      patterns: matched.map((pattern) => pattern.name),
    });

    const confidence =
      typeof response === 'number'
        ? response
        : Number(response?.confidence);

    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      return null;
    }

    return confidence;
  } catch {
    return null;
  }
}

export async function decide(alert) {
  const patterns = await loadPatterns();
  const matched = matchedPatterns(alert, patterns);

  if (matched.length === 0) {
    return {
      action: 'record',
      confidence: RECORD_CONFIDENCE,
      reason: '근거 패턴 없음',
    };
  }

  const clearPattern = matched.find(
    (pattern) => countSignals(alert, pattern.name) >= 2,
  );

  if (clearPattern) {
    return {
      action: 'block',
      confidence: BLOCK_CONFIDENCE,
      reason: clearPattern.name,
    };
  }

  const jevConfidence = await askJev(alert, matched);

  if (jevConfidence === null) {
    return {
      action: 'alert',
      confidence: ALERT_CONFIDENCE,
      reason: matched[0].name,
    };
  }

  if (jevConfidence >= 0.85) {
    return {
      action: 'block',
      confidence: jevConfidence,
      reason: matched[0].name,
    };
  }

  if (jevConfidence >= 0.5) {
    return {
      action: 'alert',
      confidence: jevConfidence,
      reason: matched[0].name,
    };
  }

  return {
    action: 'record',
    confidence: jevConfidence,
    reason: matched[0].name,
  };
}

// 직접 실행하지 않고, XDR 실행기에서 decide(alert)를 호출합니다.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('web-injection decide 모듈: decide(alert)를 export합니다.');
}
