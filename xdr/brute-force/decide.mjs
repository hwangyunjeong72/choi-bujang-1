import patterns from './patterns.json' with { type: 'json' };

const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

const [SHORT_BURST, PASSWORD_SPRAY] = patterns.patterns.map((pattern) => pattern.name);

function textOf(alert) {
  return String(alert?.rule?.description ?? '');
}

function hasT1110(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
}

function matchedPattern(alert) {
  const description = textOf(alert);

  if (
    /같은 비밀번호/.test(description)
    && /(여러|서로 다른|계정 \d+개)/.test(description)
  ) {
    return PASSWORD_SPRAY;
  }

  if (
    hasT1110(alert)
    && /(로그인 실패|실패)/.test(description)
  ) {
    return SHORT_BURST;
  }

  return null;
}

function isClearlyNormal(alert) {
  return !hasT1110(alert) && /성공|로그아웃|유지|열렸습니다/.test(textOf(alert));
}

function isClearlyMalicious(alert, patternName) {
  return Boolean(
    hasT1110(alert)
    && patternName
    && Number(alert?.rule?.level) >= 8
  );
}

// Jev is an optional judgement hook. If the runner does not provide it,
// ambiguous events safely fall back to alert as required.
async function askJev(alert, patternName) {
  const judge = globalThis.Jev?.decide;
  if (typeof judge !== 'function') return null;

  const safeAlert = {
    id: alert?.id,
    timestamp: alert?.timestamp,
    rule: {
      level: alert?.rule?.level,
      description: textOf(alert),
      mitre: Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [],
    },
    data: {
      srcip: alert?.data?.srcip,
      srcuser: alert?.data?.srcuser,
    },
  };

  try {
    const result = await judge({
      alert: safeAlert,
      pattern: patternName,
    });

    const confidence = Number(result?.confidence);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      return null;
    }

    return { confidence };
  } catch {
    return null;
  }
}

function decisionFromConfidence(confidence, reason) {
  if (confidence >= BLOCK_THRESHOLD) {
    return { action: 'block', confidence, reason };
  }
  if (confidence >= ALERT_THRESHOLD) {
    return { action: 'alert', confidence, reason };
  }
  return { action: 'record', confidence, reason };
}

export async function decide(alert) {
  const patternName = matchedPattern(alert);

  if (isClearlyNormal(alert)) {
    return {
      action: 'record',
      confidence: 0.99,
      reason: '패턴 불일치',
    };
  }

  if (isClearlyMalicious(alert, patternName)) {
    return {
      action: 'block',
      confidence: 0.99,
      reason: patternName,
    };
  }

  // Pattern signal exists but is not strong enough for an automatic block:
  // ask Jev for confidence. No response means alert.
  if (patternName) {
    const jev = await askJev(alert, patternName);
    if (!jev) {
      return {
        action: 'alert',
        confidence: ALERT_THRESHOLD,
        reason: patternName,
      };
    }
    return decisionFromConfidence(jev.confidence, patternName);
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: '패턴 불일치',
  };
}
