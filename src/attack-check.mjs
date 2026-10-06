// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 5) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const appResponse = await fetch(new URL('/api/notes', app), {
    headers: { Accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  const originalResponse = await fetch(config.originalApiUrl, {
    headers: { Accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  return [
    {
      attackId: 'anonymous_note_api_read',
      expected: '비로그인 /api/notes 요청은 401로 거부',
      observed: `비로그인 /api/notes 요청 HTTP ${appResponse.status}${appResponse.status === 401 ? '로 거부됨' : '로 응답함'}`,
    },
    {
      attackId: 'anonymous_original_api_read',
      expected: '원본 Supabase 자료 API의 직접 익명 요청은 SQL 권한 회수 후 401 또는 403으로 거부',
      observed: `원본 자료 API 직접 요청 HTTP ${originalResponse.status}${originalResponse.status === 401 || originalResponse.status === 403 ? '로 거부됨' : '로 응답함'}`,
    },
  ];
}
