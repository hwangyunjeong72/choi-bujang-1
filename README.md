# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 Deploy 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 본인 계정의 Public 저장소인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

## 현재 저장점 — 5단계 저장점

현재 구현은 **5단계 자료 요청 보호 구조**까지 반영되어 있습니다.

- 로그인한 사용자만 `/api/notes` 자료 API를 사용할 수 있습니다.
- `GET /api/notes`는 서버에서 확인한 로그인 사용자의 자료만 반환합니다.
- `POST /api/notes`는 서버가 확인한 사용자 ID를 `owner_id`로 저장합니다.
- `GET/PUT/DELETE /api/notes/:id`는 서버에서 로그인 사용자와 자료 소유자를 함께 확인합니다.
- 브라우저는 메모 CRUD를 Supabase 테이블에 직접 요청하지 않고 Vercel 서버 함수로 요청합니다.
- 서버 함수는 서버 전용 `SUPABASE_SECRET_KEY`를 사용하며 이 값은 브라우저·Git·응답에 넣지 않습니다.
- `aleph.config.json`의 `step`은 5이며, 원본 자료 API 주소는 `originalApiUrl`에 기록되어 있습니다.
- **직접 테이블 권한 회수 SQL은 학습 DB에서 별도로 적용합니다.** 이 저장점 커밋은 SQL을 대신 실행하지 않습니다.

### 5단계 학습 DB 권한 변경

A의 화면 기능을 유지하면서 브라우저가 원본 테이블에 직접 접근하지 못하게 하려면 학습 DB의 `public.learning_notes`에 대한 `PUBLIC`, `anon`, `authenticated`의 직접 테이블 권한을 회수합니다.

적용 전후 권한은 다음 쿼리로 확인합니다.

```sql
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'learning_notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;

REVOKE ALL PRIVILEGES
ON TABLE public.learning_notes
FROM PUBLIC, anon, authenticated;

SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'learning_notes'
  AND grantee IN ('anon', 'authenticated')
ORDER BY grantee, privilege_type;
```

SQL 적용 후에는 A 화면에서 로그인 → 목록 조회 → 추가 → 수정 → 삭제가 정상인지 확인하고, 원본 API의 익명 직접 요청은 401 또는 403으로 거부되는지 확인합니다.

### 다시 실행

1. Vercel 환경변수에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 설정합니다. 서버 전용 키는 코드와 Git에 넣지 않습니다.
2. 학습 DB에서 위 권한 회수 SQL을 실행하고 적용 전후 결과를 확인합니다.
3. `npm run build`로 빌드합니다.
4. `npm run bundle`로 제출 묶음을 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 제출 묶음 생성용 파일이므로 Git에 커밋하지 않습니다.
5. 로그인 후 자료 추가·조회·수정·삭제가 정상 동작하는지 확인합니다.
6. 비로그인 `/api/notes` 요청은 401이어야 합니다.
7. 원본 Supabase 자료 API에 익명으로 직접 요청했을 때 SQL 적용 후 401 또는 403이어야 합니다.

### 주의

- `originalApiUrl`은 심판이 원본 직접 요청을 확인할 수 있도록 주소만 기록한 것입니다.
- 브라우저에 Supabase 서버 전용 키를 넣지 않습니다.
- 실행하지 않은 점검은 성공으로 기록하지 않습니다.
- `artifacts/submission.json`은 `npm run bundle` 실행 결과이며 Git에 커밋하지 않습니다.
