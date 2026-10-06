import { createClient } from '@supabase/supabase-js';

function readBody(request) {
  return new Promise((resolve, reject) => {
    let raw = '';
    request.on('data', chunk => {
      raw += chunk;
      if (raw.length > 100000) reject(new Error('body_too_large'));
    });
    request.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('invalid_json')); }
    });
    request.on('error', reject);
  });
}

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'Method Not Allowed' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return response.status(500).json({ error: '서버 인증 설정이 없습니다.' });

  try {
    const body = await readBody(request);
    const supabase = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });

    if (body.action === 'login') {
      if (typeof body.email !== 'string' || typeof body.password !== 'string'
          || !body.email.trim() || !body.password) {
        return response.status(400).json({ error: '이메일과 비밀번호가 필요합니다.' });
      }

      const { data, error } = await supabase.auth.signInWithPassword({
        email: body.email.trim(),
        password: body.password
      });

      if (error || !data.session || !data.user) {
        return response.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
      }

      return response.status(200).json({
        session: {
          access_token: data.session.access_token,
          refresh_token: data.session.refresh_token,
          expires_at: data.session.expires_at,
          user: { id: data.user.id, email: data.user.email }
        }
      });
    }

    if (body.action === 'refresh') {
      if (typeof body.refresh_token !== 'string' || !body.refresh_token) {
        return response.status(401).json({ error: '로그인 세션이 없습니다.' });
      }

      const { data, error } = await supabase.auth.refreshSession({
        refresh_token: body.refresh_token
      });

      if (error || !data.session || !data.user) {
        return response.status(401).json({ error: '로그인 세션이 만료되었습니다.' });
      }

      return response.status(200).json({
        session: {
          access_token: data.session.access_token,
          refresh_token: data.session.refresh_token,
          expires_at: data.session.expires_at,
          user: { id: data.user.id, email: data.user.email }
        }
      });
    }

    return response.status(400).json({ error: '지원하지 않는 인증 요청입니다.' });
  } catch (error) {
    if (error.message === 'body_too_large') return response.status(413).json({ error: '요청이 너무 큽니다.' });
    if (error.message === 'invalid_json') return response.status(400).json({ error: 'JSON 형식이 올바르지 않습니다.' });
    return response.status(500).json({ error: '인증 처리 중 오류가 발생했습니다.' });
  }
}
