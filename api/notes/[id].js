import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

let verifyLoginAuthorization;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

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
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return response.status(500).json({ error: '서버 자료 설정이 없습니다.' });

  try {
    verifyLoginAuthorization ??= createLoginVerifier({ config, supabaseSecretKey: key });
    const login = await verifyLoginAuthorization(request.headers.authorization);
    if (!login) return response.status(401).json({ error: '로그인이 필요합니다.' });

    const id = request.query.id;
    if (!UUID.test(id || '')) return response.status(400).json({ error: 'id는 UUID여야 합니다.' });

    const supabase = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });

    if (request.method === 'GET') {
      const { data, error } = await supabase.from('learning_notes')
        .select('id,title,content').eq('id', id).maybeSingle();
      if (error) return response.status(500).json({ error: '자료를 불러오지 못했습니다.' });
      if (!data) return response.status(404).json({ error: '자료를 찾을 수 없습니다.' });
      return response.status(200).json({ id: data.id, title: data.title, body: data.content });
    }

    if (request.method === 'PUT') {
      const body = await readBody(request);
      if (typeof body.title !== 'string' || typeof body.body !== 'string') {
        return response.status(400).json({ error: 'title과 body가 필요합니다.' });
      }
      const { data, error } = await supabase.from('learning_notes')
        .update({ title: body.title, content: body.body }).eq('id', id)
        .select('id,title,content').maybeSingle();
      if (error) return response.status(500).json({ error: '자료를 수정하지 못했습니다.' });
      if (!data) return response.status(404).json({ error: '자료를 찾을 수 없습니다.' });
      return response.status(200).json({ id: data.id, title: data.title, body: data.content });
    }

    if (request.method === 'DELETE') {
      const { data, error } = await supabase.from('learning_notes')
        .delete().eq('id', id).select('id').maybeSingle();
      if (error) return response.status(500).json({ error: '자료를 삭제하지 못했습니다.' });
      if (!data) return response.status(404).json({ error: '자료를 찾을 수 없습니다.' });
      return response.status(204).end();
    }

    response.setHeader('Allow', 'GET, PUT, DELETE');
    return response.status(405).json({ error: 'Method Not Allowed' });
  } catch (error) {
    if (error.message === 'body_too_large') return response.status(413).json({ error: '요청이 너무 큽니다.' });
    if (error.message === 'invalid_json') return response.status(400).json({ error: 'JSON 형식이 올바르지 않습니다.' });
    return response.status(500).json({ error: '자료 API 처리 중 오류가 발생했습니다.' });
  }
}
