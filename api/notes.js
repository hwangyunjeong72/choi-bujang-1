import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let verifyLoginAuthorization;

async function authenticate(request) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('missing_server_config');
  verifyLoginAuthorization ??= createLoginVerifier({ config, supabaseSecretKey: key });
  const login = await verifyLoginAuthorization(request.headers.authorization);
  if (!login) return null;
  const supabase = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  return { login, supabase };
}

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

function shape(row) {
  return { id: row.id, title: row.title, body: row.content };
}

export default async function handler(request, response) {
  try {
    const auth = await authenticate(request);
    if (!auth) return response.status(401).json({ error: '로그인이 필요합니다.' });

    if (request.method === 'GET') {
      const { data, error } = await auth.supabase
        .from('learning_notes')
        .select('id,title,content')
        .eq('owner_id', auth.login.userId)
        .order('created_at', { ascending: true });
      if (error) return response.status(500).json({ error: '자료를 불러오지 못했습니다.' });
      response.setHeader('Cache-Control', 'no-store');
      return response.status(200).json(data.map(shape));
    }

    if (request.method === 'POST') {
      const body = await readBody(request);
      if (typeof body.title !== 'string' || typeof body.body !== 'string') {
        return response.status(400).json({ error: 'title과 body가 필요합니다.' });
      }
      const id = body.id === undefined
        ? crypto.randomUUID()
        : (typeof body.id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(body.id) ? body.id : null);
      if (!id) return response.status(400).json({ error: 'id는 UUID여야 합니다.' });

      const { data, error } = await auth.supabase
        .from('learning_notes')
        .insert({ id, title: body.title, content: body.body, owner_id: auth.login.userId })
        .select('id')
        .single();
      if (error) return response.status(500).json({ error: '자료를 추가하지 못했습니다.' });
      return response.status(201).json({ id: data.id });
    }

    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'Method Not Allowed' });
  } catch (error) {
    if (error.message === 'body_too_large') return response.status(413).json({ error: '요청이 너무 큽니다.' });
    if (error.message === 'invalid_json') return response.status(400).json({ error: 'JSON 형식이 올바르지 않습니다.' });
    return response.status(500).json({ error: '자료 API 처리 중 오류가 발생했습니다.' });
  }
}
