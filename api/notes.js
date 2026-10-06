import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'Method Not Allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(500).json({ error: '서버 자료 설정이 없습니다.' });
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });

  const { data, error } = await supabase
    .from('learning_notes')
    .select('title,content,created_at')
    .order('created_at', { ascending: true });

  if (error) {
    return response.status(500).json({ error: '가상 자료를 불러오지 못했습니다.' });
  }

  response.setHeader('Cache-Control', 'no-store');
  return response.status(200).json({ notes: data });
}
