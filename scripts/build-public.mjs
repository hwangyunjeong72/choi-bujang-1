import { mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

await mkdir(resolve(root, 'public'), { recursive: true });

// 2단계부터는 가상 메모를 정적 public/data.json으로 복사하지 않습니다.
// 이전 빌드 산출물이 남아 있다면 제거하여 /data.json 공개 경로를 없앱니다.
await rm(resolve(root, 'public', 'data.json'), { force: true });

// 심판이 읽는 5단계 설정을 배포 결과물에도 포함합니다.
// aleph.config.json 자체에는 서버 비밀값이 없어 공개해도 됩니다.
const config = await readFile(resolve(root, 'aleph.config.json'), 'utf8');
await writeFile(resolve(root, 'public', 'aleph.config.json'), config, 'utf8');
await writeFile(resolve(root, 'public', 'aleph.json'), config, 'utf8');

console.log('5단계 빌드: aleph.config.json과 aleph.json을 공개 설정 파일로 생성합니다.');
