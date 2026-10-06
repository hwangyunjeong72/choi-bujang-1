import { mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

await mkdir(resolve(root, 'public'), { recursive: true });

// 2단계부터는 가상 메모를 정적 public/data.json으로 복사하지 않습니다.
// 이전 빌드 산출물이 남아 있다면 제거하여 /data.json 공개 경로를 없앱니다.
await rm(resolve(root, 'public', 'data.json'), { force: true });

console.log('2단계 빌드: 공개 data.json 복사를 하지 않습니다.');
