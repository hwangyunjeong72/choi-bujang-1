import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

if (config.step !== 2) {
  throw new Error('2단계 설정을 확인하세요.');
}

await mkdir(resolve(root, 'public'), { recursive: true });

// 2단계부터는 가상 메모를 정적 public/data.json으로 복사하지 않습니다.
// 이전 빌드 산출물이 남아 있다면 제거하여 /data.json 공개 경로를 없앱니다.
await rm(resolve(root, 'public', 'data.json'), { force: true });

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8',
  );
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
