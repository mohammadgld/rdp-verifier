import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, cp, mkdir, rm, stat, rename } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') {
  throw new Error('This packaging script runs on Windows.');
}

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(project, 'dist');
const folderName = 'RDP-Verifier-Windows';
const bundle = join(dist, folderName);
const archive = join(dist, `${folderName}.zip`);
const electronDist = join(project, 'node_modules', 'electron', 'dist');

if (!resolve(bundle).startsWith(`${resolve(dist)}${sep}`)) {
  throw new Error('Invalid build directory.');
}
await stat(join(electronDist, 'electron.exe'));
await mkdir(dist, { recursive: true });
await rm(bundle, { recursive: true, force: true });
await rm(archive, { force: true });
await cp(electronDist, bundle, { recursive: true });
await rename(join(bundle, 'electron.exe'), join(bundle, 'RDP Verifier.exe'));

const appDirectory = join(bundle, 'resources', 'app');
await mkdir(appDirectory, { recursive: true });
for (const file of ['package.json', 'main.cjs', 'server.mjs']) {
  await copyFile(join(project, file), join(appDirectory, file));
}
for (const directory of ['public', 'src']) {
  await cp(join(project, directory), join(appDirectory, directory), { recursive: true });
}
await copyFile(join(project, 'README.md'), join(bundle, 'README.md'));
await mkdir(join(bundle, 'docs'), { recursive: true });
await copyFile(join(project, 'docs', 'preview.png'), join(bundle, 'docs', 'preview.png'));

const packed = spawnSync('tar', ['-a', '-c', '-f', archive, '-C', dist, folderName], {
  encoding: 'utf8',
  windowsHide: true,
});
if (packed.status !== 0) {
  throw new Error(`ZIP creation failed: ${packed.stderr || packed.stdout}`);
}

const hash = createHash('sha256');
for await (const chunk of createReadStream(archive)) hash.update(chunk);
console.log(`${archive}\nSHA256 ${hash.digest('hex')}`);
