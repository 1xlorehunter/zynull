import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const name = process.argv[2] ?? 'normal';
if (!['normal', 'exit'].includes(name)) throw new Error('unknown circuit');
const flatten = spawnSync(process.execPath, ['scripts/flatten-circom.mjs', name], { stdio: 'inherit' });
if (flatten.status !== 0) process.exit(flatten.status || 1);
const local = resolve('.tools/circom.exe');
const native = process.platform === 'win32' && existsSync(local);
const optimization = ['--O2'];
const build = native
  ? spawnSync(local, [`build/${name}_flat.circom`, '--r1cs', '--wasm', '--sym', ...optimization, '-o', 'build'], { stdio: 'inherit' })
  : spawnSync(process.execPath, ['../node_modules/circom2/cli.js', `${name}_flat.circom`, '--r1cs', '--wasm', '--sym', ...optimization, '-o', '.'], { cwd: 'build', stdio: 'inherit' });
if (build.error) {
  console.error(`Circom compiler not available: ${build.error.message}`);
  process.exit(1);
}
process.exit(build.status || 0);
