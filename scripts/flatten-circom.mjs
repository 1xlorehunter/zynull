import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

// Windows builds of Circom can fail to resolve includes. Flatten only for the
// build artifact; the source circuit keeps normal, auditable includes.
const name = process.argv[2] ?? 'normal';
if (!['normal', 'exit'].includes(name)) throw new Error('unknown circuit');
const root = resolve(`circuits/${name}.circom`);
const out = resolve(`build/${name}_flat.circom`);
const seen = new Set();
function flatten(file, isRoot = false) {
  const absolute = realpathSync(file);
  if (seen.has(absolute)) return '';
  seen.add(absolute);
  return readFileSync(absolute, 'utf8').split(/\r?\n/).map((line) => {
    const include = line.match(/^\s*include\s+"([^"]+)"\s*;/);
    if (include) {
      const candidate = join(dirname(absolute), include[1]);
      const dependency = existsSync(candidate) ? candidate : resolve('node_modules', include[1]);
      if (!existsSync(dependency)) throw new Error(`Missing Circom dependency: ${include[1]}`);
      return flatten(dependency);
    }
    if (!isRoot && /^\s*pragma circom\b/.test(line)) return '';
    return line;
  }).join('\n');
}
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, flatten(root, true));
console.log(`Flattened ${seen.size} source files into ${out}`);
