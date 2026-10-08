// Compiles contracts/aegis_account.fc with the FunC compiler bundled in
// @ton-community/func-js (func + fift as WebAssembly) and writes
//   build/aegis_account.fif       Fift assembly
//   build/aegis_account.code.boc  code cell (BOC)
import { compileFunc, compilerVersion } from '@ton-community/func-js';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const contracts = resolve(here, '..', 'contracts');
const out = resolve(here, '..', 'build');

export async function compile() {
  const result = await compileFunc({
    targets: ['aegis_account.fc'],
    sources: (p) => readFileSync(join(contracts, p)).toString(),
  });
  if (result.status === 'error') throw new Error(result.message);
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const v = await compilerVersion();
  const r = await compile();
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'aegis_account.fif'), r.fiftCode);
  const boc = Buffer.from(r.codeBoc, 'base64');
  writeFileSync(join(out, 'aegis_account.code.boc'), boc);
  console.log(`func ${v.funcVersion}: aegis_account.fc -> ${boc.length} bytes of code BOC`);
  if (r.warnings) console.log(r.warnings);
}
