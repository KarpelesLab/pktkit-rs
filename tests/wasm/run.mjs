// Run the smoke module: node run.mjs <module.wasm>
//
// Supplies what a browser page would for wasm32-unknown-unknown (the pktkit
// clock imports and purecrypto's entropy import), or WASI for wasm32-wasip1,
// then plays the host event loop: pktkit has no threads here, so nothing
// happens between calls unless we make the calls.
import fs from 'node:fs';
import { webcrypto } from 'node:crypto';
import { WASI } from 'node:wasi';

const bytes = fs.readFileSync(process.argv[2]);
const module = await WebAssembly.compile(bytes);
const wanted = new Set(WebAssembly.Module.imports(module).map((i) => i.module));
let memory;
const view = (ptr, len) => new Uint8Array(memory.buffer, ptr, len);

const imports = {
  env: { log: (ptr, len) => console.log(new TextDecoder().decode(view(ptr, len))) },
  pktkit: { now_ms: () => performance.now(), unix_ms: () => Date.now() },
  purecrypto: { random_get: (ptr, len) => { webcrypto.getRandomValues(view(ptr, len)); } },
};
const wasi = wanted.has('wasi_snapshot_preview1') ? new WASI({ version: 'preview1' }) : null;
if (wasi) imports.wasi_snapshot_preview1 = wasi.wasiImport;

const instance = await WebAssembly.instantiate(module, imports);
memory = instance.exports.memory;
if (wasi) wasi.initialize(instance);
console.log('imports:', [...wanted].sort().join(', '));

const x = instance.exports;
const fail = (what, code) => { console.error(`FAIL: ${what} returned ${code}`); process.exit(1); };
for (const name of ['wg_handshake', 'pcap_timestamp', 'tcp_start']) {
  const r = x[name]();
  if (r !== 1) fail(name, r);
}
const deadline = Date.now() + 60_000;
for (;;) {
  const r = x.tcp_step();
  if (r === 1) break;
  if (r < 0) fail('tcp_step', r);
  if (Date.now() > deadline) { console.error('FAIL: transfer did not finish within 60s'); process.exit(1); }
  await new Promise((resolve) => setTimeout(resolve, 2));
}
console.log('ok');
