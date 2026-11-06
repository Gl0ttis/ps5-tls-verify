# ps5-tls-verify

Toggleable TLS verifier override for PS5. A single standalone `pldmgr`
payload that walks every live process on the system, patches the
primary certificate-chain verifier in each of the TLS libraries it has
loaded, and then stays resident to catch newly-spawned processes.

- **First run**: patches every covered verifier site in every process
  that currently has one of the TLS libraries loaded. Stays resident
  as a watch loop that re-patches newly-spawned candidates every ~1 s.
- **Second run** (after a first run): detects that the system is
  already patched by **majority rule** and flips everything back to
  pristine. Exits the watch loop afterwards.
- **Third run**: patches again, re-enters the watch loop.
- At any time: reboot restores everything to pristine (patches live in
  RAM only).

Firmware-agnostic — no hard-coded SPRX offsets. See [Resolution](#resolution)
below.

**This is a verifier bypass, not a trust extension.** The patched
functions no longer walk the certificate chain or consult the system
trust store. Use only on an isolated network.

---

## What it covers

Four TLS libraries, patched per-process:

| Library | Target | Resolution | Patch |
|---|---|---|---|
| `libSceSsl.sprx` | inner chain-verifier function (`FUN_801e6d020` on 13.20) | `kernel_dynlib_mapbase_addr` + signature scan for the unique `0x8095F00C` immediate; pattern-based locator for the four inner patch sites | **4 inner sites** per process (P1/P2/P3/P4) |
| `libSceLibreSsl.sprx` | `X509_verify_cert` | `kernel_dynlib_dlsym` by name | 6-byte entry stub `B8 01 00 00 00 C3` (`MOV EAX, 1 ; RET`) |
| `libSceLibreSsl3.sprx` | `X509_verify_cert` | `kernel_dynlib_dlsym` by name | 6-byte entry stub |
| `libmono-btls-shared.sprx` | BoringSSL `X509_verify_cert` (statically linked, not exported) | Read exported thunk `mono_btls_x509_store_ctx_verify_cert`, decode its `jmp rel32` to reach the real function | 6-byte entry stub |

### The four libSceSsl inner sites

An entry stub on the chain verifier would be insufficient here:
the function mutates error-flag state in a caller-owned struct, and
the caller inspects that state independently of the function's return
value. The 4-site inner patch reshapes control flow so the
`UNKNOWN_CA` bit (0x20 in the error-flag field) is never set:

| Site | Pristine | Patched | Semantic effect |
|---|---|---|---|
| P1 | `0f 84 rel32` (JZ long) | 6× `0x90` | Force the trust walk even when the "force-verify" flag is clear |
| P2 | `74 06` (JZ rel8) over an `OR BYTE [R12+disp8], 0x20` | `eb 06` | Unconditionally skip the inline UNKNOWN_CA bit-set |
| P3 | `0f 85 rel32` (JNZ long, backward) | 6× `0x90` | Never jump back into the register-OR-sets-0x20 path |
| P4 | `74 2a` (JZ rel8) over a 42-byte callback-error block | `eb 2a` | Unconditionally skip the custom-callback error-emit path |

### Why libSceSsl is patched per-process

`libSceSsl.rx` is shared-mapped at the memory-layout level, but
`kernel_proc_copyin` (which is what this payload uses) goes through
`proc_rwmem`, which operates on the target proc's vmspace and triggers
copy-on-write — patches land only in the process they were written
against. (`PT_IO` goes through the shared backing instead and would
propagate; the SDK does not expose that path without a ptrace attach.)
The payload therefore iterates every candidate process and writes the
4 libSceSsl sites in each one individually. The expensive pattern
search runs only once (in the first pid that has libSceSsl loaded);
the resulting four `.rx` offsets are cached and reused as
`base + offset` for every other pid.

### Thunk decoding for libmono-btls-shared

Mono's TLS backend (BoringSSL-based) is statically linked into
`libmono-btls-shared.sprx`, so the real `X509_verify_cert` is not an
exported symbol. The exported wrapper is a 9-byte tail-call thunk:

```
48 8b 7f 08          mov rdi, [rdi+8]
e9 XX XX XX XX       jmp rel32  →  real X509_verify_cert
```

The payload resolves the thunk via `dlsym`, reads its bytes, decodes
the `rel32`, and patches the real function's entry.

### Resolution — firmware-agnostic locators

**libSceSsl**: the chain verifier is not exported. Locate it at
runtime without hard-coded firmware offsets:

1. `kernel_dynlib_mapbase_addr` gives the `.rx` base.
2. Scan the `.rx` for the unique immediate `B8 0C F0 95 80`
   (`MOV EAX, 0x8095F00C` — the `UNKNOWN_CA` error constant). This
   appears exactly once in `libSceSsl.rx`.
3. Walk backward to the standard function prologue
   `55 48 89 E5 41 57`. That is the verifier entry.
4. Scan the function body (up to 2 pages forward) for each of the four
   patch sites by its **semantic prefix**:

   | Site | Prefix pattern (pristine / patched) |
   |---|---|
   | P1 | `41 8b 44 24 ?? a8 01 { 0f 84 r r r r \| 90 90 90 90 90 90 }` — `MOV EAX, [R12+disp]; TEST AL, 0x01; JZ-long or NOP-sled` |
   | P2 | `{ 74 06 \| eb 06 } 41 80 4c 24 ?? 20` — short-JZ-skip followed by `OR BYTE [R12+disp], 0x20` |
   | P3 | `b8 20 00 00 00 { 0f 85 r r r r \| 90 90 90 90 90 90 }` — `MOV EAX, 0x20` followed by JNZ-long or NOP-sled |
   | P4 | `{ 74 r \| eb r } 41 83 7c 24 ?? ??` — short-JZ-skip followed by `CMP DWORD [R12+disp], imm8` |

5. Each site must match exactly once in the function body; otherwise
   the payload bails without writing anything. A future firmware
   change that moves any site surfaces as "`libSceSsl: ambiguous site
   count — bailing`" in klog, not as a wrong-bytes patch.

For both LibreSSL variants, `X509_verify_cert` is an exported symbol
with a preserved strtab, so `kernel_dynlib_dlsym` by name resolves it
on any firmware where the API name is kept.

### P1/P3 restore and the state file

P2 and P4 are 2-byte opcode flips (`74 ↔ eb`, rel8 preserved) so a
restore run can reconstruct them by inspection. P1 and P3 overwrite
the `rel32` bytes of the pristine `JZ`/`JNZ` with a NOP sled, which
isn't reversible from the patched form alone.

To support toggle-back without a reboot, the payload saves the P1/P3
pristine 12 bytes to `/data/ps5-tls-verify.state` on the patch pass
and reads it on the restore pass. If the state file is missing when a
restore is requested, the payload still restores P2/P4 and the
LibreSSL/mono-btls entry stubs; P1/P3 are left as NOPs and klog says
"P1/P3 restore skipped — reboot to fully revert".

### Watch mode and single-instance guard

After a successful patch pass the payload stays resident and enters a
watch loop that polls `allproc` every ~1 s for the candidate process
names. Any pid it hasn't seen before gets a one-off patch pass for its
per-process TLS libraries (including the libSceSsl 4-site patch —
remember, that's per-process under `kernel_proc_copyin`). This closes
the drift gap where a process spawning after the initial run would
otherwise come up pristine.

Only one watcher runs at a time. On startup the payload reads
`/data/ps5-tls-verify.pid`, SIGTERMs any prior instance named in it,
waits up to 5 s for it to exit, then writes its own pid. The watch
loop exits cleanly on SIGTERM / reboot.

A **restore** run (patched → pristine) does not enter the watch loop,
so toggling verify back on also stops the watcher.

### Cross-process memory access

All reads and writes to target processes go through the SDK's
`kernel_proc_copyout` / `kernel_proc_copyin`, which operate directly
in the kernel (via `proc_rwmem` on the target proc's vmspace). There
is no `PT_ATTACH`, no `PT_IO`, no target stop. If the payload is
killed mid-run, no target is left in a half-attached state. The
tradeoff is that this write path is copy-on-write for shared `.rx`
mappings (which is why libSceSsl needs per-process patching).

### What is NOT covered

- **Hostname / expiration / revocation checks.** The patched sites
  short-circuit the verifier before those checks run; all of them are
  effectively bypassed.
- **Application-layer certificate pinning.** If a service does its own
  SPKI pinning above TLS, that path is untouched. Observed symptom
  when encountered: specific endpoints that close the socket
  mid-handshake without an alert (`UNEXPECTED_EOF_WHILE_READING`
  server-side) — these aren't verifier failures and this payload won't
  change them.
- **Processes outside the candidate list.** The candidate list in
  `src/main.c` names the known Sony services that do TLS; a third-party
  process we haven't listed won't be touched. Add it to
  `CANDIDATE_PROCS[]` if needed.

---

## Build

Requires the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

```
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make
```

Output: `ps5-tls-verify.elf`.

## Deploy

Upload and launch via `pldmgr`. The upload-slot filename must include
the `.elf` extension or `pldmgr` returns HTTP 500.

```
curl -X POST -H "X-PLDMGR-Request: 1" \
     -H "Content-Type: application/octet-stream" \
     --data-binary @ps5-tls-verify.elf \
     "http://<PS5-IP>:8084/manage:upload?filename=ps5tlsverify.elf&mode=replace"

curl -X POST -H "X-PLDMGR-Request: 1" \
     "http://<PS5-IP>:8084/loadpayload:local/ps5tlsverify"
```

Monitor progress on PS5 klog (TCP port 3232). Expected output on a
first (patching) run from an all-pristine cold boot:

```
[ps5-tls-verify] starting (4-site libSceSsl + watch mode)
[ps5-tls-verify] libSceSsl: prologue=0x... P1 hits=1 P2 hits=1 P3 hits=1 P4 hits=1
[ps5-tls-verify] libSceSsl offsets: P1=+0x50bf P2=+0x53b0 P3=+0x54dd P4=+0x54bc
[ps5-tls-verify] SURVEY: 0 OFF, N ON, 0 unknown (of N targets) — flipping ALL to OFF (majority rule)
[ps5-tls-verify] state file saved (P1@+0x50bf P3@+0x54dd)
[ps5-tls-verify] libSceSsl P1 @ pid=58 (SceShellCore) 0x... -> OFF
[ps5-tls-verify] libSceSsl P2 @ pid=58 (SceShellCore) 0x... -> OFF
[ps5-tls-verify] libSceSsl P3 @ pid=58 (SceShellCore) 0x... -> OFF
[ps5-tls-verify] libSceSsl P4 @ pid=58 (SceShellCore) 0x... -> OFF
[ps5-tls-verify] libSceSsl P1 @ pid=71 (SceJSCd) 0x... -> OFF
...
[ps5-tls-verify] DONE  flipped=N already=OFF=0 errors=0
[ps5-tls-verify] entering watch loop (1s poll, SIGTERM/reboot to exit)
```

On re-run, the klog begins with `signalling previous instance pid=…
to exit` as the single-instance guard terminates the prior watcher.

## Rollback

Three equivalent options:

1. **Re-run the payload.** Majority rule inverts the overall state and
   the previous watcher is SIGTERM'd.
2. **Reboot the console.** All changes live in RAM; nothing on disk
   is modified. The pid and state files under `/data/` persist across
   reboots but are harmless on their own.
3. **Do nothing special, just stop using the lab network.** Patches
   remain active until step 1 or 2.

Reboot is the strongest guarantee: it drops every modification plus
any transient state in patched processes, including state the watch
loop may have been maintaining.

---

## Safety

- **Isolated lab networks only.** While patched, the covered processes
  trust any certificate from any server, including attacker-forged
  certs on a non-isolated network. Do not reconnect the console to an
  open network until patches are rolled back (toggle off, or reboot).
- **No persistence of patches.** Patches live in RAM only. The state
  file at `/data/ps5-tls-verify.state` records only P1/P3 pristine
  bytes (12 bytes); the pid file at `/data/ps5-tls-verify.pid` holds
  the watcher pid. Neither modifies system state.
- **No data captured by this payload.** It writes a few bytes per
  verifier site and prints a counter to klog. No handshake data, no
  request contents, no identity information touches this payload or
  its logs.

---

## Why these four libraries

- `libSceSsl.sprx` — Sony's internal TLS stack used by `libSceHttp` /
  `libSceHttp2` for most system HTTPS traffic (including SceJSCd
  telemetry; this is the one that needs the 4-site patch).
- `libSceLibreSsl.sprx` — Sony's LibreSSL port, used by `libcurl` and
  by some system services (Party, PsNow, audio daemon).
- `libSceLibreSsl3.sprx` — a second LibreSSL variant, used by NP
  (PlayStation Network) processes, SceJSCd's own TLS, remote play,
  video core, and the WebKit-driven paths that reach TLS via
  `libcurl`.
- `libmono-btls-shared.sprx` — Mono's BoringSSL build, used by the
  .NET/C# code in `SceShellUI` (home-screen UI, store, in-app
  browser). Mono's `HttpClient` ultimately drives this TLS stack.

Patching all four covers every TLS flow observed in testing on
fw 13.20.

---

## Troubleshooting

- **`libSceSsl: ambiguous site count — bailing`**: one of the four
  pattern searches found 0 or ≥2 matches in the verifier body. Most
  likely cause is a firmware revision whose compile shifted the
  surrounding instructions, so one of the semantic prefixes (P1's
  `MOV; TEST AL, 1`, P2/P3's bit-0x20 skeletons, or P4's `CMP r/m32`)
  no longer matches. Dump the function body and update the prefixes.
  The payload makes no writes in this case.
- **`libSceSsl: UNKNOWN_CA anchor not located`**: no process in the
  candidate list has `libSceSsl.sprx` loaded, or Sony changed the
  `0x8095F00C` error constant. Start a Sony service that does system
  HTTPS (any home-screen activity triggers `SceShellCore` / `SceJSCd`)
  and re-run.
- **`state file missing/mismatched — P1/P3 restore skipped`**: a
  restore run (patched → pristine) was requested but `/data/ps5-tls-verify.state`
  is absent, truncated, or carries a different `rx_offset`. Reboot to
  fully revert, or delete the file and re-apply the patch to let the
  next run save a fresh state.
- **`P1/P3 restore skipped (no pristine bytes)`**: same cause, logged
  per target. Non-fatal; P2/P4 and the LibreSSL/mono-btls entry stubs
  still restore.
- **Patch application reports `errors=N`**: cross-process write failed
  for N targets (via `kernel_proc_copyin`). Common causes: the process
  was mid-exit, or the address became unmapped between the scan and
  the write. Does not block the other targets.
- **Handshakes still fail after a successful run**: check the
  candidate list in `src/main.c`; a Sony process that spawned after the
  initial run should have been picked up by the watch loop within 1 s,
  but a process name we don't list won't be. The watch loop logs each
  pid it catches.

## License

GPLv3+ (see `LICENSE`). This payload links the [PS5 Payload
SDK](https://github.com/ps5-payload-dev/sdk) runtime (crt0, rtld, and
kernel helpers), which is GPLv3+ with no linking exception, so the
combined work is distributed under the same terms.

Intended for security research and interoperability on hardware the
user owns.

## Disclaimer

**Tested only on a single PS5 running firmware 13.20.** It has not been
tried on any other console or firmware revision. The locators are
designed to be firmware-agnostic (no hard-coded offsets), but on an
untested firmware the pattern searches may fail to match or, worse,
match the wrong site — behavior on anything other than fw 13.20 is
unverified. Run it only on hardware you own, on an isolated network.
Provided as-is, with no warranty of any kind (see `LICENSE`).

**Authorship.** The payload (`src/main.c`) was written by GPT-6 Luna.
