# File Inspector

A small defensive file triage tool in C: it inspects a single file and prints a
security-focused risk report — what the file *actually* is, whether its name is
lying about that, and what evidence of suspicious content it carries.

## The problem it solves

"Is this file safe to open?" is usually answered by looking at the file name —
which is exactly the thing an attacker controls. A `.jpg` attachment can be a
Windows executable; a "document" can carry an appended archive; a harmless-looking
blob can be a packed payload. File Inspector answers the question from the
**bytes** instead of the name, and combines several weak signals into one
readable verdict, the way a human analyst would triage an unknown sample.

## Who it's for

Security students and learners doing malware-triage exercises, analysts who want
a quick offline first-pass check, and anyone teaching how magic bytes, entropy,
and IOC extraction work. It is an educational triage aid, not an antivirus.

## What it does

For one input file, entirely offline:

- **Magic-byte type detection** — identifies PE (MZ), ELF, PDF, ZIP/Office,
  JPEG, PNG, GZIP from leading bytes.
- **Extension-vs-content mismatch** — flags a file whose name claims one type
  but whose bytes prove another (the headline check).
- **Embedded-signature scan** — looks for known signatures *past* the header
  (appended archives, polyglots, embedded executables), with an honest
  false-positive caveat for the short 2-byte signatures.
- **Shannon entropy** — flags > 7.2 bits/byte as possibly packed or encrypted.
- **SHA-256 fingerprint** — computed locally (own FIPS 180-4 implementation),
  with an optional lookup against a **local** known-bad hash list.
- **String extraction** — printable-ASCII runs of 4+ characters.
- **IOC scan** — IPv4 addresses (strict 0–255 octet validation) and
  http/https URLs inside the extracted strings. No regex library; small
  state machines.
- **Risk summary** — a weight-of-evidence score and a verdict:
  `CLEAN` / `WORTH A LOOK` / `SUSPICIOUS`.

## What it does NOT do

- No networking, ever. Hash lookups are against a local file you provide.
- No detection/removal of real malware families; a `CLEAN` verdict means
  "no signals fired", not "safe".
- No archive unpacking, no PE/ELF structure parsing, no Unicode string
  extraction.

## Install (fresh clone)

Requires only a C compiler and `make` (macOS: Xcode command-line tools;
Linux: `gcc`/`clang` + `make`). No third-party libraries.

```sh
git clone <this-repo>
cd simple-file-inspector
make
```

## Quick start

```sh
./fileinspect <path-to-file>

# generate the safe sample files, then try the headline case:
sh examples/generate.sh
./fileinspect examples/renamed-executable.jpg
```

## Example

```sh
./fileinspect --hashlist examples/demo-hashlist.txt examples/renamed-executable.jpg
```

```
---- Identity ----------------------------------------------
Path           examples/renamed-executable.jpg
Size           48 bytes
SHA-256        43d31a4b43a238887930699f03e528d199981ef2f98e2afe47efcf1581d15480
Hash list      [!] MATCH - known-bad hash (examples/demo-hashlist.txt)
Type (magic)   PE executable (MZ)
Extension      .jpg [!] content is PE executable (MZ)

---- Content signals ---------------------------------------
Entropy        4.1054 bits/byte (normal range)
Embedded sigs  none past the header

---- Strings -----------------------------------------------
1 printable string(s) of length >= 4
         8   this is filler text, not a real program

---- IOCs --------------------------------------------------
none found

---- Risk summary (weight of evidence) ---------------------
  [+2] SHA-256 present in known-bad hash list
  [+2] Extension mismatch: named .jpg but content is PE executable (MZ)

Verdict: SUSPICIOUS (score 4)
```

## Options

| Option | Meaning |
|---|---|
| `<path-to-file>` | the single file to inspect (required) |
| `--hashlist <file>` | compare the file's SHA-256 against a local list of known-bad hashes (one hex hash per line, `#` comments allowed; compatible with MalwareBazaar full exports) |
| `-h`, `--help` | usage help |

Exit code is `0` when the inspection ran (regardless of verdict) and `1` for
usage errors or unreadable input. Output is colored only when stdout is a
terminal; piped output is plain text.

## Web UI (optional)

The same C code compiles to WebAssembly into a single self-contained page with
drag-and-drop: open `web/fileinspect.html` in any browser — everything runs
locally, no file leaves the machine. Rebuilding it requires
[Emscripten](https://emscripten.org): `make web`. The CLI is the primary tool;
the web page is a convenience front-end to the identical code.

## Tests

```sh
sh tests/run_tests.sh
```

Ten cases covering normal input, invalid input, and edge cases; each checks
both the exit code and the output. See `TEST_REPORT.pdf` for the full test
report with screenshots.

## Known limitations

- The signature table is small; Mach-O, GIF, MP4, plain text, etc. report as
  `unknown`. An unknown type is not a verdict.
- The 2-byte signatures (MZ, GZIP) match random data by chance in the
  embedded-signature scan (~3 hits per 64 KB of random bytes); the tool
  discloses this and does not score such hits.
- Compressed formats (ZIP, PNG, JPEG) legitimately have high entropy, so the
  entropy flag alone is only ever "worth a look", not "suspicious".
- Absence from a hash list proves nothing; only a match is a signal.
- Strings are printable ASCII only (no UTF-16), and the IOC scan covers IPv4
  and http/https URLs only (no IPv6, no bare domains).
- The whole file is loaded into memory, so inspecting multi-GB files is not
  recommended.

## Safety and ethical use

File Inspector is defensive and educational: it only reads the file it is
given and never executes anything, never touches the network, and never
transmits data. All bundled samples are self-generated and harmless — the
"executable" is a 2-byte header plus filler text, and sample IPs/domains use
RFC 5737 documentation ranges and `.example`/`.invalid` names. Use the tool
only on files you are authorized to analyze; handle real malware samples in an
isolated environment.

## License

MIT — see [LICENSE](LICENSE).
