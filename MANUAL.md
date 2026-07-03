# File Inspector — User Manual

This manual explains how to install and use `fileinspect`, what every part of
the report means, and how to troubleshoot common problems. For a quick
overview, read [README.md](README.md) first.

## 1. Requirements and supported environment

- **OS:** macOS or Linux (any environment with a C11 compiler and `make`).
  Windows works under WSL.
- **Build tools:** `gcc` or `clang`, `make`. Nothing else — the tool uses the
  C standard library only.
- **Optional, for the web UI build only:** Emscripten (`emcc`) and `python3`.
  The prebuilt `web/fileinspect.html` works without either.

## 2. Installation

```sh
git clone <this-repo>
cd simple-file-inspector
make            # produces ./fileinspect
```

To verify the build:

```sh
sh tests/run_tests.sh   # should end with: Results: 10 passed, 0 failed
```

## 3. Usage

```
./fileinspect [--hashlist <list-file>] <path-to-file>
./fileinspect --help
```

Step by step:

1. Build (`make`) if you have not already.
2. (Optional) generate the safe sample files: `sh examples/generate.sh`
3. Run the tool on one file: `./fileinspect examples/iocs.txt`
4. Read the report bottom-up if you are in a hurry: the **Verdict** line
   summarizes everything, and the **Risk summary** above it lists exactly
   which signals fired and why.

### Options and modes

| Option | Explanation |
|---|---|
| `<path-to-file>` | The file to inspect. Exactly one file per run. Any type of file is accepted, including binary data; the tool only reads it and never executes it. |
| `--hashlist <list-file>` | Also compare the file's SHA-256 against a local list of known-bad hashes. A match is the strongest signal the tool can raise (+2). The flag may appear before or after the file path. |
| `-h`, `--help` | Print usage help and exit. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Inspection completed (whatever the verdict). |
| `1` | Usage error, unreadable input file, or unreadable hash list. A specific message is printed to stderr. |

### Color

Output is colorized (warnings yellow, verdict green/yellow/red) only when
stdout is a terminal. Piped or redirected output (`./fileinspect x > out.txt`)
is automatically plain text.

## 4. Input formats

**The inspected file** can be anything — there is no format requirement.

**The hash list** (`--hashlist`) is a plain text file:

- one SHA-256 hash (64 hex characters) per line, upper- or lowercase;
- anything after the hash on the same line is ignored (e.g. a family label);
- blank lines and lines starting with `#` are ignored;
- lines that are not a SHA-256 are skipped silently.

This matches the format of public hash exports such as MalwareBazaar's
`full_sha256.txt`. A tiny demo list is generated at
`examples/demo-hashlist.txt`; it contains the hash of our own harmless sample
so the match path can be demonstrated without real malware data.

```
# Demo known-bad hash list (format: <sha256 hex> <label>)
43d31a4b43a2...d15480  Demo.FakeExecutable
```

## 5. Understanding the report

The report has five sections. `[!]` marks a finding.

### Identity

| Field | Meaning |
|---|---|
| `Path` | The file as given on the command line. |
| `Size` | Size in bytes. `0 bytes [!] empty` is itself a signal. |
| `SHA-256` | Fingerprint of the content. Renaming a file never changes it, which is why hash lists work. |
| `Hash list` | Only when `--hashlist` is given: `MATCH - known-bad hash` or `no match`. |
| `Type (magic)` | What the leading bytes say the file is: PE (MZ), ELF, PDF, ZIP/Office, JPEG, PNG, GZIP, or `unknown`. `unknown` includes every format not in the table (plain text, Mach-O, GIF, ...). |
| `Extension` | The name's claim, compared against the detected type: `(matches content)`, `[!] content is <type>` (name claims one known type, bytes prove another), or `[!] no <type> signature present` (name claims a type whose signature is absent). Extensions with no magic bytes (`.txt`, `.c`, ...) have nothing to check. |

### Content signals

| Field | Meaning |
|---|---|
| `Entropy` | Shannon entropy in bits/byte, 0–8. Text is typically 4–5; compressed or encrypted data approaches 8. Above 7.2 is flagged. Note that ZIP/PNG/JPEG content is *legitimately* high-entropy. |
| `Embedded sigs` | Known signatures found at offsets past the header — evidence of appended or embedded content (polyglots, droppers). Hits from 2-byte signatures (MZ, GZIP) can occur by chance in random-looking data; the report says so and does not score them. |

### Strings

Count of printable-ASCII runs of 4+ characters, with the first 10 shown as
`<file offset>  <string>`. Strings often reveal embedded commands, paths, or
network indicators.

### IOCs

IPv4 addresses (each octet strictly validated 0–255, so `999.1.2.3` or
`1.2.3.4.5` never match) and `http://`/`https://` URLs found inside the
extracted strings, each with its file offset. IOC presence in an unknown file
is a reason to look closer, not proof of malice.

### Risk summary and verdict

Each fired signal contributes a weight:

| Signal | Weight | Rationale |
|---|---|---|
| SHA-256 in known-bad list | +2 | direct identification |
| Extension mismatch (bytes prove a different known type) | +2 | active deception |
| Extension claims a type whose signature is absent | +1 | possible disguise or corruption |
| High entropy (> 7.2) | +1 | circumstantial |
| Embedded signatures (3+ byte signatures only) | +1 | circumstantial |
| Network IOCs present | +1 | circumstantial |
| Empty file | +1 | anomaly |

Verdict thresholds: **0 = CLEAN**, **1 = WORTH A LOOK**, **≥ 2 = SUSPICIOUS**.
One circumstantial signal alone is never "suspicious"; two independent ones
are — that is the "weight of evidence" idea. The two +2 signals cross the
threshold on their own because each is direct rather than circumstantial
evidence.

## 6. The web UI (optional)

`web/fileinspect.html` is a single self-contained page: the same C code
compiled to WebAssembly. Open it in a browser, drag a file onto the drop zone
(or click to choose), and optionally load a hash list with the button — the
current file is automatically re-inspected when the list changes. Everything
runs inside the browser; no data leaves the machine.

To rebuild it after changing the C sources: `make web` (requires Emscripten).
Note that the page embeds the code at build time — C changes do not appear in
it until you rebuild.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `make: gcc: command not found` | Install build tools: `xcode-select --install` (macOS) or `sudo apt install build-essential` (Debian/Ubuntu). |
| `Error: cannot open '<file>': No such file or directory` | Wrong path — check spelling and working directory. |
| `Error: cannot open '<file>': Permission denied` | You lack read permission: `chmod +r <file>` or run as a user who can read it. |
| `Error: cannot open hash list ...` | The `--hashlist` argument points to a missing/unreadable file. |
| `Error: --hashlist requires a file argument.` | `--hashlist` was given last with no list after it. |
| Weird `[33m`-style characters in saved output | You captured colored output with something that is not a terminal-aware pager. Redirect instead (`> out.txt`); redirection disables color automatically. |
| `make web` fails with `emcc not found` | Emscripten is not installed. The web UI is optional; the prebuilt `web/fileinspect.html` still works. |
| Web page shows old behavior after editing C code | The page is built from the sources; run `make web` again. |
| Inspecting a huge file is slow / uses lots of memory | The whole file is loaded into RAM by design. Not recommended above a few hundred MB. |

## 8. Worked example, input to output

Create the samples and inspect the renamed fake executable together with the
demo hash list:

```sh
sh examples/generate.sh
./fileinspect --hashlist examples/demo-hashlist.txt examples/renamed-executable.jpg
```

The input file is 48 bytes: the two magic bytes `MZ` (`4D 5A`), a few header
filler bytes, then the text "this is filler text, not a real program" — and it
is *named* `.jpg`.

Output (colors omitted):

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

Reading it: the leading bytes say *PE executable* while the name says *JPEG* —
that mismatch alone (+2) makes the file suspicious, because it is deception,
not coincidence. Independently, its SHA-256 appears in the provided known-bad
list (+2). Entropy is normal (it is mostly plain text), there is nothing
embedded past the header, and the single extracted string and empty IOC scan
show there is no other content of interest. Total score 4 → **SUSPICIOUS** —
which is the correct triage for a fake image carrying an executable header.
