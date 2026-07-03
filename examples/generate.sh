#!/bin/sh
# Generates the safe sample files used in the File Inspector demos and tests.
# Everything is created locally from nothing. The "executable" is only a
# 2-byte MZ header plus plain filler text - it contains no code and cannot
# run. IPs use the RFC 5737 documentation ranges and domains use
# .example/.invalid, so no sample points at a real system.
set -eu
cd "$(dirname "$0")"

# 1. Normal text file: no signals at all -> verdict CLEAN
cat > normal.txt <<'EOF'
Meeting notes
-------------
- reviewed the quarterly report
- lunch order: two sandwiches, one coffee
- next sync on Friday
EOF

# 2. Renamed fake executable: MZ header + harmless filler, named as a JPEG
#    -> extension mismatch (the headline check), verdict SUSPICIOUS
printf 'MZ\220\000\003\000\000\000 this is filler text, not a real program' \
    > renamed-executable.jpg

# 3. High-entropy blob: random bytes -> entropy flag, verdict WORTH A LOOK
head -c 4096 /dev/urandom > high-entropy.bin

# 4. Text with embedded network IOCs -> IOC flag, verdict WORTH A LOOK
cat > iocs.txt <<'EOF'
session log (fabricated for testing)
connection attempt from 203.0.113.7 port 4444
callback to https://c2.invalid.example/beacon?id=42
secondary mirror at http://198.51.100.23:8080/payload.bin
these must NOT be detected as IPs: 999.1.2.3, 1.2.3.4.5, ver1.2.3
EOF

# 5. Empty file -> empty-file flag, verdict WORTH A LOOK
: > empty.bin

# 6. Demo known-bad hash list for --hashlist: contains the SHA-256 of our
#    own fake executable, so the hash-match path can be demonstrated
#    without any real malware data.
hash=$(shasum -a 256 renamed-executable.jpg 2>/dev/null | awk '{print $1}') || true
if [ -z "${hash:-}" ]; then
    hash=$(openssl dgst -sha256 -r renamed-executable.jpg | awk '{print $1}')
fi
{
    echo "# Demo known-bad hash list (format: <sha256 hex> <label>)"
    echo "# This is the hash of renamed-executable.jpg, our own harmless sample."
    echo "$hash  Demo.FakeExecutable"
} > demo-hashlist.txt

echo "Generated in $(pwd):"
echo "  normal.txt renamed-executable.jpg high-entropy.bin"
echo "  iocs.txt empty.bin demo-hashlist.txt"
