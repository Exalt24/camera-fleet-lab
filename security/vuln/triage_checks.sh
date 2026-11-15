#!/usr/bin/env bash
# The checks behind the written triage in docs/vuln-and-iam.md: for each ranked item that needed a look at the real container, the
# command and what it printed. Read only; it changes nothing. Needs the lab running in the given compose project.
#
#   bash security/vuln/triage_checks.sh [cfl-iam]  > docs/security/vuln/triage_checks.txt
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
P="${1:-cfl-iam}"
dx() { docker compose -p "$P" --profile iam exec -T "$@"; }

echo "== CVE-2026-123158 (OpenSSH password bypass on musl without PAM, CISA KEV) against the Alpine router container =="
echo "-- is any OpenSSH package installed in the edge container?"
dx edge sh -c 'apk info -e openssh openssh-server openssh-client; echo "exit code $? (3 means none of the three is installed)"'
echo "-- is there an sshd binary?"
dx edge sh -c 'command -v sshd || echo "no sshd on the PATH"'
echo "-- what is listening in the edge container (a TCP listener on 22 would show here)?"
dx edge sh -c 'ss -ltn'
echo "-- the Alpine release, and how many packages the image holds"
dx edge sh -c 'cat /etc/alpine-release; apk list -I | wc -l; echo "packages:"; apk list -I | sed "s/ .*//" | tr "\n" " "; echo'

echo
echo "== CVE-2026-3087 (Python shutil.unpack_archive with a Windows drive path) against this repo =="
echo "-- does any Python file in the lab call unpack_archive?"
if grep -rn --include='*.py' --exclude-dir=.git --exclude-dir=snapshots --exclude-dir=tests --exclude=cve_triage.py 'unpack_archive' hub security scripts edge camera demo 2>/dev/null; then :; else echo "no call to unpack_archive in hub/, security/, scripts/, edge/, camera/ or demo/"; fi
echo "-- the hub's Python, and whether it runs on Windows"
dx hub python -c 'import sys,platform;print(sys.version.split()[0], platform.system())'

echo
echo "== FFmpeg 7.1.5, the 41 findings that are the most numerous =="
echo "-- the exact Debian package version in the hub image (a +debNuN suffix means Debian has patched it without changing the upstream number)"
dx hub dpkg-query -W -f '${Package} ${Version}\n' ffmpeg
echo "-- what the hub runs ffmpeg for"
dx hub sh -c 'grep -n "ffprobe\|ffmpeg" /srv/app/probe.py | head -5'
