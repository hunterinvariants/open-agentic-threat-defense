#!/usr/bin/env bash
set -euo pipefail

repo_url="${REPO_URL:-https://github.com/hunterinvariants/open-agentic-threat-defense}"
repo_slug="${REPO_SLUG:-hunterinvariants/open-agentic-threat-defense}"
runner_name="${RUNNER_NAME:-sentinel-oatd}"
runner_labels="${RUNNER_LABELS:-oadtd-staging}"
runner_user="${RUNNER_USER:-runner}"
runner_dir="${RUNNER_DIR:-/opt/actions-runner}"
runner_arch="${RUNNER_ARCH:-x64}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root: sudo bash scripts/setup-self-hosted-runner.sh" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "tar is required" >&2
  exit 1
fi

if ! id -u "$runner_user" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$runner_dir" --shell /bin/bash "$runner_user"
fi

install -d -m 0755 "$runner_dir"
chown "$runner_user:$runner_user" "$runner_dir"
chmod 0755 "$runner_dir"

runner_version="$(
  curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n1
)"

if [ -z "$runner_version" ]; then
  echo "Could not determine latest GitHub Actions runner version" >&2
  exit 1
fi

runner_tarball="actions-runner-linux-${runner_arch}-${runner_version#v}.tar.gz"
runner_url="https://github.com/actions/runner/releases/download/${runner_version}/${runner_tarball}"
tmp_dir="$(mktemp -d)"
chown "$runner_user:$runner_user" "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

curl -fsSL -o "$tmp_dir/$runner_tarball" "$runner_url"
chown "$runner_user:$runner_user" "$tmp_dir/$runner_tarball"
sudo -u "$runner_user" tar xzf "$tmp_dir/$runner_tarball" -C "$runner_dir"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  registration_token="$(gh api "repos/$repo_slug/actions/runners/registration-token" --jq .token)"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  registration_json="$(
    curl -fsSL -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "https://api.github.com/repos/$repo_slug/actions/runners/registration-token"
  )"
  registration_token="$(printf '%s' "$registration_json" | sed -n 's/.*"token":[[:space:]]*"\([^"]*\)".*/\1/p')"
else
  echo "Install GitHub CLI (gh) and authenticate, or set GITHUB_TOKEN to a token with repo admin access." >&2
  exit 1
fi

if [ -z "${registration_token:-}" ]; then
  echo "Could not obtain a runner registration token" >&2
  exit 1
fi

sudo -u "$runner_user" "$runner_dir/config.sh" \
  --url "$repo_url" \
  --token "$registration_token" \
  --name "$runner_name" \
  --labels "$runner_labels" \
  --unattended \
  --replace

cat >/etc/sudoers.d/oadtd-runner <<'EOF'
runner ALL=(root) NOPASSWD: /usr/bin/install, /bin/ln, /bin/rm, /bin/chown, /bin/systemctl, /usr/bin/journalctl
EOF
chmod 0440 /etc/sudoers.d/oadtd-runner

"$runner_dir/svc.sh" install "$runner_user"
"$runner_dir/svc.sh" start
"$runner_dir/svc.sh" status
