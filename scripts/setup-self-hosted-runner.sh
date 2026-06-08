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

registration_auth_token=""
if command -v gh >/dev/null 2>&1; then
  registration_auth_token="$(gh auth token 2>/dev/null || true)"
fi
if [ -z "$registration_auth_token" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  registration_auth_token="$GITHUB_TOKEN"
fi
if [ -z "$registration_auth_token" ]; then
  echo "Authenticate gh on this VM or set GITHUB_TOKEN to a repo-admin token." >&2
  exit 1
fi

registration_json="$(
  curl -fsSL -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${registration_auth_token}" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "https://api.github.com/repos/$repo_slug/actions/runners/registration-token"
)"
registration_token="$(printf '%s' "$registration_json" | sed -n 's/.*"token":[[:space:]]*"\([^"]*\)".*/\1/p')"

if [ -z "${registration_token:-}" ]; then
  echo "Could not obtain a runner registration token" >&2
  exit 1
fi

if [ -f "$runner_dir/.runner" ]; then
  echo "Runner is already configured; skipping config.sh"
else
  sudo -u "$runner_user" "$runner_dir/config.sh" \
    --url "$repo_url" \
    --token "$registration_token" \
    --name "$runner_name" \
    --labels "$runner_labels" \
    --unattended \
    --replace
fi

# Install the fixed, root-owned deploy entrypoint and deploy script so the runner
# can sudo only the wrapper, not arbitrary privileged commands.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -d -m 0755 /opt/oadtd/bin
install -m 0755 "$script_dir/deploy-release.sh" /opt/oadtd/bin/deploy-release.sh
install -m 0755 "$script_dir/oadtd-deploy-wrapper.sh" /usr/local/sbin/oadtd-deploy
chown root:root /opt/oadtd/bin/deploy-release.sh /usr/local/sbin/oadtd-deploy

cat >/etc/sudoers.d/oadtd-runner <<EOF
$runner_user ALL=(root) NOPASSWD: /usr/local/sbin/oadtd-deploy
EOF
chmod 0440 /etc/sudoers.d/oadtd-runner

# Run the runner service as the non-root runner user (not as root).
sudo bash -lc "cd '$runner_dir' && ./svc.sh install '$runner_user'"
sudo bash -lc "cd '$runner_dir' && ./svc.sh start"
sudo bash -lc "cd '$runner_dir' && ./svc.sh status"
