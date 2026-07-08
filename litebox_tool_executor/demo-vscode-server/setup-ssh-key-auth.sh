#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
auth_dir="${repo_root}/target/demo-vscode-server/ssh/server"
client_dir="${repo_root}/target/demo-vscode-server/ssh/client"
auth_keys="${auth_dir}/authorized_keys"

windows_profile_to_wsl() {
    local profile drive rest
    profile="$(cmd.exe /C 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r' | tail -n 1 || true)"
    case "${profile}" in
        [A-Za-z]:\\*)
            drive="$(printf '%s' "${profile:0:1}" | tr '[:upper:]' '[:lower:]')"
            rest="$(printf '%s' "${profile:2}" | sed 's#\\#/#g')"
            printf '/mnt/%s%s\n' "${drive}" "${rest}"
            ;;
    esac
}

key_dir="${LITEBOX_DEMO_SSH_KEY_DIR:-}"
if [[ -z "${key_dir}" ]]; then
    if command -v cmd.exe >/dev/null 2>&1; then
        win_profile="$(windows_profile_to_wsl)"
        if [[ -n "${win_profile}" && -d "${win_profile}" ]]; then
            key_dir="${win_profile}/.ssh"
        fi
    fi
fi
if [[ -z "${key_dir}" ]]; then
    key_dir="${HOME}/.ssh"
fi

key_path="${key_dir}/litebox_ed25519"
mkdir -p "${key_dir}" "${auth_dir}" "${client_dir}"
chmod 700 "${key_dir}" "${auth_dir}" "${client_dir}" 2>/dev/null || true

if [[ ! -f "${key_path}" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C 'litebox-vscode-demo' -f "${key_path}"
fi
chmod 600 "${key_path}" 2>/dev/null || true

if [[ ! -f "${key_path}.pub" ]]; then
    ssh-keygen -y -f "${key_path}" > "${key_path}.pub"
fi

install -m 600 "${key_path}.pub" "${auth_keys}"
install -m 600 "${key_path}" "${client_dir}/litebox_ed25519"
install -m 644 "${key_path}.pub" "${client_dir}/litebox_ed25519.pub"

printf 'LiteBox demo SSH private key: %s\n' "${key_path}"
printf 'LiteBox demo WSL test key: %s\n' "${client_dir}/litebox_ed25519"
printf 'LiteBox demo authorized_keys: %s\n' "${auth_keys}"
