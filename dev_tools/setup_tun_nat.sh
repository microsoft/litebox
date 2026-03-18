#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Sets up a TUN device with NAT so litebox guests can reach the internet.
#
# The guest network stack uses hardcoded addresses (see litebox/src/net/mod.rs):
#   Guest IP:  10.0.0.2
#   Gateway:   10.0.0.1
#
# This script configures the host side of that link.
#
# Usage:
#   sudo ./setup_tun_nat.sh [up|down]
#
# Requires: iproute2, iptables, dnsmasq

set -euo pipefail

TUN_DEV="tun99"
TUN_ADDR="10.0.0.1/24"
TUN_SUBNET="10.0.0.0/24"
OUTBOUND_DEV=$(ip route show default | awk '{print $5; exit}')
DNS_UPSTREAM="127.0.0.53"

usage() {
    echo "Usage: sudo $0 [up|down]"
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: must run as root" >&2
        exit 1
    fi
}

up() {
    require_root

    # Tear down first if already running (idempotent)
    if ip link show "${TUN_DEV}" &>/dev/null; then
        echo "==> ${TUN_DEV} already exists, tearing down first"
        down
    fi

    local TUN_USER
    TUN_USER="$(logname 2>/dev/null || echo "${SUDO_USER:-root}")"

    echo "==> Setting up TUN device ${TUN_DEV} (owner: ${TUN_USER})"
    ip tuntap add dev "${TUN_DEV}" mode tun user "${TUN_USER}"
    ip addr add "${TUN_ADDR}" dev "${TUN_DEV}"
    ip link set "${TUN_DEV}" up

    echo "==> Enabling IP forwarding"
    sysctl -q net.ipv4.ip_forward=1

    echo "==> Adding iptables NAT + FORWARD rules (outbound via ${OUTBOUND_DEV})"
    iptables -t nat -A POSTROUTING -s "${TUN_SUBNET}" -o "${OUTBOUND_DEV}" -j MASQUERADE
    iptables -A FORWARD -i "${TUN_DEV}" -j ACCEPT
    iptables -A FORWARD -o "${TUN_DEV}" -m state --state RELATED,ESTABLISHED -j ACCEPT

    echo "==> Starting dnsmasq on ${TUN_ADDR%%/*}:53 (upstream ${DNS_UPSTREAM})"
    dnsmasq \
        --no-daemon \
        --listen-address="${TUN_ADDR%%/*}" \
        --port=53 \
        --server="${DNS_UPSTREAM}" \
        --bind-interfaces \
        --no-hosts \
        --no-resolv \
        --log-queries &
    DNSMASQ_PID=$!
    echo "${DNSMASQ_PID}" > "/tmp/${TUN_DEV}_dnsmasq.pid"

    echo "==> Ready. dnsmasq PID=${DNSMASQ_PID}"
    echo "    Guest will use: --tun-device-name ${TUN_DEV}"
    echo "    Runner can be invoked as regular user (no sudo needed)."
}

down() {
    require_root
    echo "==> Tearing down TUN networking"

    # Stop dnsmasq
    if [[ -f "/tmp/${TUN_DEV}_dnsmasq.pid" ]]; then
        DNSMASQ_PID=$(cat "/tmp/${TUN_DEV}_dnsmasq.pid")
        if kill -0 "${DNSMASQ_PID}" 2>/dev/null; then
            echo "    Stopping dnsmasq (PID ${DNSMASQ_PID})"
            kill "${DNSMASQ_PID}"
        fi
        rm -f "/tmp/${TUN_DEV}_dnsmasq.pid"
    fi

    # Remove iptables rules (best-effort, ignore errors)
    echo "    Removing iptables rules"
    iptables -t nat -D POSTROUTING -s "${TUN_SUBNET}" -o "${OUTBOUND_DEV}" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "${TUN_DEV}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${TUN_DEV}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    # Remove TUN device
    if ip link show "${TUN_DEV}" &>/dev/null; then
        echo "    Removing ${TUN_DEV}"
        ip link delete "${TUN_DEV}"
    fi

    echo "==> Done"
}

case "${1:-}" in
    up)   up   ;;
    down) down ;;
    *)    usage ;;
esac
