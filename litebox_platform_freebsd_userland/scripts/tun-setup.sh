#! /bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

. "$(dirname "$0")/_common.sh"

# If not root, exit
if [ "$(id -u)" -ne 0 ]; then
    fatal "Requires running as root"
fi

# Parse arguments
REMOVE_TUN=0
FORCE_RECREATE=0
TUN_DEV="tun99"
TUN_IP="10.0.0.1"
TUN_REMOTE_IP="10.0.0.2"
while getopts "hdft:i:r:" opt; do
    case $opt in
        h)
            echo "Usage: $0 [-h] [-d | -f] [-t TUN] [-i IP] [-r REMOTE_IP]" 1>&2
            echo "  -h  Show this help message" 1>&2
            echo "  -d  Remove the TUN device" 1>&2
            echo "  -f  Force re-create the TUN device" 1>&2
            echo "  -t  TUN device name (default: $TUN_DEV)" 1>&2
            echo "  -i  TUN local IP address (default: $TUN_IP)" 1>&2
            echo "  -r  TUN remote (guest) IP address (default: $TUN_REMOTE_IP)" 1>&2
            exit 0
            ;;
        d)
            REMOVE_TUN=1
            ;;
        f)
            FORCE_RECREATE=1
            ;;
        t)
            TUN_DEV="$OPTARG"
            ;;
        i)
            TUN_IP="$OPTARG"
            ;;
        r)
            TUN_REMOTE_IP="$OPTARG"
            ;;
        \?)
            fatal "Invalid option: -$OPTARG"
            ;;
    esac
done
if [ $REMOVE_TUN -eq 1 ] && [ $FORCE_RECREATE -eq 1 ]; then
    fatal "Cannot remove and force re-create at the same time"
fi

check_for_tools ifconfig

info "Script parameters:"
info2 "TUN device: ${BOLD}${TUN_DEV}${RESET}"
if [ $REMOVE_TUN -eq 1 ]; then
    info2 "Remove TUN device: ${BOLD}yes${RESET}"
else
    info2 "TUN local IP: ${BOLD}${TUN_IP}${RESET}"
    info2 "TUN remote IP: ${BOLD}${TUN_REMOTE_IP}${RESET}"
fi
if [ $FORCE_RECREATE -eq 1 ]; then
    info2 "Force recreate TUN device: ${BOLD}yes${RESET}"
fi

# Check if the TUN device already exists
if ifconfig "$TUN_DEV" > /dev/null 2>&1; then
    info "TUN device already exists"
    if [ $REMOVE_TUN -eq 1 ] || [ $FORCE_RECREATE -eq 1 ]; then
        info "Destroying TUN device"
        ifconfig "$TUN_DEV" destroy
        success "Removed TUN device"
        if [ $REMOVE_TUN -eq 1 ]; then
            exit 0
        fi
    else
        fatal "Use ${BOLD}-d${RESET} to remove the TUN device or ${BOLD}-f${RESET} to force re-create it"
    fi
elif [ $REMOVE_TUN -eq 1 ]; then
    warn "TUN device does not exist"
    fatal "Nothing to remove"
fi

info "Creating TUN device"
ifconfig "$TUN_DEV" create

info "Assigning IP address (point-to-point: $TUN_IP -> $TUN_REMOTE_IP)"
ifconfig "$TUN_DEV" inet "$TUN_IP" "$TUN_REMOTE_IP" netmask 255.255.255.0

# Allow the current user to open the device node
CURRENT_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
if [ -n "$CURRENT_USER" ] && [ -c "/dev/$TUN_DEV" ]; then
    info "Setting ownership of /dev/$TUN_DEV to $CURRENT_USER"
    chown "$CURRENT_USER" "/dev/$TUN_DEV"
fi

success "Created TUN device"
