#! /bin/bash

source "$(dirname "$0")/_common.sh"

# If not root, exit
if [ "$(id -u)" -ne 0 ]; then
    fatal "Requires running as root"
fi

# Parse arguments
REMOVE_TUN=0
FORCE_RECREATE=0
TUN_DEV="tun99"
TUN_IP="10.0.0.1"
while getopts ":hdft:i:" opt; do
    case $opt in
        h)
            echo "Usage: $0 [-h] [-d | -f] [-t TUN] [-i IP]" 1>&2
            echo "  -h  Show this help message" 1>&2
            echo "  -d  Remove the TUN device" 1>&2
            echo "  -f  Force re-create the TUN device" 1>&2
            echo "  -t  TUN device name (default: $TUN_DEV)" 1>&2
            echo "  -i  TUN IP address (default: $TUN_IP)" 1>&2
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
        :)
            fatal "Option -$OPTARG requires an argument"
            ;;
        \?)
            fatal "Invalid option: -$OPTARG"
            ;;
    esac
done
if [ $REMOVE_TUN -eq 1 ] && [ $FORCE_RECREATE -eq 1 ]; then
    fatal "Cannot remove and force re-create at the same time"
fi

check_for_tools ip

info "Script parameters:"
info2 "TUN device: ${BOLD}${TUN_DEV}${RESET}"
if [ $REMOVE_TUN -eq 1 ]; then
    info2 "Remove TUN device: ${BOLD}yes${RESET}"
else
    info2 "TUN IPs: ${BOLD}${TUN_IP}/24${RESET}"
fi
if [ $FORCE_RECREATE -eq 1 ]; then
    info2 "Force recreate TUN device: ${BOLD}yes${RESET}"
fi

if ip tuntap show | grep "^${TUN_DEV}:" &> /dev/null; then
    info "TUN device already exists"
    if [ $REMOVE_TUN -eq 1 ] || [ $FORCE_RECREATE -eq 1 ]; then
        info "Bringing down TUN device"
        ip link set dev "$TUN_DEV" down
        info "Removing TUN device"
        ip tuntap del dev "$TUN_DEV" mode tun
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
ip tuntap add dev "$TUN_DEV" mode tun

info "Assigning IP addresses"
ip addr add "$TUN_IP"/24 dev "$TUN_DEV"

info "Bringing up TUN device "
ip link set dev "$TUN_DEV" up

success "Created TUN device"
