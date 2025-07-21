#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
BLU='\033[1;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log() { echo -e "${BLU}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GRN}[✔]${NC} $1"; }
warn() { echo -e "${YEL}[!]${NC} $1"; }
error() { echo -e "${RED}[✘]${NC} $1"; }

# Ensure root
if [[ $EUID -ne 0 ]]; then
    error "Run this script as root."
    exit 1
fi

LXC_ID=""
MANUAL_IP=""
LOG_FILE="/var/log/lxc-ip-assign.log"
REPORT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)
            shift
            MANUAL_IP="$1"
            ;;
        [0-9]*)
            LXC_ID="$1"
            ;;
        *)
            echo "Usage: $0 [<lxc_id>] [--ip <manual_ip>]"
            exit 1
            ;;
    esac
    shift
done

CONFIG_PATH="/etc/pve/lxc/${LXC_ID}.conf"

# Detect interface, gateway, subnet
log "Detecting network interface..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
[[ -z "$IFACE" ]] && { error "No default interface found."; exit 1; }

GATEWAY=$(ip route | grep default | awk '{print $3}')
IP_CIDR=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}' | head -n 1)
NETMASK_LINE=$(ipcalc "$IP_CIDR" | grep -w 'Netmask')
NETMASK=$(echo "$NETMASK_LINE" | awk '{print $2}')
CIDR_MASK=$(echo "$NETMASK_LINE" | awk '{print $4}')

echo -e "${BOLD}Network Info:${NC}"
echo -e "${CYN}Interface${NC}: $IFACE"
echo -e "${CYN}Gateway${NC}  : $GATEWAY"
echo -e "${CYN}Subnet${NC}   : $IP_CIDR"
echo -e "${CYN}Netmask${NC}  : $NETMASK = /$CIDR_MASK"

# Scan used IPs
log "Running arp-scan..."
ARP_IPS=$(arp-scan --interface="$IFACE" --localnet | awk '/^[0-9]+\./ {print $1}' || true)

log "Running nmap ping sweep..."
NMAP_UP_IPS=$(nmap -sn "$IP_CIDR" | awk '/Nmap scan report/{ip=$NF} /Host is up/{print ip}')

log "Collecting used LXC IPs..."
LXC_USED_IPS=$(grep -hEo 'ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' /etc/pve/lxc/*.conf 2>/dev/null | cut -d= -f2)

USED_IPS=$(echo -e "$ARP_IPS\n$NMAP_UP_IPS\n$LXC_USED_IPS" | sort -u)

# Calculate free IPs
log "Calculating available IPs in subnet..."
ALL_IPS=$(nmap -n -sL "$IP_CIDR" | awk '/Nmap scan report/{print $NF}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
FREE_IPS=$(comm -23 <(echo "$ALL_IPS" | sort -u) <(echo "$USED_IPS" | sort -u))

# Filter invalid/reserved IPs
SAFE_FREE_IPS=$(echo "$FREE_IPS" | grep -vE '\.0$|\.255$|^0\.|\.1$')

FIRST_FREE_IP=$(echo "$SAFE_FREE_IPS" | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n | head -n 1)

# Display available IPs
echo -e "\n${BOLD}========= Free IP addresses =========${NC}"
echo "$SAFE_FREE_IPS" | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n
echo -e "${BOLD}=====================================${NC}"
echo -e "${CYN}Total free:${NC} $(echo "$SAFE_FREE_IPS" | grep -c '^')"
echo -e "${CYN}Suggested IP:${NC} $FIRST_FREE_IP"

# Decide on IP to assign
ASSIGNED_IP="$FIRST_FREE_IP"
if [[ -n "$MANUAL_IP" ]]; then
    if echo "$USED_IPS" | grep -q "^$MANUAL_IP$"; then error "Manual IP $MANUAL_IP already in use."; exit 1; fi
    if echo "$MANUAL_IP" | grep -qE '\.0$|\.255$|^0\.|\.1$'; then error "Manual IP $MANUAL_IP is reserved or invalid."; exit 1; fi
    ASSIGNED_IP="$MANUAL_IP"
    success "Manual IP accepted: $ASSIGNED_IP"
fi

# If LXC ID provided, apply config
if [[ -n "$LXC_ID" ]]; then
    log "Assigning IP $ASSIGNED_IP to LXC $LXC_ID"

    if [[ ! -f "$CONFIG_PATH" ]]; then error "LXC config $CONFIG_PATH not found."; exit 1; fi

    # Stop container if running
    RUNNING=$(pct status "$LXC_ID" | grep -q "running" && echo "yes" || echo "no")
    if [[ "$RUNNING" == "yes" ]]; then
        warn "Container $LXC_ID is running — stopping..."
        pct stop "$LXC_ID"
    fi

    # Modify config
    sed -i '/^net0:/d' "$CONFIG_PATH"
    echo "net0: name=eth0,bridge=$IFACE,ip=$ASSIGNED_IP/$CIDR_MASK,gw=$GATEWAY" >> "$CONFIG_PATH"
    success "LXC config updated"

    # Container info
    CT_NAME=$(pct config "$LXC_ID" | grep '^hostname:' | awk '{print $2}')
    [ -z "$CT_NAME" ] && CT_NAME="(unknown)"

    # Start container
    log "Starting container $LXC_ID..."
    pct start "$LXC_ID"
    success "Container started"

    # Confirm assignment
    echo -e "\n${BOLD}${CYN}Assigned IP Confirmation:${NC}"
    pct config "$LXC_ID" | grep net0

    # Nmap scan
    echo -e "\n${BOLD}${CYN}Nmap Port Scan (${ASSIGNED_IP}):${NC}"
    OPEN_PORTS=$(nmap -Pn -p 22,80,443,5432,8006 "$ASSIGNED_IP" | grep -Eo "^[0-9]+/tcp\s+open" | awk '{print $1}' | paste -sd ',' -)
    [[ -z "$OPEN_PORTS" ]] && OPEN_PORTS="None"
    echo "$OPEN_PORTS"

    # Ping test
    echo -e "\n${BOLD}${CYN}Ping Test:${NC}"
    if ping -c 3 -W 1 "$ASSIGNED_IP" > /dev/null; then
        PING_RESULT="Success"
        success "Ping successful"
    else
        PING_RESULT="Failed"
        warn "Ping failed (check firewall or startup delay)"
    fi

    # Final report
    echo -e "\n${BOLD}${GRN}📋 FINAL ASSIGNMENT REPORT${NC}"
    printf "${BLU}%-16s${NC}: %s\n" "Container ID" "$LXC_ID"
    printf "${BLU}%-16s${NC}: %s\n" "Hostname" "$CT_NAME"
    printf "${BLU}%-16s${NC}: %s\n" "Assigned IP" "$ASSIGNED_IP"
    printf "${BLU}%-16s${NC}: %s\n" "Open Ports" "$OPEN_PORTS"
    printf "${BLU}%-16s${NC}: %s\n" "Ping Status" "$PING_RESULT"

    # Append structured log
    {
        echo "---"
        echo "$(date '+%Y-%m-%d %H:%M:%S')"
        echo "Container ID : $LXC_ID"
        echo "Hostname     : $CT_NAME"
        echo "Assigned IP  : $ASSIGNED_IP"
        echo "Open Ports   : $OPEN_PORTS"
        echo "Ping         : $PING_RESULT"
    } >> "$LOG_FILE"

    success "Report logged to $LOG_FILE"
fi
