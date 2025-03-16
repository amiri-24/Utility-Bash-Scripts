#!/bin/bash
# --------------------------------------------
# GRE & IPIP Tunnel Setup Script for CentOS, AlmaLinux, and Ubuntu
# Supports both GRE and IP-IP Tunneling
# Allows Routing Specific IPv4 Ranges Through the Tunnel
# --------------------------------------------

# Function to validate IP addresses
function validate_ip() {
  local ip=$1
  local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if [[ $ip =~ $regex ]]; then
    return 0
  else
    echo "Invalid IP address: $ip"
    exit 1
  fi
}

# Function to validate CIDR notation
function validate_cidr() {
  local cidr=$1
  local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
  if [[ $cidr =~ $regex ]]; then
    return 0
  else
    echo "Invalid CIDR notation: $cidr"
    exit 1
  fi
}

# Prompt user for required values
read -p "Enter your local public IP: " LOCAL_IP
validate_ip "$LOCAL_IP"

read -p "Enter remote public IP: " REMOTE_IP
validate_ip "$REMOTE_IP"

read -p "Enter local tunnel IP (e.g., 192.168.90.1/30): " LOCAL_TUN_IP
read -p "Enter remote tunnel IP (e.g., 192.168.90.2): " REMOTE_TUN_IP

read -p "Enter tunnel interface name (e.g., tun1): " TUNNEL_IF
read -p "Enter tunnel name (e.g., my_tunnel): " TUNNEL_NAME
read -p "Enter routing name (e.g., my_route): " ROUTE_NAME

read -p "Enter tunnel mode (gre/ipip): " TUNNEL_MODE
if [[ "$TUNNEL_MODE" != "gre" && "$TUNNEL_MODE" != "ipip" ]]; then
  echo "Invalid tunnel mode. Choose 'gre' or 'ipip'."
  exit 1
fi

# Prompt user for routing IPv4 ranges
declare -a ROUTE_RANGES
while true; do
  read -p "Enter an IPv4 range to route through the tunnel (CIDR format, leave empty to finish): " RANGE
  if [[ -z "$RANGE" ]]; then
    break
  fi
  validate_cidr "$RANGE"
  ROUTE_RANGES+=("$RANGE")
done

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Load required kernel module
modprobe "$TUNNEL_MODE"

# Create tunnel
ip tunnel add "$TUNNEL_IF" mode "$TUNNEL_MODE" local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255

# Bring up the tunnel interface
ip link set "$TUNNEL_IF" up

# Assign IP to tunnel interface
ip addr add "$LOCAL_TUN_IP" dev "$TUNNEL_IF"

# Add routing rules
for CIDR in "${ROUTE_RANGES[@]}"; do
  ip route add "$CIDR" dev "$TUNNEL_IF"
done

# Confirm setup
echo "--------------------------------------------"
echo "Tunnel configured successfully with the following parameters:"
echo "Local IP:         $LOCAL_IP"
echo "Remote IP:        $REMOTE_IP"
echo "Local Tunnel IP:  $LOCAL_TUN_IP"
echo "Remote Tunnel IP: $REMOTE_TUN_IP"
echo "Interface:        $TUNNEL_IF"
echo "Tunnel Name:      $TUNNEL_NAME"
echo "Routing Name:     $ROUTE_NAME"
echo "Tunnel Mode:      $TUNNEL_MODE"
echo "Routed IPv4 Ranges:"
for CIDR in "${ROUTE_RANGES[@]}"; do
  echo "  - $CIDR"
done
echo "--------------------------------------------"
