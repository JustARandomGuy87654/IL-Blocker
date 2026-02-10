#!/usr/bin/env bash
# il_block_manager.sh
# Works on Arch (pacman) and Debian/Ubuntu (apt)
# Must be run as root

set -euo pipefail
IFS=$'\n\t'

IL_V4_URL="https://www.ipdeny.com/ipblocks/data/countries/il.zone"
IL_V6_URL="https://www.ipdeny.com/ipv6/ipaddresses/aggregated/il-aggregated.zone"

TABLE="il_block"
SET4="il_ipv4"
SET6="il_ipv6"

DNSMASQ_BASE="/etc/dnsmasq.d/il-base.conf"
DNSMASQ_CUSTOM="/etc/dnsmasq.d/il-custom.conf"
HOSTS_MARK_START="# IL_BLOCK START"
HOSTS_MARK_END="# IL_BLOCK END"
HOSTS_TAG="# IL_BLOCK"

DOH_IPS=( "1.1.1.1" "1.0.0.1" "8.8.8.8" "8.8.4.4" "9.9.9.9" "149.112.112.112" )

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root."
    exit 1
  fi
}

detect_package_manager() {
  if command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v apt >/dev/null 2>&1; then
    echo "apt"
  else
    echo "unknown"
  fi
}

install_deps() {
  pm="$(detect_package_manager)"
  if [ "$pm" = "pacman" ]; then
    pacman -Sy --noconfirm nftables dnsmasq curl || true
  elif [ "$pm" = "apt" ]; then
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y nftables dnsmasq curl || true
  else
    echo "Unsupported distro. Install nftables, dnsmasq and curl manually."
  fi
}

restart_dnsmasq() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart dnsmasq || true
  else
    service dnsmasq restart || true
  fi
}

add_hosts_entry() {
  local domain="$1"
  if ! grep -qF "$HOSTS_MARK_START" /etc/hosts 2>/dev/null; then
    printf "%s\n%s\n%s\n" "$HOSTS_MARK_START" "$HOSTS_MARK_END" >> /etc/hosts
  fi
  if ! grep -qF "$domain $HOSTS_TAG" /etc/hosts 2>/dev/null; then
    sed -i "/$HOSTS_MARK_END/i 0.0.0.0 $domain $HOSTS_TAG" /etc/hosts
  fi
}

remove_hosts_entry() {
  local domain="$1"
  sed -i "\,0.0.0.0 $domain $HOSTS_TAG,d" /etc/hosts || true
}

list_custom_domains() {
  if [ -f "$DNSMASQ_CUSTOM" ]; then
    grep -oP '(?<=address=/).*(?=/0.0.0.0)' "$DNSMASQ_CUSTOM" 2>/dev/null || true
  fi
}

is_il_domain() {
  case "$1" in
    *.il) return 0 ;;
    *) return 1 ;;
  esac
}

create_nft_table_and_chains() {
  nft delete table inet "$TABLE" 2>/dev/null || true

  nft add table inet "$TABLE"

  nft add chain inet "$TABLE" input  "{ type filter hook input priority 0; policy accept; }"
  nft add chain inet "$TABLE" output "{ type filter hook output priority 0; policy accept; }"

  nft add set inet "$TABLE" "$SET4" "{ type ipv4_addr; flags interval; }"
  nft add set inet "$TABLE" "$SET6" "{ type ipv6_addr; flags interval; }"
}

populate_nft_sets() {
  echo "[i] Populating Israel IP lists (this may take a few seconds)..."
  if command -v curl >/dev/null 2>&1; then
    # v4
    curl -fsSL "$IL_V4_URL" | while read -r ip; do
      if [ -n "$ip" ]; then
        nft add element inet "$TABLE" "$SET4" "{ $ip }" 2>/dev/null || true
      fi
    done
    # v6
    curl -fsSL "$IL_V6_URL" | while read -r ip; do
      if [ -n "$ip" ]; then
        nft add element inet "$TABLE" "$SET6" "{ $ip }" 2>/dev/null || true
      fi
    done
  else
    echo "curl not found; cannot populate ip lists."
  fi
}

add_nft_rules() {
  # block IPs
  nft add rule inet "$TABLE" output ip daddr @"$SET4" counter log prefix "IL_IPV4 " drop 2>/dev/null || true
  nft add rule inet "$TABLE" output ip6 daddr @"$SET6" counter log prefix "IL_IPV6 " drop 2>/dev/null || true

  # kill QUIC (UDP 443)
  nft add rule inet "$TABLE" output udp dport 443 counter log prefix "IL_QUIC " drop 2>/dev/null || true

  # kill DoH by blocking connections to known resolvers on port 443
  for ip in "${DOH_IPS[@]}"; do
    nft add rule inet "$TABLE" output ip daddr "$ip" tcp dport 443 counter log prefix "IL_DOH " drop 2>/dev/null || true
  done

  # kill DoT
  nft add rule inet "$TABLE" output tcp dport 853 counter log prefix "IL_DOT " drop 2>/dev/null || true

  # force all outgoing DNS to local resolver (redirect to :53)
  # note: redirect in output chain is supported on many systems; if it errors, user can remove/adjust
  nft add rule inet "$TABLE" output udp dport 53 redirect to :53 2>/dev/null || true
  nft add rule inet "$TABLE" output tcp dport 53 redirect to :53 2>/dev/null || true
}

enable_firewall_full() {
  echo "[+] Setting up nftables rules..."
  create_nft_table_and_chains
  populate_nft_sets
  add_nft_rules
  echo "[+] nftables rules applied."
}

delete_nft_table() {
  nft delete table inet "$TABLE" 2>/dev/null || true
}

enable_dnsmasq_base() {
  echo "[+] Creating dnsmasq base + custom files..."
  mkdir -p /etc/dnsmasq.d
  cat > "$DNSMASQ_BASE" <<'EOF'
# Global .il block (base)
address=/.il/0.0.0.0
address=/.il/::
EOF
  touch "$DNSMASQ_CUSTOM"
  chmod 644 "$DNSMASQ_BASE" "$DNSMASQ_CUSTOM"
  systemctl enable --now dnsmasq 2>/dev/null || true
  restart_dnsmasq
  echo "[+] dnsmasq configured."
}

add_domain_persistent() {
  local domain="$1"
  if ! is_il_domain "$domain"; then
    echo "❌ Only .il domains are allowed."
    return 1
  fi
  if grep -qF "address=/$domain/0.0.0.0" "$DNSMASQ_CUSTOM" 2>/dev/null; then
    echo "⚠️ $domain already in custom list."
    return 0
  fi
  echo "address=/$domain/0.0.0.0" >> "$DNSMASQ_CUSTOM"
  echo "address=/$domain/::" >> "$DNSMASQ_CUSTOM"
  add_hosts_entry "$domain"
  restart_dnsmasq
  echo "✅ $domain added (dnsmasq + /etc/hosts)."
}

remove_domain_persistent() {
  local domain="$1"
  if ! is_il_domain "$domain"; then
    echo "❌ Only .il domains are allowed."
    return 1
  fi
  if [ ! -f "$DNSMASQ_CUSTOM" ]; then
    echo "No custom list present."
    return 1
  fi
  if ! grep -qF "address=/$domain/0.0.0.0" "$DNSMASQ_CUSTOM" 2>/dev/null; then
    echo "⚠️ $domain not present in custom list."
    return 0
  fi
  sed -i "\,address=/$domain/0.0.0.0,d" "$DNSMASQ_CUSTOM" || true
  sed -i "\,address=/$domain/::,d" "$DNSMASQ_CUSTOM" || true
  remove_hosts_entry "$domain"
  restart_dnsmasq
  echo "✅ $domain removed."
}

disable_enforcement() {
  echo "[!] Disabling enforcement (removes nftables table)."
  delete_nft_table
  echo "✅ Enforcement disabled. dnsmasq config and custom domains are still preserved."
}

purge_everything() {
  echo "!!! PURGE ALL: This will remove nftables table, dnsmasq base & custom files, and hosts entries created by this script."
  read -r -p "Type 'PURGE' to confirm irreversible removal: " confirm
  if [ "$confirm" != "PURGE" ]; then
    echo "Aborted."
    return 1
  fi
  delete_nft_table
  rm -f "$DNSMASQ_BASE" "$DNSMASQ_CUSTOM"
  # remove hosts lines with the IL_BLOCK tag
  sed -i "\,${HOSTS_TAG},d" /etc/hosts || true
  # remove marker lines if present
  sed -i "/$HOSTS_MARK_START/d" /etc/hosts || true
  sed -i "/$HOSTS_MARK_END/d" /etc/hosts || true
  restart_dnsmasq
  echo "✅ All artifacts removed. You may want to inspect /etc/hosts manually."
}

### INTERACTIVE MENU
show_menu() {
  cat <<'MENU'

===== Israel Block Manager =====
1) Add domain (.il only)
2) Remove domain
3) List custom domains
4) Disable enforcement (keep configs)
5) Purge everything (dangerous)
6) Exit
MENU
}

main_loop() {
  while true; do
    show_menu
    read -r -p "Choice: " choice
    case "$choice" in
      1)
        read -r -p "Enter domain (must end with .il): " domain
        domain="${domain// /}"  
        if [ -z "$domain" ]; then
          echo "No domain entered."
          continue
        fi
        add_domain_persistent "$domain" || true
        ;;
      2)
        echo "Custom domains:"
        mapfile -t arr < <(list_custom_domains)
        if [ "${#arr[@]}" -eq 0 ]; then
          echo " (none)"
          continue
        fi
        nl -w2 -s'. ' -ba < <(printf "%s\n" "${arr[@]}")
        read -r -p "Enter number to remove or domain name: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]]; then
          idx=$((sel-1))
          if [ "$idx" -lt 0 ] || [ "$idx" -ge "${#arr[@]}" ]; then
            echo "Invalid index."
            continue
          fi
          domain="${arr[$idx]}"
        else
          domain="$sel"
        fi
        remove_domain_persistent "$domain" || true
        ;;
      3)
        echo "--- custom domains ---"
        list_custom_domains || true
        echo "----------------------"
        ;;
      4)
        disable_enforcement
        ;;
      5)
        purge_everything
        ;;
      6)
        echo "Bye."
        exit 0
        ;;
      *)
        echo "Invalid choice."
        ;;
    esac
  done
}

require_root
echo "== Israel Block Manager =="
echo "[i] Installing deps (if missing)..."
install_deps
echo "[i] Enabling base firewall + dnsmasq (this may take a moment)..."
enable_firewall_full
enable_dnsmasq_base
echo "[✓] Base blocking enabled. Custom domains preserved in $DNSMASQ_CUSTOM"
echo

main_loop
