#!/bin/bash
set -euo pipefail

TABLE_NAME="inode_modern_guard"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

init_guard() {
    nft -f - << 'EOF'
add table inet inode_modern_guard
add set inet inode_modern_guard allowed_cgroups { type cgroupsv2; }
add chain inet inode_modern_guard input { type filter hook input priority -10; policy accept; }
add chain inet inode_modern_guard output { type filter hook output priority 0; policy accept; }
flush chain inet inode_modern_guard input
flush chain inet inode_modern_guard output
add rule inet inode_modern_guard input iifname != "lo" udp dport { 50000, 50001, 50002 } drop
add rule inet inode_modern_guard output udp dport { 50000, 50001, 50002 } socket cgroupv2 level 2 @allowed_cgroups accept
add rule inet inode_modern_guard output udp dport { 50000, 50001, 50002 } drop
EOF
}

cleanup_guard() {
    exec /usr/bin/python3 -I -B "$SCRIPT_DIR/firewall.py" --teardown
}

case "${1:-}" in
    init)
        init_guard
        ;;
    cleanup)
        cleanup_guard
        ;;
    check)
        exec /usr/bin/python3 -I -B "$SCRIPT_DIR/firewall.py"
        ;;
    *)
        echo "Usage: $0 {init|cleanup|check}" >&2
        exit 1
        ;;
esac
