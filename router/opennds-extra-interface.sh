#!/bin/sh
# Generated LAN attachment support for openNDS 10.3.1.
set -eu
config=/etc/opennds-manager/networks.conf
guard_file=/etc/opennds-manager/networks-guard.nft

reconcile() {
    [ -s "$config" ] && [ -s "$guard_file" ] || return 1
    checksum=$(sha256sum "$guard_file" | awk '{print $1}')
    previous=$(cat /tmp/opennds-networks-guard-sum 2>/dev/null || true)
    if [ "$checksum" != "$previous" ] || ! nft list table inet nds_extra_guard >/dev/null 2>&1; then
        guard_batch=$(mktemp /tmp/nds-network-guard.XXXXXX)
        if nft list table inet nds_extra_guard >/dev/null 2>&1; then
            echo 'delete table inet nds_extra_guard' > "$guard_batch"
        fi
        cat "$guard_file" >> "$guard_batch"
        if ! nft -c -f "$guard_batch" || ! nft -f "$guard_batch"; then
            rm -f "$guard_batch"
            return 1
        fi
        rm -f "$guard_batch"
        printf '%s' "$checksum" > /tmp/opennds-networks-guard-sum
    fi
    nft list chain ip nds_filter ndsNET 2>/dev/null | grep -q 'counter.*reject' || return 1
    nft list chain ip nds_filter ndsNET | grep -q '0x00030000 == 0x00030000' || return 1
    rules=$(mktemp /tmp/nds-network-rules.XXXXXX)
    wanted=$(mktemp /tmp/nds-network-wanted.XXXXXX)
    trap 'rm -f "$rules" "$wanted"' EXIT HUP INT TERM
    while read -r table chain direction target; do
        existing=$(nft -a list chain ip "$table" "$chain") || return 1
        while read -r kind dev; do
            [ "$kind" = extra ] || continue
            tag="manager-extra-$dev-$table-$chain-$target"
            printf '%s\n' "$tag" >> "$wanted"
            if ! printf '%s\n' "$existing" | grep -Fq "comment \"$tag\""; then
                printf 'add rule ip %s %s %s "%s" counter jump %s comment "%s"\n' \
                    "$table" "$chain" "$direction" "$dev" "$target" "$tag" >> "$rules"
            fi
        done < "$config"
    done <<'DISPATCH'
nds_mangle ndsPRE iifname ndsTRU
nds_mangle ndsPRE iifname ndsOUT
nds_mangle ndsPOST oifname ndsINC
nds_mangle ndsINC oifname ndsDLR
nds_mangle ndsINC oifname nds_ft_INC
nds_nat ndsPRE iifname ndsOUT
nds_filter ndsINP iifname ndsRTR
nds_filter ndsFWD iifname ndsNET
DISPATCH
    # A native chain can have several dispatch targets. Compare the complete
    # desired tag set and delete each obsolete rule only once per chain.
    while read -r table chain; do
        existing=$(nft -a list chain ip "$table" "$chain") || return 1
        printf '%s\n' "$existing" | sed -n 's/.*comment "\(manager-extra-[^"]*\)".*# handle \([0-9]*\).*/\1 \2/p' |
        while read -r tag handle; do
            if ! grep -Fxq "$tag" "$wanted"; then
                printf 'delete rule ip %s %s handle %s\n' "$table" "$chain" "$handle" >> "$rules"
            fi
        done
    done <<'CHAINS'
nds_mangle ndsPRE
nds_mangle ndsPOST
nds_mangle ndsINC
nds_nat ndsPRE
nds_filter ndsINP
nds_filter ndsFWD
CHAINS
    if [ -s "$rules" ]; then
        nft -c -f "$rules" && nft -f "$rules" || return 1
        logger -t opennds-extra 'Reconciled discovered LAN attachments'
    fi
    rm -f "$rules" "$wanted"
    trap - EXIT HUP INT TERM
}

if [ "${1:-}" = once ]; then
    reconcile
else
    while :; do
        reconcile || logger -t opennds-extra 'Waiting for compatible openNDS chains; selected LANs remain guarded'
        sleep 3
    done
fi
