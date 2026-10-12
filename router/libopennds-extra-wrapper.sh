#!/bin/sh
# Use the generated device map while preserving the native gateway identity.
if [ "${1:-}" = get_interface_by_ip ] && [ -s /etc/opennds-manager/networks.conf ]; then
    routed_if=$(ip -4 route get "$2" 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    primary=$(awk '$1=="primary" {print $2; exit}' /etc/opennds-manager/networks.conf)
    if [ -n "$routed_if" ] && [ -n "$primary" ] && awk -v dev="$routed_if" '$1=="extra" && $2==dev {found=1} END {exit !found}' /etc/opennds-manager/networks.conf; then
        printf '%s' "$primary"
        exit 0
    fi
fi
exec /usr/lib/opennds/libopennds-extra-base.sh "$@"
