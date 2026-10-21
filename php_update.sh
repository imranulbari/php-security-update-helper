#!/usr/bin/env bash
#
# PHP host updater and verifier.
# This script updates packages supplied by the operating system vendor. It does
# not patch PHP installed in containers, custom prefixes, or source builds.

set -uo pipefail

readonly PROVIDED_CVES="CVE-2026-109618, CVE-2026-109619"
declare -Ar PROVIDED_FIXED_VERSIONS=(
    ["8.5"]="8.5.12"
    ["8.4"]="8.4.27"
    ["8.3"]="8.3.36"
    ["8.2"]="8.2.35"
)

MODE="check"
ASSUME_YES=false

usage() {
    cat <<'EOF'
Usage: sudo ./php_update.sh [--check | --apply] [--yes]

  --check  Inventory PHP installations and running services (default).
  --apply  Apply the operating system's available PHP package updates.
  --yes    Do not ask before applying updates.
  --help   Show this help.

The reported fixed versions are supplied targets, not an authoritative security
advisory. Confirm the CVE and package status with PHP and your OS vendor before
using the result as evidence of remediation.
EOF
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

version_at_least() {
    local current=$1 target=$2
    [ "$(printf '%s\n%s\n' "$target" "$current" | sort -V | head -n 1)" = "$target" ]
}

detect_package_manager() {
    local manager
    for manager in apt-get dnf yum zypper pacman apk; do
        if command -v "$manager" >/dev/null 2>&1; then
            printf '%s\n' "$manager"
            return
        fi
    done
    return 1
}

find_php_binaries() {
    local binary
    {
        command -v php 2>/dev/null || true
        compgen -G '/usr/bin/php[0-9]*' || true
        compgen -G '/usr/local/bin/php[0-9]*' || true
    } | awk '!seen[$0]++' | sort
}

print_php_inventory() {
    local binary version branch target
    local found=false

    log "Installed PHP command-line binaries:"
    while IFS= read -r binary; do
        [ -n "$binary" ] || continue
        found=true
        version=$("$binary" -r 'echo PHP_VERSION;' 2>/dev/null || true)
        branch=$(printf '%s' "$version" | awk -F. 'NF >= 2 { print $1 "." $2 }')
        target=${PROVIDED_FIXED_VERSIONS[$branch]-}

        if [ -z "$version" ]; then
            printf '  %s: version could not be read\n' "$binary"
        elif [ -n "$target" ] && version_at_least "$version" "$target"; then
            printf '  %s: %s (meets supplied target %s)\n' "$binary" "$version" "$target"
        elif [ -n "$target" ]; then
            printf '  %s: %s (below supplied target %s)\n' "$binary" "$version" "$target"
        else
            printf '  %s: %s (no supplied target for PHP %s)\n' "$binary" "$version" "${branch:-unknown}"
        fi
    done < <(find_php_binaries)

    if [ "$found" = false ]; then
        log "  No PHP command-line binary was found in standard locations."
    fi
}

print_running_services() {
    local service
    log
    log "PHP-related services:"
    if command -v systemctl >/dev/null 2>&1; then
        while IFS= read -r service; do
            [ -n "$service" ] && printf '  %s\n' "$service"
        done < <(systemctl list-units --type=service --state=running --no-legend 2>/dev/null |
            awk '$1 ~ /^(php.*fpm|apache2|httpd|nginx)\.service$/ { print $1 }')
    elif command -v service >/dev/null 2>&1; then
        service --status-all 2>&1 | grep -E 'php.*fpm|apache2|httpd|nginx' || true
    else
        warn "Could not enumerate services; restart the PHP handler and web server manually."
    fi
}

restart_services() {
    local service restarted=false
    command -v systemctl >/dev/null 2>&1 || {
        warn "No systemctl detected. Restart PHP-FPM and the web server manually."
        return
    }

    while IFS= read -r service; do
        [ -n "$service" ] || continue
        log "Restarting $service..."
        systemctl restart "$service" || die "Failed to restart $service. Inspect: systemctl status $service"
        restarted=true
    done < <(systemctl list-units --type=service --state=running --no-legend 2>/dev/null |
        awk '$1 ~ /^(php.*fpm|apache2|httpd|nginx)\.service$/ { print $1 }')

    if [ "$restarted" = false ]; then
        warn "No running PHP-FPM, Apache, or Nginx systemd services were found."
    fi
}

apply_updates() {
    local manager=$1
    case "$manager" in
        apt-get)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y 'php*'
            ;;
        dnf)
            dnf upgrade -y 'php*'
            ;;
        yum)
            yum update -y 'php*'
            ;;
        zypper)
            zypper --non-interactive update 'php*'
            ;;
        pacman)
            pacman -Syu --noconfirm
            ;;
        apk)
            apk update
            apk upgrade 'php*'
            ;;
        *)
            die "Unsupported package manager: $manager"
            ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) MODE="check" ;;
        --apply) MODE="apply" ;;
        --yes) ASSUME_YES=true ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1. Use --help for usage." ;;
    esac
    shift
done

log "PHP host inventory for supplied CVEs: $PROVIDED_CVES"
log "Supplied fixed versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35"
warn "Verify these CVE claims and fixed versions against official PHP and OS-vendor advisories."
log
print_php_inventory
print_running_services

if [ "$MODE" = "check" ]; then
    log
    log "Check complete. This does not assess PHP in containers, nonstandard paths, or source builds."
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "Run --apply as root, for example: sudo ./php_update.sh --apply"
manager=$(detect_package_manager) || die "No supported package manager found."

if [ "$ASSUME_YES" = false ]; then
    printf '\nApply available PHP updates with %s and restart detected services? [y/N] ' "$manager"
    read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) log "No changes made."; exit 0 ;;
    esac
fi

apply_updates "$manager"
restart_services
log
log "Post-update inventory:"
print_php_inventory
warn "Rebuild and redeploy every image that contains PHP; this host update does not modify images or containers."
