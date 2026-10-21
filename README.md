# PHP update helper

This repository inventories PHP and applies operating-system package updates. It
does **not** independently establish that a CVE exists, that a target version is
correct, or that every installed PHP runtime was remediated. Before making an
incident decision, confirm the CVE record, fixed versions, and any vendor
backports with:

- [PHP downloads](https://www.php.net/downloads.php)
- Your operating system's security advisory and package changelog
- The PHP package/distribution provider for your application or hosting platform

## Disclaimer

This helper is provided to the community in good faith to assist with PHP
inventory and update operations. Its author has no intention to harm users,
systems, or data. You are solely responsible for reviewing the scripts,
validating their suitability for your environment, maintaining backups, testing
where appropriate, obtaining required approvals, and deciding whether to run
them. Running either script, especially with administrative privileges, is at
your own risk.

The supplied report identifies `CVE-2026-109618` and `CVE-2026-109619` and
targets PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. At the time this helper was
prepared, those claims could not be confirmed from an official PHP advisory; do
not treat a script message as proof of mitigation.

## Linux

1. Log in through your approved administrative channel and take an application
   backup or snapshot according to your change process.
2. Copy this repository to the host. Do **not** run an internet-downloaded script
   as root until you have reviewed it.
3. Inspect PHP installations and web/PHP services:

   ```bash
   chmod +x php_update.sh
   ./php_update.sh --check
   ```

4. Check the installed package's changelog/security advisory. A distribution
   may backport a fix without changing the upstream-looking version enough to
   satisfy the supplied target.
5. During an approved maintenance window, apply available vendor PHP updates:

   ```bash
   sudo ./php_update.sh --apply
   ```

   Add `--yes` only for an approved non-interactive automation run.
6. Verify the post-update output. Confirm the running handler and not only CLI:

   ```bash
   php -v
   systemctl status php*-fpm apache2 httpd nginx
   ```

   Restart any application-specific workers (for example, queue workers) using
   that application's documented procedure.
7. Find images and rebuild/redeploy every one that includes PHP. Host package
   updates do not modify container layers:

   ```bash
   docker ps --format 'table {{.Names}}\t{{.Image}}'
   docker compose build --pull
   docker compose up -d --force-recreate
   ```

   Use the deployment process for Kubernetes, OpenShift, or another orchestrator
   instead of these Docker Compose commands.

Supported automatic Linux package managers are APT, DNF, YUM, Zypper, Pacman,
and APK. Source builds, custom PHP prefixes, containers, and control-panel
managed PHP must be updated through their respective vendors.

## Windows

1. Take an approved application backup/snapshot and open **PowerShell as
   Administrator**.
2. Change to the repository directory and audit common PHP locations:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\php_update.ps1
   ```

3. Verify the affected application's PHP distribution and fixed-version guidance.
   PHP installed by XAMPP, WampServer, an IIS application, a manually extracted
   ZIP, or a hosting/control-panel product must be upgraded through that product.
4. If PHP was installed through WinGet, Chocolatey, or Scoop, preview then apply
   the package-manager update:

   ```powershell
   .\php_update.ps1 -Apply -WhatIf
   .\php_update.ps1 -Apply
   ```

5. Restart IIS if the host uses it:

   ```powershell
   .\php_update.ps1 -RestartServices
   ```

   For Apache, Nginx, PHP FastCGI, or another service manager, restart the
   specific service according to its vendor documentation.
6. Validate the runtime loaded by the web application, not only `php.exe`:

   ```powershell
   php.exe -v
   Get-Service W3SVC
   ```

7. Rebuild and redeploy container images separately from a Docker-enabled
   administrative environment.

## Safety notes

- Test updates in a representative non-production environment when the response
  window permits.
- Use the package and platform vendors' advisory as the source of truth. Do not
  force an upstream version over a supported vendor build merely because its
  display version differs.
- The scripts fail on package-manager errors and do not download arbitrary PHP
  archives or modify container images automatically.
