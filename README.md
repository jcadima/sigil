<div style="text-align: center;">
  <img src="https://jcadima.dev/images/sigil_bg.png" alt="Sigil — Infrastructure Hardening Manifest Engine">
</div>

# Sigil — Infrastructure Hardening Manifest Engine

> SIGIL is what `composer audit` would be if it covered your entire infrastructure — Nginx, Docker, PHP, and your database not just your dependencies.

Sigil scans your actual server configuration files, scores findings by severity, generates executable patches, and tracks configuration drift between deploys. It is a CLI-first tool designed for developers and backend engineers managing self-hosted LEMP stacks.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Commands](#commands)
  - [scan](#sigil-scan)
  - [enforce](#sigil-enforce)
  - [snapshot](#sigil-snapshot)
  - [drift](#sigil-drift)
  - [rules](#sigil-rules)
- [How Fixes Work](#how-fixes-work)
- [Severity Model](#severity-model)
- [Rule Library](#rule-library)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Requirements

- PHP 8.3+
- Composer

Sigil uses four [standalone Symfony components](https://symfony.com/components) not the full framework. It runs on any Linux server that has PHP in `$PATH`.

---

## Installation

Install globally via Composer:

```bash
composer global require jcadima/sigil
```

Make sure your global Composer `bin` directory is in your `$PATH`. On most systems this is one of:

```bash
export PATH="$HOME/.composer/vendor/bin:$PATH"
# or
export PATH="$HOME/.config/composer/vendor/bin:$PATH"
```

Add that line to your `~/.bashrc` or `~/.zshrc` to make it permanent. After that, `sigil` is available system-wide.

Verify the installation:

```bash
sigil --version
```

---

## Commands

### `sigil scan`

Audits your project against the full rule library. Sigil auto-detects your stack (framework, web server, database engine) from `.env`, `docker-compose.yml`, and the file system no flags required in most cases.

```bash
sigil scan [path] [options]
```

**Arguments**

| Argument | Default | Description |
|----------|---------|-------------|
| `path` | current directory | Absolute or relative path to the project root being scanned |

**Options**

| Option | Description |
|--------|-------------|
| `--output=cli` | Human-readable terminal output with colored severity labels *(default)* |
| `--output=json` | Machine-readable JSON to stdout suitable for CI/CD pipelines and the dashboard |
| `--output=patch` | Generates unified diff files to `.sigil/patches/` for all patchable findings |
| `--env=production` | Override the detected environment context. Affects which rules fire and severity thresholds |
| `--stack=laravel-docker-nginx` | Skip auto-detection and declare the stack explicitly |
| `--compat=mariadb` | Force the MariaDB rule pack when `.env` has `DB_CONNECTION=mysql` but the image is actually MariaDB |

**Examples**

```bash
# Scan the current directory, display results in terminal
sigil scan

# Scan a specific project path
sigil scan /var/www/myapp

# Scan and output JSON (pipe to jq, send to CI, etc.)
sigil scan /var/www/myapp --output=json | jq '.findings[] | select(.severity == "CRITICAL")'

# Generate patch files for reviewable fixes
sigil scan /var/www/myapp --output=patch

# Force environment context if .env detection is ambiguous
sigil scan /var/www/myapp --env=production
```

**Sample output**

```
  SIGIL v1.0.0
  Detected: laravel · docker · nginx · mysql · production
  ─────────────────────────────────────────────────────────

  LARAVEL / PHP
  ✖ [CRITICAL] L001  APP_DEBUG=true (.env line 2)
               → sigil enforce --rule=L001
  ✖ [HIGH]     L012  disable_functions not set exec, shell_exec exposed
               → /etc/php/8.3/fpm/php.ini line 312
  ✓ [PASS]     L003  APP_KEY set
  ✓ [PASS]     L005  CSRF middleware present

  NGINX
  ✖ [CRITICAL] N010  .env not blocked in nginx config
               → Patch available: sigil scan --output=patch
  ✖ [MEDIUM]   N004  HSTS header missing
  ✓ [PASS]     N007  TLSv1/1.1 disabled

  DOCKER
  ✖ [CRITICAL] D002  Docker socket mounted in php-fpm container
  ✖ [HIGH]     D001  php-fpm running as root
  ✖ [HIGH]     D007  Port 3306 bound to 0.0.0.0 on host

  MYSQL
  ✖ [CRITICAL] M001  DB_USERNAME=root app connecting as superuser
  ✓ [PASS]     M004  MySQL 8.0 within support window

  ──────────────────────────────────────────────────────────
  Score: 44/100  Critical: 4  High: 3  Medium: 1  Low: 0
  Auto-fixable: 3 findings  |  run 'sigil enforce'
```

---

### `sigil enforce`

Applies auto-fixes for supported findings. Sigil **always writes a backup** before modifying any file. CRITICAL and HIGH findings are never auto-applied see [How Fixes Work](#how-fixes-work) for the full breakdown.

```bash
sigil enforce [options]
```

**Options**

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview every change that would be made without writing anything |
| `--rule=ID` | Apply only the fix for a single rule (e.g. `--rule=L001`) |

**Examples**

```bash
# Preview all pending auto-fixes without applying them
sigil enforce --dry-run

# Apply all eligible fixes interactively (prompts for confirmation)
sigil enforce

# Apply a single specific rule fix
sigil enforce --rule=L010

# Target a specific project path
sigil enforce /var/www/myapp --dry-run
```

**Interactive flow**

```
$ sigil enforce

  Backup written to .sigil/backups/php.ini.20260307_174800
  Backup written to .sigil/backups/.env.20260307_174800

  Pending changes:
    L001  .env           → APP_DEBUG=false
    L010  php.ini        → expose_php=Off
    L011  php.ini        → display_errors=Off
    L012  php.ini        → disable_functions=exec,shell_exec,passthru,proc_open,system

  Proceed? [y/N]: y

  ✓ Applied L001  ✓ Applied L010  ✓ Applied L011  ✓ Applied L012
```

Backups are stored in `.sigil/backups/` inside your project root and can be restored manually if needed.

---

### `sigil snapshot`

Saves the current configuration state as a signed baseline for drift comparison. Run this after a deploy or after applying fixes to record a known-good state.

```bash
sigil snapshot [path]
```

Snapshots are stored in `.sigil/snapshots/` and are HMAC-signed to detect tampering. Each snapshot captures parsed values from `.env`, `nginx.conf`, `docker-compose.yml`, `php.ini`, and database config files.

```bash
# Snapshot the current directory
sigil snapshot

# Snapshot a specific project
sigil snapshot /var/www/myapp
```

---

### `sigil drift`

Compares the current configuration state against the most recent stored snapshot. Use this after deploys, config changes, or when investigating unexpected changes.

```bash
sigil drift [path]
```

```bash
# Check for drift in the current directory
sigil drift

# Check a specific project
sigil drift /var/www/myapp
```

Drift detection flags any configuration value that changed since the last `sigil snapshot`. Removed rules, new environment variables, changed php.ini directives, and modified nginx blocks all appear as drift events.

---

### `sigil rules`

Lists all rules available for the detected (or specified) stack, with severity levels and short descriptions.

```bash
sigil rules [options]
```

**Options**

| Option | Description |
|--------|-------------|
| `--category=<name>` | Filter to a single rule category |

Available categories: `laravel`, `nginx`, `docker`, `mysql`, `mariadb`, `postgresql`

**Examples**

```bash
# List all rules for the auto-detected stack
sigil rules

# List only PostgreSQL rules
sigil rules --category=postgresql

# List only Nginx rules
sigil rules --category=nginx
```

---

## How Fixes Work

Sigil uses three distinct remediation modes depending on the severity and type of finding.

### Mode 1 — `sigil enforce` (auto-apply, LOW/INFO only)

Low-risk findings with safe, deterministic fixes are handled automatically. Sigil writes a backup first, then applies the change.

Auto-fixable rules:

| Rule | What gets fixed |
|------|----------------|
| L001 | Sets `APP_DEBUG=false` in `.env` |
| L006 | Corrects `storage/` directory permissions |
| L010 | Sets `expose_php=Off` in `php.ini` |
| L011 | Sets `display_errors=Off` in `php.ini` |
| L012 | Sets `disable_functions` in `php.ini` |

### Mode 2 — `sigil scan --output=patch` (review, then apply)

For MEDIUM findings and structural changes to Nginx or Docker config. Sigil generates the diff file you own the apply step.

```bash
$ sigil scan --output=patch
  Patches written to .sigil/patches/
    → nginx-security-headers.patch
    → nginx-block-env.patch

$ cat .sigil/patches/nginx-block-env.patch
  --- /etc/nginx/sites-available/myapp
  +++ /etc/nginx/sites-available/myapp.patched
  @@ -14,6 +14,10 @@
       root /var/www/myapp/public;
  +    # SIGIL N010 — Block direct .env access
  +    location ~ /\.env {
  +        deny all; return 404;
  +    }

$ patch /etc/nginx/sites-available/myapp < .sigil/patches/nginx-block-env.patch
$ nginx -t && nginx -s reload
```

### Mode 3 — Manual remediation guide (CRITICAL/HIGH)

Sigil never auto-applies CRITICAL or HIGH findings under any circumstance. Instead it outputs precise, actionable instructions with file references and recommended commands:

```
  D002 — MANUAL REMEDIATION
  Docker socket mounted in php-fpm gives container full host root access.
  This allows any web shell in your app to escape the container entirely.

  Remove from docker-compose.yml:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  ← delete this line

  After removing: docker compose down && docker compose up -d
```

---

## Severity Model

| Severity | Meaning | Auto-Fix |
|----------|---------|----------|
| **CRITICAL** | Active exploitation vector. Requires immediate action. Examples: `APP_DEBUG=true`, `.env` publicly accessible, Docker socket mounted. | Never |
| **HIGH** | Significant exposure with likely exploitability. Examples: container running as root, root DB user, world-writable `storage/`. | Never |
| **MEDIUM** | Exploitable under specific conditions. Examples: missing HSTS, weak SSL ciphers, no login rate limiting. | Manual (patch) |
| **LOW** | Best-practice deviation with low immediate risk. Examples: `server_tokens On`, `expose_php On`, no health check. | Yes |
| **INFO** | Informational, not a vulnerability. Examples: PHP version detected, framework version logged. | Yes |

---

## Rule Library

### Laravel / PHP (L001–L012)

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| L001 | `APP_DEBUG=true` in production `.env` | CRITICAL | Yes |
| L002 | `.env` file readable via HTTP (cross-checked with nginx config) | CRITICAL | Manual |
| L003 | `APP_KEY` not set or using a default value | CRITICAL | No |
| L004 | Session driver set to `file` with world-readable storage | HIGH | Manual |
| L005 | CSRF middleware removed from web middleware group | HIGH | No |
| L006 | `storage/` directory world-writable (chmod 0777) | HIGH | Yes |
| L007 | Rate limiting not applied to login/register routes | MEDIUM | Manual |
| L008 | Composer packages with known CVEs (via NVD API) | MEDIUM | No |
| L009 | PHP version below active security support window | MEDIUM | No |
| L010 | `expose_php=On` in `php.ini` — version leaked in HTTP headers | LOW | Yes |
| L011 | `display_errors=On` in `php.ini` | LOW | Yes |
| L012 | `disable_functions` not set — `exec`, `shell_exec`, `passthru`, `proc_open` exposed | HIGH | Yes |

### Nginx (N001–N011)

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| N001 | `server_tokens On` — nginx version exposed in response headers | LOW | Yes |
| N002 | Missing `X-Frame-Options` header (clickjacking vector) | MEDIUM | Yes |
| N003 | Missing `X-Content-Type-Options` header | LOW | Yes |
| N004 | Missing `Strict-Transport-Security` (HSTS) header | MEDIUM | Yes |
| N005 | Missing `Content-Security-Policy` header | MEDIUM | Manual |
| N006 | `autoindex On` — directory listing enabled | HIGH | Yes |
| N007 | Weak SSL protocols enabled (TLSv1.0, TLSv1.1) | HIGH | Yes |
| N008 | Weak SSL cipher suites configured | HIGH | Yes |
| N009 | No rate limiting on authentication endpoints | MEDIUM | Manual |
| N010 | No deny rule for `.env` — file publicly accessible | CRITICAL | Yes |
| N011 | `client_max_body_size` not configured (DoS vector) | LOW | Yes |

### Docker (D001–D009)

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| D001 | Container running as root (no `USER` directive in Dockerfile) | HIGH | Manual |
| D002 | Docker socket (`/var/run/docker.sock`) mounted in container | CRITICAL | Manual |
| D003 | Container using `latest` image tag — no pinned version | MEDIUM | No |
| D004 | `privileged: true` set on container | CRITICAL | Manual |
| D005 | No memory/CPU resource limits defined on any container | MEDIUM | Yes |
| D006 | Secrets passed as plain environment variables (not Docker secrets) | HIGH | Manual |
| D007 | Database port exposed to host on `0.0.0.0` (3306 or 5432) | HIGH | Manual |
| D008 | No health check defined for web-facing container | LOW | Yes |
| D009 | No `.dockerignore` — build context copies entire project | LOW | Yes |

### MySQL (M001–M005)

Loaded automatically when `DB_CONNECTION=mysql` is detected in `.env` or the `mysql` image is found in `docker-compose.yml`.

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| M001 | Root user used as application DB user (`DB_USERNAME=root`) | CRITICAL | Manual |
| M002 | MySQL port 3306 exposed to host network | HIGH | Manual |
| M003 | No SSL/TLS configured for MySQL connections | MEDIUM | Manual |
| M004 | `general_log=ON` in production (performance + data exposure) | LOW | Yes |
| M005 | MySQL version below active security support window | MEDIUM | No |

### MariaDB (MB001–MB005)

Loaded when `DB_CONNECTION=mariadb` is set, or when the `mariadb` image name is found in `docker-compose.yml`. Docker image detection takes priority over `.env` when both are readable.

> **Note on `unix_socket` auth:** MariaDB enables `unix_socket` authentication for root by default. Sigil treats this as a PASS. The MB001 root-user rule does not fire for a correctly configured MariaDB `unix_socket` setup unlike the equivalent MySQL rule, which would be a false positive here.

If your project has `DB_CONNECTION=mysql` but is actually running MariaDB, use the `--compat=mariadb` flag to force the correct rule pack:

```bash
sigil scan --compat=mariadb
```

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| MB001 | Root user used as application DB user | CRITICAL | Manual |
| MB002 | MariaDB port 3306 exposed to host network | HIGH | Manual |
| MB003 | No SSL/TLS for MariaDB connections | MEDIUM | Manual |
| MB004 | MariaDB version below active security support window | MEDIUM | No |
| MB005 | `STRICT_TRANS_TABLES` not in `sql_mode` — silent data truncation risk | MEDIUM | Manual |

### PostgreSQL (PG001–PG007)

Loaded when `DB_CONNECTION=pgsql` is set, or when the `postgres` image is found in `docker-compose.yml`.

> **Note on `pg_hba.conf`:** This file is often only readable from inside the database container. If Sigil cannot access it, PG003 and PG007 will be skipped and flagged as INFO with a note to run the scan from inside the container.

| Rule | Finding | Severity | Auto-Fix |
|------|---------|----------|----------|
| PG001 | Superuser used as application DB user (`DB_USERNAME=postgres`) | CRITICAL | Manual |
| PG002 | PostgreSQL port 5432 exposed to host network on `0.0.0.0` | HIGH | Manual |
| PG003 | `pg_hba.conf` contains `trust` authentication method | CRITICAL | Manual |
| PG004 | `ssl=off` in `postgresql.conf` — connections unencrypted | MEDIUM | Manual |
| PG005 | `log_connections` / `log_disconnections` disabled — no audit trail | LOW | Yes |
| PG006 | PostgreSQL version below active security support window | MEDIUM | No |
| PG007 | `pg_hba.conf` allows all hosts (`0.0.0.0/0`) without restriction | HIGH | Manual |

---

## Project Structure

```
sigil/
├── bin/sigil                       # Executable entry point
├── src/
│   ├── Application.php             # Bootstraps console, registers commands
│   ├── Commands/                   # scan, enforce, snapshot, drift, rules
│   ├── Parsers/                    # .env, nginx.conf, docker-compose.yml, php.ini, my.cnf, pg_hba.conf
│   ├── Rules/
│   │   ├── RuleInterface.php       # evaluate(), getSeverity(), getRemediation(), canAutoFix()
│   │   ├── Laravel/                # L001–L012
│   │   ├── Nginx/                  # N001–N011
│   │   ├── Docker/                 # D001–D009
│   │   ├── MySQL/                  # M001–M005
│   │   ├── MariaDB/                # MB001–MB005
│   │   └── PostgreSQL/             # PG001–PG007
│   ├── Fixers/                     # Write layer — separate from Rules
│   ├── Engine/
│   │   ├── ScanContext.php         # Data container passed to every rule
│   │   ├── StackDetector.php       # Auto-detects framework, web server, DB engine
│   │   ├── RuleEngine.php          # Loads rule packs, collects findings
│   │   ├── NvdClient.php           # NIST NVD API v2 with 24hr local cache
│   │   └── SnapshotManager.php     # HMAC-signed snapshots for drift detection
│   └── Reporters/                  # cli, json, patch output renderers
├── stubs/                          # Nginx and php.ini patch templates
└── tests/                          # Unit + integration tests with fixtures
```

The architecture follows a strict three-layer separation:

- **Rules** — read-only. They interrogate `ScanContext` and return findings. They never touch the filesystem.
- **Fixers** — the only layer that writes files. Always backs up before modifying.
- **Reporters** — render `FindingCollection` to the chosen output format.

---

## Contributing

Contributions are welcome. The most useful contributions are new rules, parser improvements, and bug reports with reproducible fixture cases.

### Getting started

```bash
git clone https://github.com/jcadima/sigil
cd sigil
composer install
./vendor/bin/phpunit
```

### Writing a new rule

Every rule implements `RuleInterface`. The interface has five methods:

```php
interface RuleInterface
{
    public function evaluate(ScanContext $context): FindingCollection;
    public function getSeverity(): Severity;
    public function getCategory(): string;
    public function getRemediation(): Remediation;
    public function canAutoFix(): bool;
    public function applyFix(ScanContext $context): FixResult;
}
```

The `evaluate()` method receives the fully parsed `ScanContext` and returns an empty `FindingCollection` on pass, or one with `Finding` objects on failure. Rules never read files directly they always work from the pre-parsed context.

The `applyFix()` method is only called by `EnforceCommand` and only if `canAutoFix()` returns `true`. **Only LOW and INFO severity rules may return `true` from `canAutoFix()`.**

After writing a rule, register it in `RuleEngine.php` and add unit tests under `tests/Unit/Rules/<Category>/`.

### Fixture-based testing

Integration tests use fixture directories under `tests/Fixtures/`. Each fixture set is a minimal project structure (`.env`, `nginx.conf`, `docker-compose.yml`, `php.ini`) representing a specific scenario. If your rule requires a new test scenario, add a fixture directory rather than mocking file reads.

### Rule naming conventions

| Category | Prefix | Example class name |
|----------|--------|--------------------|
| Laravel | `L` | `AppDebugEnabledRule` |
| Nginx | `N` | `EnvNotBlockedRule` |
| Docker | `D` | `DockerSocketMountedRule` |
| MySQL | `M` | `RootAsAppUserRule` |
| MariaDB | `MB` | `SqlModeStrictRule` |
| PostgreSQL | `PG` | `PgHbaTrustAuthRule` |

### Submitting changes

1. Fork the repository and create a branch from `main`
2. Add or modify code with corresponding tests
3. Run the full test suite: `./vendor/bin/phpunit`
4. Open a pull request with a clear description of what the rule detects and why it matters

For bug reports, please include the output of `sigil scan --output=json` (with sensitive values redacted) and the Sigil version (`sigil --version`).

---

## License

MIT see [LICENSE](LICENSE).
