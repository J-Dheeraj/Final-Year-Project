# Reproducing the OpenEMR transfer case (GHSA-q366-cv5v-83w8)

1. `git clone https://github.com/openemr/openemr.git _work/checkout` (inside this directory)
2. `docker build -f Dockerfile.php -t openemr-transfer-php:latest .`
3. `python run_harness.py` from this directory (requires `NO_PAID_BACKEND=1` and `requests`)

The harness itself creates and tears down the MariaDB container, the
PHP container, and the Docker network on each run - no other manual
setup is required. It checks out the vulnerable commit
(`b5313ea25f7928538eb793d4b4184ed4601d9afd`) and the fixed commit
(`50f789fad45ada625fe8d0faf0c7a9c15ef52aa5`) directly in
`_work/checkout/`, so that directory's git state changes between runs;
this is expected and matches the free5GC runtime harness's own
commit-checkout pattern.
