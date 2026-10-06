# Reproducing the free5GC full-deployment extension

1. `git clone https://github.com/free5gc/free5gc-compose.git compose` (inside this directory)
2. Copy `docker-compose.override.yaml` (this directory) into `compose/`
3. In `compose/config/nrfcfg.yaml`, change `oauth: true` to `oauth: false`
   (see `docs/FREE5GC_FULL_DEPLOYMENT_RESULTS.md` for why this is
   necessary and explicitly out of scope for this result)
4. `cd udr_build && docker build --build-arg "UDR_COMMIT=86686276a7e226183ee786e3dd6714ec56c78fda^" -t free5gc-udr-custom:vulnerable .`
5. Still inside `udr_build/`: `docker build --build-arg "UDR_COMMIT=86686276a7e226183ee786e3dd6714ec56c78fda" -t free5gc-udr-custom:patched .`
6. `cd ..` back to `free5gc_full_deployment/`, then `python run_full_deployment_harness.py` (requires `NO_PAID_BACKEND=1` and `requests`)

## OAuth2 enforcement experiment (optional, see docs/FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md)

7. Copy `nrfcfg_oauth2.yaml` and `docker-compose.oauth2.yaml` (this
   directory) into `compose/config/` and `compose/` respectively (same
   pattern as step 2-3 - `compose/` itself is a cloned third-party repo
   and is gitignored, so these overrides live here, tracked, and get
   copied in).
8. `pip install pyjwt cryptography` if not already installed.
9. `python free5gc_oauth2_enforcement.py` - this activates the OAuth2
   override only for its own run and restores the default (OAuth2-off)
   stack afterward, so step 6 keeps working unmodified after this runs.
