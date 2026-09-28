# Reproducing the free5GC full-deployment extension

1. `git clone https://github.com/free5gc/free5gc-compose.git compose` (inside this directory)
2. Copy `docker-compose.override.yaml` (this directory) into `compose/`
3. In `compose/config/nrfcfg.yaml`, change `oauth: true` to `oauth: false`
   (see `docs/FREE5GC_FULL_DEPLOYMENT_RESULTS.md` for why this is
   necessary and explicitly out of scope for this result)
4. `cd udr_build && docker build --build-arg "UDR_COMMIT=86686276a7e226183ee786e3dd6714ec56c78fda^" -t free5gc-udr-custom:vulnerable .`
5. Still inside `udr_build/`: `docker build --build-arg "UDR_COMMIT=86686276a7e226183ee786e3dd6714ec56c78fda" -t free5gc-udr-custom:patched .`
6. `cd ..` back to `free5gc_full_deployment/`, then `python run_full_deployment_harness.py` (requires `NO_PAID_BACKEND=1` and `requests`)
