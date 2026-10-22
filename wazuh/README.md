# Wazuh for free5GC experiment integrity and logs

## Role in the FYP

Use Wazuh only as supporting telemetry for the free5GC runtime case study. It records changes to the experiment inputs and evidence bundle, and collects the vulnerable and patched UDR process logs. It does not decide whether an exploit succeeded or a patch worked. Keep the harness's HTTP responses, benign checks, and verdict logic as the source of those conclusions.

## Requirements

- Docker Desktop with the WSL 2 backend and Docker Compose
- Git on PATH
- At least 4 CPU cores, 8 GB RAM, and 50 GB free disk for the single-node stack
- WSL 2 setting `vm.max_map_count=262144`

For a Windows host, open a WSL 2 distribution and run:

```sh
sudo sysctl -w vm.max_map_count=262144
```

The setting resets when the Docker host restarts. See the official Wazuh Docker deployment guide for persistent configuration.

## Start the local stack

From the repository root in PowerShell:

```powershell
.\wazuh\install.ps1
```

The script clones the official `wazuh/wazuh-docker` repository at **v4.14.9**, generates self-signed certificates, and starts the single-node stack. Published services bind to loopback only. Open the dashboard at <https://localhost:8443>.

The upstream demo credentials are `admin` / `SecretPassword`. Change them before exposing the stack or connecting remote agents. Your browser will warn about the self-signed dashboard certificate.

To stop the stack while preserving its data:

```powershell
Push-Location .\wazuh\.wazuh-docker\single-node
docker compose down
Pop-Location
```

## Collect the free5GC experiment signals

Install the native Wazuh agent on the endpoint where the free5GC Docker experiment runs. The Windows host agent can monitor local project files. For Docker event monitoring, install/configure the agent on the Docker server as described by Wazuh; that is a separate optional setup and depends on where the Docker daemon runs.

Copy the relevant entries from [agent-ossec.conf.example](agent-ossec.conf.example) into the agent's existing `ossec.conf`, replace the checkout path, and restart the agent. The FIM scope targets `free5gc_full_deployment` while excluding the cloned upstream `compose` directory. It records changes to the harness, build configuration, and evidence bundle. The log collectors read the vulnerable and patched UDR process logs written by `run_full_deployment_harness.py`.

Run the harness as usual. In Wazuh, inspect the File Integrity Monitoring events and the collected process logs around the experiment timestamps.

## How to use the telemetry in the report

Keep the evaluation small and controlled:

1. Run the vulnerable and patched free5GC cases with the same harness and deployment settings.
2. Confirm that Wazuh records the expected evidence-bundle changes and receives both UDR process logs.
3. Record log completeness and ingestion delay. Use a benign run to establish the expected background event volume.
4. Treat these signals as experiment context and integrity history. They do not prove exploitability, patch correctness, or tamper-proof chain of custody. Wazuh will not automatically detect arbitrary application-layer exploits without suitable logs and detection rules.

This gives the FYP an auditable view of what changed around a test run, while keeping the core claim tied to the project's existing dynamic checks.

## Official references

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh file integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html)
- [Using Wazuh to monitor Docker](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html)
- [Wazuh Windows agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
