# Wazuh for FYP result integrity and experiment logs

## Role in the FYP

Use Wazuh only as a supporting integrity and observability layer for the results already produced by the FYP. Its File Integrity Monitoring (FIM) can baseline the current result files and report changes made after the agent is configured. It can also collect the available vulnerable and patched free5GC UDR process logs. It cannot recreate alerts or runtime telemetry for past runs, and it does not decide whether an exploit succeeded or a patch worked. The harness's HTTP responses, benign checks, and verdict logic remain the source of those conclusions.

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

## Monitor the existing result bundles

Install the native Wazuh agent on the endpoint where the free5GC Docker experiment runs. The Windows host agent can monitor local project files. For Docker event monitoring, install/configure the agent on the Docker server as described by Wazuh; that is a separate optional setup and depends on where the Docker daemon runs.

Copy the relevant entries from [agent-ossec.conf.example](agent-ossec.conf.example) into the agent's existing `ossec.conf`, replace the checkout path, and restart the agent. FIM covers the existing evidence folders for the minimal and full free5GC cases, the OpenEMR transfer case, and `reports/reachability`. The agent establishes its baseline when configured; it can report later changes to those files, but it cannot prove whether a result was altered before that baseline. The two log collectors point to the vulnerable and patched UDR process logs in the full free5GC bundle.

The result bundles are already present, so you can configure the agent against them without rerunning the experiments. In Wazuh, confirm that files from each monitored folder are inventoried. For new controlled checks, inspect subsequent FIM events and the collected UDR process logs. Do not change the original evidence to test detection; use a disposable copy.

## How to use the telemetry in the report

Keep the evaluation small and controlled:

1. Configure FIM on the existing result folders and record the baseline inventory.
2. Check that the expected result files from the free5GC and OpenEMR cases and the reachability reports are visible in Wazuh.
3. On a disposable copy, make one harmless test-file change and record whether Wazuh reports it and how long ingestion takes. Record completeness and delay for the available UDR logs separately.
4. Report Wazuh as post-baseline integrity monitoring and log collection. These signals do not prove exploitability, patch correctness, or tamper-proof chain of custody. Wazuh will not automatically detect arbitrary application-layer exploits without suitable logs and detection rules.

This gives the FYP an auditable view of what changed around a test run, while keeping the core claim tied to the project's existing dynamic checks.

## Official references

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh file integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html)
- [Using Wazuh to monitor Docker](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html)
- [Wazuh Windows agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
