# Wazuh for local project monitoring

Wazuh is a separate security monitoring stack, not a Python dependency for the CVE pipeline. This setup adds an opt-in local Wazuh server, indexer, and dashboard using Wazuh's official Docker deployment. It keeps the Wazuh checkout, generated certificates, and runtime data out of this repository.

## Requirements

- Docker Desktop with the WSL 2 backend and Docker Compose
- Git on PATH
- At least 4 CPU cores, 8 GB RAM, and 50 GB free disk for the single-node stack
- WSL 2 setting `vm.max_map_count=262144` (see below)

For a Windows host, open a WSL 2 distribution and run:

```sh
sudo sysctl -w vm.max_map_count=262144
```

The setting resets when the Docker host restarts. See the Wazuh Docker documentation for persistent configuration.

## Start the local stack

From the repository root in PowerShell:

```powershell
.\wazuh\install.ps1
```

The script clones the official `wazuh/wazuh-docker` repository at **v4.14.9**, generates the documented self-signed certificates, and starts the single-node stack. It binds published services to loopback only. The dashboard is at <https://localhost:8443>; the manager and indexer APIs are available only on this host.

The upstream demo credentials are `admin` / `SecretPassword`. This is a local development setup. Change the credentials before connecting remote agents or exposing any ports beyond localhost. Your browser will warn about the self-signed dashboard certificate.

The Wazuh stack needs resources in addition to the free5GC and test containers. To stop it while preserving its data:

```powershell
Push-Location .\wazuh\.wazuh-docker\single-node
docker compose down
Pop-Location
```

## Monitor this Windows host and checkout

The central stack alone does not monitor the Windows host or files in this checkout. Install the native Windows Wazuh agent and set its manager address to `127.0.0.1`. A Wazuh agent running in a container cannot inspect the host filesystem.

After enrolling the host agent, add the following entries to its `ossec.conf`, replacing the path with the absolute path to this checkout. The first entry enables real-time file integrity monitoring for the project. The `localfile` entries collect the repository's watcher output and lab audit events when those files exist.

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">C:\path\to\Final-Year-Project</directories>
  <ignore>C:\path\to\Final-Year-Project\.git</ignore>
  <ignore>C:\path\to\Final-Year-Project\.venv</ignore>
  <ignore>C:\path\to\Final-Year-Project\reports</ignore>
  <ignore>C:\path\to\Final-Year-Project\__pycache__</ignore>
  <ignore>C:\path\to\Final-Year-Project\.pytest_cache</ignore>
</syscheck>
<localfile>
  <location>C:\path\to\Final-Year-Project\watcher.log</location>
  <log_format>syslog</log_format>
</localfile>
<localfile>
  <location>C:\path\to\Final-Year-Project\watcher_stderr.log</location>
  <log_format>syslog</log_format>
</localfile>
<localfile>
  <location>C:\path\to\Final-Year-Project\ssrf_lab\lab_audit.ndjson</location>
  <log_format>json</log_format>
</localfile>
```

Use the official [Windows agent installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html) for installation and agent restart steps. Review the exclusions against your own monitoring goals; excluding `reports` reduces noise from generated experiment output.

## Official references

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Changing default Wazuh Docker passwords](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html)
- [Wazuh Windows agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
