# Connect a real Windows VM

The default stack is synthetic. This optional path changes only an explicitly authorized disposable Windows VM. Snapshot it first. Use a private host-only network, no corporate domain membership, no shared folders/clipboard, and no production credentials. Download trusted signed dependencies before isolating it.

## 1. Prepare collection

Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and Winlogbeat matching the pinned Elastic version from Elastic. Verify their signatures/checksums. Copy `configs/sysmon/lab.xml` and `configs/winlogbeat.yml` into the VM. Do not run these commands on your workstation.

In an elevated VM PowerShell prompt, from the Sysmon directory:

```powershell
.\Sysmon64.exe -accepteula -i C:\Lab\lab.xml
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 3
```

The sample config collects process, connection, file, registry and DNS events broadly and filters ProcessAccess to LSASS. It is intentionally noisy and suitable only for a small lab. Check the installed Sysmon schema before applying a configuration from another version (`Sysmon64.exe -s`).

Enable the Windows Security audit categories needed for logon and task creation, inside the VM only:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

Subcategory names are localized; on non-English Windows inspect `auditpol /list /subcategory:*` and use the corresponding names. Event 1102 indicates log clearing; this guide does not instruct you to clear logs. Service installation evidence is collected from System event 7045.

## 2. Establish a restricted tunnel

Keep the Compose ports on localhost. Use an existing, secured SSH service on the lab Docker host, reachable only from the host-only VM network. The operator must configure key authentication and restrict forwarding to `127.0.0.1:9200`. This project does not install or expose SSH automatically.

From the VM:

```powershell
ssh -N -L 127.0.0.1:19200:127.0.0.1:9200 laboperator@<LAB_HOST_PRIVATE_IP>
```

Keep that terminal open. The VM connects to `https://localhost:19200`; its TLS hostname matches the generated certificate. This creates a controlled ingestion path without exposing Elasticsearch on a LAN address or disabling certificate validation. If your environment cannot provide this tunnel, design an equivalent private authenticated path and reissue certificates for its hostname before changing binds.

## 3. Trust only the lab CA and configure Winlogbeat

On the Docker host, create `artifacts`, then export the public CA and retrieve the restricted Beats password:

```sh
docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./artifacts/ca.crt
docker compose run --rm --no-deps lab credentials
```

Transfer **only** `ca.crt`, the Winlogbeat config and the `beats_writer` password securely to the VM. Never copy the CA private key or the elastic password. Put the CA at `C:\Program Files\Winlogbeat\ca.crt` and the config at `C:\Program Files\Winlogbeat\winlogbeat.yml`.

In the Winlogbeat directory, use the [Winlogbeat keystore](https://www.elastic.co/docs/reference/beats/winlogbeat/keystore):

```powershell
.\winlogbeat.exe keystore create
.\winlogbeat.exe keystore add BEATS_PASSWORD
.\winlogbeat.exe test config -c .\winlogbeat.yml
.\winlogbeat.exe test output -c .\winlogbeat.yml
.\winlogbeat.exe -e -c .\winlogbeat.yml
```

Enter the generated `beats_writer` password at the prompt. Start interactively for the exercise; follow Elastic's platform instructions if installing a service. The lab bootstrap already installs the template and pipeline, so do not run Beats setup as an administrator against Elasticsearch.

## 4. Validate real collection

Run the harmless discovery command **inside the VM**:

```powershell
whoami /all
```

In Discover, use the `PurpleLab events` data view and query:

```text
purplelab.synthetic: false AND event.code: "1" AND process.executable: *whoami.exe
```

Inspect the real host name, process command line and timestamp. Within a few minutes, the `Interactive user discovery` rule should alert. Search Security alerts by `host.name`, time and rule name, not `purplelab.run_id`: real events have no synthetic run labels. Record the rule execution result and the actual source event ID separately from synthetic validation.

The normalization pipeline maps selected raw `winlog.event_data` fields into ECS while retaining the originals. Different Windows/Winlogbeat versions can use different field names; compare the raw event, pipeline simulation and detection filters before claiming support. Scheduled-task XML, service paths and access masks must actually be collected. The automated synthetic validator does not certify this VM path.

## 5. Finish

Stop Winlogbeat and the tunnel, export sanitized evidence, then revert the VM snapshot. Do not leave the broad Sysmon policy or test dependencies installed on a production endpoint.
