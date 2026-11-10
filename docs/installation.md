# Installation and troubleshooting

Use a dedicated lab machine or disposable VM with Docker Engine/Desktop, Compose v2.24+ and Linux containers. Reserve at least 8 GB RAM, four CPU cores and 20 GB disk. Windows users need a working Docker Desktop Linux engine (WSL2). Python 3.11+ is only needed for local development or the optional cross-platform helper scripts.

```sh
git clone https://github.com/TORNADO984/PurpleLab-SOC.git
cd PurpleLab-SOC
docker compose up -d
docker compose logs -f provision
docker compose ps -a
```

The initial image pull needs internet access; runtime backend traffic stays internal. `secrets`, `certificates`, `security-setup` and `provision` should exit with code 0. Elasticsearch, Kibana and gateway should remain healthy. On slower machines the first startup can take several minutes. `up -d` starts the provisioning job; inspect its exit status before generating events.

An `.env` file is optional. Copy `.env.example` if you need alternate host ports. All Elastic components must use the same version. Do not downgrade an existing data volume; test version upgrades in a separate project first.

## Credentials

```sh
docker compose run --rm --no-deps lab credentials
```

This intentionally displays the generated lab passwords. Do not paste the output into an issue, screenshot or commit. There is no default password and no production mode with weaker credentials. Secrets live in Docker volumes, not `.env` or source files. A restart preserves them. Do not delete the secret volume while retaining Elasticsearch data; bootstrap passwords do not reset existing users.

## Certificate trust

Export the **public CA certificate only**:

```sh
docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./artifacts/ca.crt
```

Create `artifacts` first if needed. Compare the certificate fingerprint locally before trusting it. Import this lab CA into a dedicated browser profile or accept the localhost exception only for this lab. Do not disable TLS verification in generators or Beats. Certificates cover `localhost`, `127.0.0.1` and the backend service names. The private CA key is held in the separate `ca-private` volume, mounted only into certificate initialization.

The leaf certificate lifetime is 825 days. Renew deliberately before expiry using the existing lab CA, replace only the leaf certificate/key pairs, and restart the services. For disposable training data, a confirmed full purge and restart creates a new CA and new credentials. Do not publish private keys.

## Common failures

- **Docker pipe/socket unavailable:** start Docker Desktop or the Docker daemon and select Linux containers.
- **Elasticsearch reports virtual memory settings:** follow [Elastic's Docker host prerequisites](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod). On a dedicated Linux lab host, set `vm.max_map_count` to the value required by your Elastic version. The project does not change host sysctls automatically.
- **Exit 137 / out of memory:** increase Docker memory allocation; do not remove memory limits on a shared host without checking capacity.
- **Port occupied:** set `KIBANA_PORT` or `ES_PORT` in `.env`. The listener still binds localhost.
- **UI unreachable while Kibana is healthy:** check `docker compose ps gateway` and `docker compose logs gateway`. The gateway is needed for Docker versions that suppress published ports on internal-only networks.
- **401 after changing secrets:** restore the matching original secret volume or use Elastic's supported password reset procedure and update the lab secret files together. Re-run provisioning afterward.
- **Provisioning failed:** inspect `docker compose logs provision`; fix the error, then run `docker compose run --rm --no-deps lab provision`. API errors and saved-object import failures are fatal rather than silently ignored.
- **No alerts:** select the last 15 minutes, verify ingestion and rules, then run the validator. Inspect rule execution errors in Security → Rules. Clock skew, missing Windows fields and insufficient API-key permissions are common causes.
- **Empty dashboards:** run generation/validation first, select the appropriate data view, and remove stale run-ID filters.

To apply source changes, run `docker compose build` followed by `docker compose up -d`. After editing only imported rules or dashboards, rebuild and explicitly run the provisioning command. Reprovisioning restores the checked-in rules and dashboard definitions, including enabling rules; export manual edits first.
