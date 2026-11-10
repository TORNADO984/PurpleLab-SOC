# Contributing

Contributions should improve reproducible defensive validation. Keep fixtures inert, original or appropriately licensed, and free of real credentials, personal data and live malicious infrastructure. Use reserved documentation IP ranges and `.test`/`.example` domains.

## Local development

Run from a source checkout; the content catalog is stored alongside the Python package.

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python scripts/build_content.py
python -m unittest discover -s tests -v
python -m compileall -q purplelab scripts tests
docker compose config --quiet
```

## Add or change a detection

1. Edit `CASES` in `scripts/build_content.py`. Provide title, rationale, ATT&CK ID/name/tactic, scenario, event source, explicit positive fixture, meaningful benign near miss and false-positive context.
2. Use the supported Sigma subset: one `selection`, AND across fields, OR across list values, exact equality, `contains`, `endswith`, and `contains|all`. Unsupported modifiers must fail closed. This is a purpose-built converter, not a general pySigma backend.
3. Add the required real Windows field mapping to the ingest pipeline when appropriate. Preserve raw fields and test normalization with Elastic's pipeline simulation API.
4. Update the scenario with observed facts, evidence gaps, exact investigation queries and defensible escalation criteria.
5. Regenerate content and inspect both Sigma and native filters. Native queries must never depend on `purplelab.run_id`, scenario, fixture IDs or expected-match labels.
6. Run offline tests, rebuild the container, reprovision and run live validation:

```sh
docker compose build
docker compose up -d
docker compose run --rm --no-deps lab provision
docker compose run --rm lab validate
```

The live validator must see real scheduled alerts for intended event/rule pairs and no alerts for negative controls. Add tests for material parser, matching, authentication, ingestion or validation changes. Do not claim an end-to-end pass from unit tests alone.

## Pull requests

Describe the observed problem, resulting behavior, affected rule/scenario IDs and validation evidence. Include sanitized reports, not passwords or private logs. Keep commits focused. CI checks deterministic generated files and offline behavior; the manually dispatched integration workflow starts the actual stack. Review dependency and Elastic version changes in their own pull requests.

Original contributions use the MIT license. Keep upstream licenses and attribution when adding external content; the current rule catalog is original lab content.
