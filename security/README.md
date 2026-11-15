# security/

A security layer for the camera site: a SIEM with log correlation, a small playbook responder that keeps evidence, a reviewer for Junos configurations, a vulnerability assessment with CVE triage, and single sign on with a TOTP code. The design notes and what the runs showed are in [`docs/security.md`](https://github.com/Exalt24/camera-fleet-lab/blob/master/docs/security.md). The control mappings are in [`COMPLIANCE-MAP.md`](COMPLIANCE-MAP.md).

It was built and tested against the Docker model of the camera site, planted and generated logs, and sample Junos configurations written from Juniper's documentation.

## Run it

Use your own compose project name if other containers are running on the machine.

```
docker compose -p cfl-sec --profile security up -d --build     # the lab plus Wazuh and the two sensors
python scripts/verify_security.py --project cfl-sec            # the live proof, about 5 minutes
python -m pip install -r security/requirements.txt
python -m pytest security/tests -q                             # offline tests; the logtest ones need the manager up
python security/tests/run_mutations.py                         # every mutation control must turn a test red
python security/junos_review.py security/junos/*.set           # the reviewer over the six sample configs
docker compose -p cfl-sec --profile security down              # stops only this project's containers
```

Without `--profile security` nothing here starts, and `docker compose up` and `scripts/verify.py` behave as before. Parts D and E have their own run commands below, and the `iam` profile is separate from `security`.

## A. SIEM and log correlation (`wazuh/`, `sensors/`, `simulate/`, `logs/`)

The open source Wazuh manager, version 4.14.10 (`wazuh/wazuh-manager`), runs as one container with no indexer and no dashboard. It reads four log files from a shared volume:

| File | Written by | Measured or simulated |
|---|---|---|
| `fleet_transitions.jsonl` | `sensors/fleet-exporter`, from the monitor's `/history` | measured |
| `edge_firewall.log` | `sensors/fw-sensor`, from NFLOG on the edge router's default-deny drops | measured |
| `ssh_auth.log` | `simulate/ssh_auth_gen.py` | simulated |
| `sim_firewall.log` | `simulate/ssh_auth_gen.py` (a sweep from an outside address) | simulated |

`wazuh/camera_fleet_decoders.xml` decodes the firewall line, `wazuh/camera_fleet_rules.xml` holds seven alerting rules (100101, 100102, 100103, 100210, 100220, 100300, 100301) and two base rules, and `wazuh/ossec.conf` is the manager's configuration. Each alerting rule has a description, a NIST CSF function and subcategory, HIPAA and SOC 2 tags, and a MITRE ATT&CK id where one applies. `logs/planted/` and `logs/benign/` are the log files the proof runs through `wazuh-logtest`, and `logs/EXPECTED.json` says what each must raise.

## B. Responder (`respond.py`, `playbooks/`, `webhook_receiver.py`)

```
python security/respond.py --alerts <alerts.json> --state security/state --logs <feed folder>             # dry run (default)
python security/respond.py --alerts <alerts.json> --state security/state --webhook http://127.0.0.1:8765/notify --apply
python security/respond.py --verify-audit security/state/audit.jsonl
python security/respond.py --verify-bundle security/state/evidence/<alert id>
python security/respond.py --unblock 203.0.113.50 --apply                                                  # undo a block
```

The playbooks are `playbooks/*.yml`. The webhook receiver is a local stand-in for a chat or paging service. The block step only prints and records its iptables command unless `--apply` is given, and then runs inside the edge container only.

## C. Junos review (`junos_review.py`, `junos/`, `vendor-docs/`)

```
python security/junos_review.py security/junos/fault-management-plane.set
python security/junos_review.py router.set --format json --fail-on high
```

It was written from Juniper's public documentation (the pages read are saved as text in `vendor-docs/`) and run on the sample configurations in `junos/`: two clean ones and four with planted faults, listed in `junos/EXPECTED.json`. It has never been run against a Junos device or a vJunos image.

## D. Vulnerability assessment and CVE triage (`vuln/`)

```
bash security/vuln/scan.sh --project cfl-iam                     # Nuclei against the lab's own services; results in docs/security/vuln/
bash security/vuln/scan.sh --check-scope http://8.8.8.8          # only the scope guard: exit 2, refused
python security/vuln/cve_triage.py --offline --out docs/security/vuln      # from the saved real answers in vuln/snapshots/, no network
python security/vuln/cve_triage.py --live --resolve-images --save-snapshots --project cfl-iam   # ask NVD, CISA and FIRST now (about 5 minutes: NVD allows 5 requests per 30 s)
bash security/vuln/triage_checks.sh cfl-iam > docs/security/vuln/triage_checks.txt   # the checks behind the written triage
```

`scan.sh` runs the official Nuclei image (`projectdiscovery/nuclei:v3.11.1`) on the lab's Docker networks. It refuses any target that is not on a loopback address or in one of the lab's subnets, and refuses host names other than `localhost`, before it sends anything. Interactsh is off, so no scan traffic goes to an outside server. It exits non zero only when the scan itself fails.

`cve_triage.py` builds the component inventory from `docker-compose.yml`, the Dockerfiles and the pinned requirements, asks NVD for the CVEs whose affected range includes each version, adds the CISA KEV flag and the EPSS score, and ranks by one rule: known exploited first, then EPSS, then CVSS, then reachable before internal (published ports in the compose file). It writes a Markdown report and a JSON file. A component it cannot look up is reported UNKNOWN, never as clean. A CVE that NVD returns only because the component is the platform the vulnerable software runs on, or because the version is the first fixed release, is listed apart with the reason.

## E. IAM with TOTP and single sign on (`iam/`)

```
bash security/iam/setup.sh                                       # writes the gitignored security/iam/.env with generated secrets
docker compose -p cfl-iam --profile iam up -d --build            # Keycloak, oauth2-proxy, and the lab behind them
bash security/iam/check_iam.sh --project cfl-iam                 # the live proof; prints the counts
docker compose -p cfl-iam --profile iam down                     # stops only this project's containers
```

Keycloak 26.8.2 (`quay.io/keycloak/keycloak`, dev mode, inside Docker only) imports `iam/realm-camera-fleet.json`: two roles (`fleet-viewer`, `fleet-admin`), a required Configure OTP action for every user, a 60 second access token, brute force detection that locks an account after five failures, and two sample users. oauth2-proxy v7.15.6 sits in front of the monitor dashboard and speaks OIDC to Keycloak, so the dashboard shows only after a password and a code. The proxy sets the user name and role headers, and the hub believes them only from the proxy's own address. A viewer reads the dashboard. Only `fleet-admin` reaches `/admin/probe-config`, the one admin route, which is read only.

The sample users are for this lab only: `viewer.sample` with password `ViewerSample-2026` and `admin.sample` with password `AdminSample-2026`. Their TOTP secret is created at their first sign in (the forced set up page), and `check_iam.py` resets both users to that state before each run. The client secrets and the cookie secret are generated by `setup.sh`; none is committed.

## Layout

```
wazuh/            ossec.conf, camera_fleet_decoders.xml, camera_fleet_rules.xml
sensors/          fw-sensor (NFLOG to log lines), fleet-exporter (monitor history to JSON lines)
simulate/         ssh_auth_gen.py, the generator for the simulated sources
logs/             planted and benign log files, EXPECTED.json
logtest_runner.py runs log lines through wazuh-logtest inside the container
respond.py        the playbook engine and its command line
playbooks/        five YAML playbooks
webhook_receiver.py  local stand-in for the notify step
junos_review.py   the Junos reviewer;  junos/ six sample configs;  vendor-docs/ the Juniper pages read
vendor-docs/compliance/   the NIST, HIPAA, AICPA and NYDFS pages read for the compliance map
vuln/             scan.sh (Nuclei, scope guard), cve_triage.py, triage_checks.sh, snapshots/ (saved real NVD, KEV and EPSS answers)
iam/              realm-camera-fleet.json, setup.sh, check_iam.sh, check_iam.py, shots.cjs
tests/            pytest files and run_mutations.py (mutation controls)
COMPLIANCE-MAP.md
```

The live proofs are [`scripts/verify_security.py`](https://github.com/Exalt24/camera-fleet-lab/blob/master/scripts/verify_security.py). Its run files are in [`docs/security/`](https://github.com/Exalt24/camera-fleet-lab/tree/master/docs/security).

The live proof for parts D and E is `security/vuln/scan.sh` plus `cve_triage.py --live`, and `security/iam/check_iam.sh`. Their run files are in [`docs/security/vuln/`](https://github.com/Exalt24/camera-fleet-lab/tree/master/docs/security/vuln) and [`docs/security/iam/`](https://github.com/Exalt24/camera-fleet-lab/tree/master/docs/security/iam).
