# security/

A security layer for the camera site: a SIEM with log correlation, a small playbook responder that keeps evidence, and a reviewer for Junos configurations. The design notes and what the runs showed are in [`docs/security.md`](https://github.com/Exalt24/camera-fleet-lab/blob/master/docs/security.md). The control mappings are in [`COMPLIANCE-MAP.md`](COMPLIANCE-MAP.md).

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

Without `--profile security` nothing here starts, and `docker compose up` and `scripts/verify.py` behave as before.

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
vendor-docs/compliance/   the NIST, HIPAA and AICPA pages read for the compliance map
tests/            pytest files and run_mutations.py (mutation controls)
COMPLIANCE-MAP.md
```

The live proof is [`scripts/verify_security.py`](https://github.com/Exalt24/camera-fleet-lab/blob/master/scripts/verify_security.py). Its run files are in [`docs/security/`](https://github.com/Exalt24/camera-fleet-lab/tree/master/docs/security).
