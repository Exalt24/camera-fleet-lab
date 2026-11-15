# Compliance map for the security layer

This is a mapping for a lab: it says which published control each detection rule, playbook step and Junos check lines up with, and what the repo produces that a reviewer could look at. It is not a compliance claim and not legal advice. Nothing here has been assessed or audited by anyone, and a Docker model of a camera site holds no regulated data.

## Sources

Each framework's primary source was read in Chromium with `Operations/tools/webread/webread.cjs` on 2026-11-15 and the page text is saved under [`vendor-docs/compliance/`](vendor-docs/compliance/).

| Framework | Primary source | Saved copy |
|---|---|---|
| NIST Cybersecurity Framework 2.0 (NIST CSWP 29) | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | [`nist-csf-2.0.txt`](vendor-docs/compliance/nist-csf-2.0.txt) |
| HIPAA Security Rule, 45 CFR 164.312 (technical safeguards) | https://www.ecfr.gov/current/title-45/section-164.312 | [`hipaa-45-cfr-164.312.txt`](vendor-docs/compliance/hipaa-45-cfr-164.312.txt) |
| HIPAA Security Rule, 45 CFR 164.308 (administrative safeguards) | https://www.ecfr.gov/current/title-45/section-164.308 | [`hipaa-45-cfr-164.308.txt`](vendor-docs/compliance/hipaa-45-cfr-164.308.txt) |
| SOC 2 Trust Services Criteria (AICPA, 2017 with revised points of focus 2022) | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | [`aicpa-tsc-download-page.txt`](vendor-docs/compliance/aicpa-tsc-download-page.txt) |
| NYDFS 23 NYCRR Part 500 (sections 500.6, 500.7, 500.14, 500.16) | https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.14 and the three sibling section pages | [`500.6`](vendor-docs/compliance/www_law_cornell_edu_regulations_new_york_23_NYCRR_500_6.txt), [`500.7`](vendor-docs/compliance/www_law_cornell_edu_regulations_new_york_23_NYCRR_500_7.txt), [`500.14`](vendor-docs/compliance/www_law_cornell_edu_regulations_new_york_23_NYCRR_500_14.txt), [`500.16`](vendor-docs/compliance/www_law_cornell_edu_regulations_new_york_23_NYCRR_500_16.txt) |

One gap in the reading. The AICPA criteria PDF needs a free AICPA account, which was not created. The criterion wording was read from a public copy of the same AICPA document at https://arpio.io/wp-content/uploads/2020/08/trust-services-criteria.pdf (includes the March 2020 updates). Only the seven criterion statements the map cites are saved, in [`aicpa-tsc-criteria-excerpts.txt`](vendor-docs/compliance/aicpa-tsc-criteria-excerpts.txt), and they should be checked against the AICPA download before anyone relies on them.

## How the rules carry the mapping

Each alerting rule in [`wazuh/camera_fleet_rules.xml`](wazuh/camera_fleet_rules.xml) holds its NIST CSF function and subcategory in an `info` line and its HIPAA and SOC 2 references in `group` tags (`hipaa_164.312.b`, `tsc_CC7.2`), the same tag style Wazuh's own rules use. They end up in `alerts.json` in the `rule.info`, `rule.hipaa` and `rule.tsc` fields. A test checks that every alerting rule names a CSF function and subcategory.

## Detection rules

| Rule | What it detects | NIST CSF 2.0 | HIPAA Security Rule | SOC 2 | Evidence the repo produces |
|---|---|---|---|---|---|
| 100101 | Monitor reports the camera site `blocked` | DE.CM-01 Networks and network services are monitored to find potentially adverse events | 164.312(b) Audit controls | CC7.2 | The alert in `alerts.json` carrying the transition's own JSON fields (state, tunnel, tcp, error), and the transition line in `fleet_transitions.jsonl`. |
| 100102 | Monitor reports the site unreachable (`tunnel_down`) | DE.CM-01 | 164.312(b) | CC7.2 | The alert and the transition line, with the handshake age and the monitor's error text. |
| 100103 | Three `tunnel_down` transitions in five minutes (flapping) | DE.AE-02 Potentially adverse events are analyzed to better understand associated activities | 164.312(b) | CC7.2 | One alert whose `previous_output` holds the earlier transitions it counted. |
| 100210 | One address hits eight different closed ports in 30 seconds | DE.CM-01 | 164.312(b) | CC7.2 | The alert plus the firewall drop lines (`edge_firewall.log` for the measured sweep, `sim_firewall.log` for the simulated one), with MITRE ATT&CK T1046. |
| 100220 | A port sweep, then the site goes `blocked` or `tunnel_down` within five minutes | DE.AE-03 Information is correlated from multiple sources | 164.308(a)(6) Security incident procedures | CC7.3 | One alert that joins two log sources (firewall drops and monitor transitions); its `previous_output` quotes the sweep line. |
| 100300 | A successful ssh login after a brute force from the same address | DE.AE-02 | 164.312(b); 164.308(a)(5)(ii)(C) Log-in monitoring | CC6.1, CC7.3 | The alert with MITRE ATT&CK T1110 and T1078, and the failed and accepted login lines (simulated log, labelled by file). |
| 100301 | An address that swept the router then logged in over ssh | DE.AE-03 | 164.308(a)(6) | CC7.3 | One alert that joins the firewall log and the ssh log on one source address. |

Rules 100101, 100102 and 100103 carry no ATT&CK technique on purpose: an outage is an operations event, and nothing in them says an attacker did it.

## Playbook steps

The playbooks are in [`playbooks/`](playbooks/) and run through [`respond.py`](respond.py). A dry run records what each step would do; `--apply` does it.

| Step | What it does | NIST CSF 2.0 | HIPAA Security Rule | SOC 2 | Evidence the repo produces |
|---|---|---|---|---|---|
| enrich | Classifies the source address (global, private, protected) and counts earlier alerts from it | RS.AN-03 Analysis is performed to establish what has taken place during an incident | 164.308(a)(6)(ii) Response and reporting | CC7.3 | The step's result in `playbook_result.json` and its `ok` line in the audit trail. |
| notify | Posts the alert to the webhook stand-in, retrying on a 5xx answer | RS.CO-02 Internal and external stakeholders are notified of incidents | 164.308(a)(6)(ii) | CC7.4 | The received JSON in `webhook_received.jsonl`, and a `failed_retryable` then `ok` pair in the audit trail when the first answer was a 500. |
| block | Inserts an iptables DROP for the source address in the edge container, never for a protected address | RS.MI-01 Incidents are contained | 164.308(a)(6)(ii) mitigate harmful effects | CC7.4; CC6.6 | `iptables -S INPUT` read back before and after (`iptables_before_after.txt`); in a dry run only the command that would run is recorded. |
| ticket | Writes an open ticket file for the incident | RS.MA-02 Incident reports are triaged and validated | 164.308(a)(6)(ii) document incidents and their outcomes | CC7.4 | `tickets/<alert id>.json` pointing at the evidence folder. |
| audit trail | Every attempt of every step is appended to `audit.jsonl`, each line carrying the sha256 of the line before | RS.AN-06 Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved | 164.312(b) Audit controls | CC7.4 | `audit.jsonl`; `respond.py --verify-audit` reports a removed or edited line. |
| evidence bundle | Per incident: the alert, the raw log lines around it, the playbook result, an audit excerpt and a sha256 manifest | RS.AN-06 | 164.308(a)(6)(ii) document incidents | CC7.3 | `evidence/<alert id>/` with `MANIFEST.sha256`; `respond.py --verify-bundle` reports a changed or missing file. |

## Junos review checks

[`junos_review.py`](junos_review.py) maps loosely, because it reviews a configuration rather than watching events. The rule ids are in the file and in `junos/EXPECTED.json`.

| Checks | What it looks for | NIST CSF 2.0 | HIPAA Security Rule | SOC 2 | Evidence the repo produces |
|---|---|---|---|---|---|
| JR001, JR002, JR003, JR007 | Filters with no final discard, accept-any terms, management ports open to any address, shadowed terms | PR.IR-01 Networks and environments are protected from unauthorized logical access | 164.312(a)(1) Access control | CC6.1, CC6.6 | A finding with the line and a fix, per planted fault, in the test run. |
| JR004, JR005, JR006 | Telnet, clear http, root password logins, default SNMP community | PR.AA-05 Access permissions and authorizations are defined and managed | 164.312(d) Person or entity authentication; 164.312(e)(1) Transmission security | CC6.1 | Same. |
| JR008, JR009, JR010, JR011, JR012, JR013 | BGP sessions without authentication, prefix limits or policies; accept-all policies; untagged black hole routes | PR.IR-01 | 164.312(e)(1) | CC6.6 | Same. |
| JR014, JR015, JR016 | Discards with no count or log, no NTP, no remote syslog | PR.PS-04 Log records are generated and made available for continuous monitoring | 164.312(b) | CC7.2 | Same. |

## Vulnerability management and identity controls

The CVE triage and the Keycloak and oauth2-proxy layer, added after the sections above. The long detail is in [`docs/vuln-and-iam.md`](../docs/vuln-and-iam.md). Same columns as the tables above.

| Piece | What it does | NIST CSF 2.0 | HIPAA Security Rule | SOC 2 | Evidence the repo produces |
|---|---|---|---|---|---|
| CVE triage (`vuln/cve_triage.py`) | Builds the component inventory from the compose file, Dockerfiles and pinned requirements, looks up CVEs in NVD, adds the CISA KEV flag and the EPSS score, and ranks by a stated rule | ID.RA-01 Vulnerabilities in assets are identified, validated, and recorded; ID.RA-05 Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization | 164.308(a)(1)(ii)(A) Risk analysis | CC7.1 | `docs/security/vuln/cve_triage.md` and `.json` (per finding: CVSS, EPSS, KEV, exposure, remediation) and the saved real answers in `vuln/snapshots/`. A component whose lookup failed is reported UNKNOWN. |
| Triage of what the scanner and the lookups returned | Each ranked item is checked against the running container, and a false positive is written up as one with the command that showed it | ID.RA-01 (validated); ID.RA-06 Risk responses are chosen, prioritized, planned, tracked, and communicated | 164.308(a)(1)(ii)(B) Risk management | CC7.1 | `docs/security/vuln/triage_checks.txt` and the triage section of `docs/vuln-and-iam.md`. |
| Nuclei scan (`vuln/scan.sh`) | Runs the Nuclei scanner against the lab's own services only, behind a scope guard that refuses any address outside loopback and the lab's subnets | ID.RA-01 | 164.308(a)(1)(ii)(A) | CC7.1 | `docs/security/vuln/nuclei_results.jsonl`, `nuclei_summary.txt` and the run log. |
| TOTP for every user | Keycloak requires every user to set up an authenticator code (required action Configure OTP) and asks for it at each sign in | PR.AA-03 Users, services, and hardware are authenticated | 164.312(d) Person or entity authentication | CC6.1 | The realm file, and `docs/security/iam/check_iam_run.txt`: the correct password alone does not reach the dashboard, a wrong code is refused, a valid code is accepted. |
| Two roles and an admin route | `fleet-viewer` reads the dashboard, `fleet-admin` alone reaches the admin route (403 for a viewer) | PR.AA-05 Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties | 164.312(a)(1) Access control | CC6.1 | The 403 and 200 lines in the run file and the screenshots in `docs/security/iam/`. |
| Brute force lockout | Keycloak locks an account after five failed passwords; ten wrong passwords were tried | PR.AA-03 | 164.308(a)(5)(ii)(C) Log-in monitoring | CC6.1 | The lockout lines in the run file: the account reported locked, the correct password refused while locked. |
| Short access token and session refresh | The access token lives 60 seconds and oauth2-proxy renews a session with the refresh token or ends it | PR.AA-03 | 164.312(a)(2)(iii) Automatic logoff (addressable) | CC6.1 | The token lifespan lines in the run file. |

## What this map does not say

It does not say the lab meets any HIPAA, SOC 2 or NIST requirement. Those frameworks assess an organisation's policies, people and systems over time, and none of that exists here. The map shows only which of the lab's detections, responses and records line up with a published control, so a reader can see where the evidence for a real programme would come from.

## NYDFS Part 500 (financial services cybersecurity regulation, New York)

Read on 2026-11-15 from the section pages saved above. As with the other frameworks this lines the lab's pieces up with the text; it is not an assessment and not legal advice.

| Piece | NYDFS section | What the text asks | Evidence the repo produces |
|---|---|---|---|
| Rules 100300 and 100301 (a login after a brute force, a sweep then a login) | 500.14(a)(1) | risk-based controls to monitor the activity of authorized users and detect unauthorized access or use | The alert with the failed and accepted login lines, joined with the firewall log for 100301. |
| Rules 100101, 100102, 100103, 100210 and 100220 | 500.14(a)(1) and 500.14(b)(2) | monitoring, and for a class A company a solution that centralizes logging and security event alerting | Alerts from one manager that reads the monitor, the firewall and the ssh log. |
| Playbook steps enrich, notify and ticket | 500.16(a)(1)(ii), (iv) and (vi) | internal processes for responding, communications, documentation and reporting of incident response activities | The audit trail line per step and the ticket payload in the evidence folder. |
| Playbook step block (dry run by default) | 500.16(a)(1) | plans to investigate and mitigate a cybersecurity event | The command it would run, recorded, and with `--apply` the read back `iptables` rule. |
| Audit trail and evidence folder with a sha256 manifest | 500.6(a)(2) | audit trails designed to detect and respond to cybersecurity events | The hash chained audit trail and the manifest that `--verify-audit` and `--verify-bundle` check. |
| Junos checks for telnet, http, ssh or snmp reachable from any address and a root login without keys | 500.7(a)(2), (a)(3) and (a)(5) | limit privileged accounts and their use, and disable or securely configure protocols that permit remote control of devices | The finding with its line and the fix text, from the sample configurations. |
| CVE triage and the Nuclei scan | 500.5(a)(2), 500.5(c) | automated scans for the purpose of discovering, analyzing and reporting vulnerabilities, and timely remediation giving priority to vulnerabilities based on the risk they pose | The ranked report with the stated rule, and the scan output, from one run. |
| TOTP for every user and the two roles | 500.12(a), 500.7(a) | multi-factor authentication for any individual accessing information systems, and limits on access privileges | The run file: password alone refused, a valid code accepted, a viewer refused the admin route. The lab has two sample users and no organisation behind them. |

What this lab does not cover in this section: 500.14(b)(1) asks a class A company for an endpoint detection and response solution, and the lab has no endpoint agent; 500.5(a)(1) asks for penetration testing by a qualified party at least annually, which the lab has not had; 500.5(b) asks for a monitoring process that tells the company of new vulnerabilities, and the triage only runs when it is run (no schedule); the sections on encryption, third party service providers, training and the annual certification are not mapped.
