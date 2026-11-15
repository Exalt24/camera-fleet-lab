# CVE triage of the lab's components

Run: 2026-11-15 13:00 UTC (offline, from saved responses). Sources: NVD 2.0 (per component, by CPE), CISA KEV catalogue, FIRST EPSS. The saved responses were fetched 2026-11-15T12:59:01Z.

Ranking rule, in order: known exploited (KEV yes, then KEV unknown, then no); EPSS, highest first; CVSS base score, highest first (v3.1, else v3.0, else v4.0, else v2); reachable from outside the lab network before internal (docker-compose.yml, published ports); CVE id.

15 components looked up, 12 answered, 3 UNKNOWN. 42 findings in all, and 17 more CVEs that NVD returned but that do not apply (listed apart, with the reason).

## Components

| Component | Version | Services | Exposure | NVD lookup | CVEs |
|---|---|---|---|---|---|
| aiomysql | 0.3.2 | hub | reachable | **UNKNOWN: the NVD dictionary has no CPE product aiomysql_project:aiomysql, so a CVE search by CPE cannot assess it; its own project advisories would have to be read** | not known |
| Alpine Linux | 3.20.10 | edge | internal | ok | 0 |
| FastAPI | 0.162.0 | hub | reachable | ok | 0 |
| FFmpeg | 7.1.5 | hub | reachable | ok | 41 |
| iptables | 1.8.10 | edge | internal | ok | 0 |
| iptables | 1.8.11 | hub | reachable | ok | 0 |
| Keycloak | 26.8.2 | keycloak | reachable | ok | 0 |
| MariaDB | 11.8.9 | mariadb | internal | ok | 0 |
| MediaMTX | 1.21.3 | camera | internal | **UNKNOWN: the NVD dictionary has no CPE product bluenviron:mediamtx, so a CVE search by CPE cannot assess it; its own project advisories would have to be read** | not known |
| oauth2-proxy | 7.15.6 | oauth2-proxy | reachable | ok | 0 |
| Python | 3.13.18 | fleet-exporter, hub | reachable | ok | 1 |
| SQLAlchemy | 2.1.8 | hub | reachable | ok | 0 |
| Uvicorn | 0.54.0 | hub | reachable | ok | 0 |
| Wazuh manager | 4.14.10 | wazuh | internal | ok | 0 |
| WireGuard tools | 1.0.20210914 | edge, hub | reachable | **UNKNOWN: the NVD dictionary has no CPE product wireguard:wireguard-tools, so a CVE search by CPE cannot assess it; its own project advisories would have to be read** | not known |

A component marked UNKNOWN was not checked. It is not a clean result.

## Matched only as a platform (not findings)

NVD matched these CVEs to the component only as the system the vulnerable software runs on (the entry is marked `vulnerable: false`). They are not counted above. Whether the vulnerable software named in the CVE is installed here is a check for a person, so each one is listed with its KEV flag.

| CVE | Component | CVSS | KEV | What the CVE is about |
|---|---|---|---|---|
| CVE-2026-123158 | Alpine Linux 3.20.10 | 8.1 | yes | sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be  |
| CVE-2020-29396 | Python 3.13.18 | 8.8 | no | A sandboxing issue in Odoo Community 11.0 through 13.0 and Odoo Enterprise 11.0 through 13.0, when running with Python 3.6 or later, allows remote authenticated users to execute arbitrary code, leadin |
| CVE-2021-32052 | Python 3.13.18 | 6.1 | no | In Django 2.2 before 2.2.22, 3.1 before 3.1.10, and 3.2 before 3.2.2 (with Python 3.9.5+), URLValidator does not prohibit newlines and tabs (unless the URLField form field is used). If an application  |

## Returned by NVD, but the version is outside every affected range (not findings)

NVD's version filter counts the end of a range as inclusive, so a release that is the first fixed one still comes back. The tool compares the version with each range itself and sets these aside; they are listed so the count can be checked.

| CVE | Component | CVSS | KEV | What the CVE is about |
|---|---|---|---|---|
| CVE-2026-107814 | MariaDB 11.8.9 | 8.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, MariaDB RPM packages created the dedicated mysql service account |
| CVE-2026-107815 | MariaDB 11.8.9 | 8.5 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the CONNECT engine's DOS table type used an incorrect boundary c |
| CVE-2026-107816 | MariaDB 11.8.9 | 6.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the qc_info plugin could be confused by a query containing embed |
| CVE-2026-107817 | MariaDB 11.8.9 | 4.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the mysql_json plugin assumed that imported MySQL tables contain |
| CVE-2026-107818 | MariaDB 11.8.9 | 8.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the mariadb.service unit used /run/mysqld/wsrep-new-cluster duri |
| CVE-2026-107821 | MariaDB 11.8.9 | 8.0 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, MariaDB insufficiently validated counts, offsets, lengths, and f |
| CVE-2026-107822 | MariaDB 11.8.9 | 6.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, MariaDB's ACL cache could generate the same database-privilege c |
| CVE-2026-107823 | MariaDB 11.8.9 | 7.2 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the MariaDB view FRM parser did not safely encode embedded newli |
| CVE-2026-85745 | MariaDB 11.8.9 | 4.3 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, ST_Area reads beyond the allocated buffer when processing invali |
| CVE-2026-85746 | MariaDB 11.8.9 | 9.9 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, ST_AsText can write beyond an allocated output buffer when conve |
| CVE-2026-85985 | MariaDB 11.8.9 | 5.4 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the CONNECT engine plugin file-access UDFs json_file(), bson_fil |
| CVE-2026-86047 | MariaDB 11.8.9 | 7.7 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, SHOW CREATE SERVER, SHOW CREATE USER, and mariadb-dump are affec |
| CVE-2026-92262 | MariaDB 11.8.9 | 9.9 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the #mysql50# bypass prefix is affected because it allows the #m |
| CVE-2026-97380 | MariaDB 11.8.9 | 8.8 | no | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the GRANT PROXY statement treats an IDENTIFIED clause with an em |

## Top 25 findings

| # | CVE | Component | CVSS | EPSS | KEV | Exposure | Remediation |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-66040 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0078 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 2 | CVE-2026-64834 | FFmpeg 7.1.5 | 7.5 (v3.1) | 0.0073 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 3 | CVE-2026-64830 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0065 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 4 | CVE-2026-3087 | Python 3.13.18 | 7.5 (v3.1) | 0.0055 | no | reachable | no fixed version is named in the NVD data for Python 3.13.18; read the vendor advisory, then upgrade or mitigate |
| 5 | CVE-2026-30754 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0052 | no | reachable | upgrade FFmpeg from 7.1.5 to 8.1 or later |
| 6 | CVE-2026-64835 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0050 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 7 | CVE-2026-66041 | FFmpeg 7.1.5 | 7.8 (v3.1) | 0.0049 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 8 | CVE-2026-107695 | FFmpeg 7.1.5 | 6.5 (v3.1) | 0.0047 | no | reachable | upgrade FFmpeg from 7.1.5 to 8.1.3 or later |
| 9 | CVE-2025-25469 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0046 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 10 | CVE-2026-30999 | FFmpeg 7.1.5 | 7.5 (v3.1) | 0.0046 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 11 | CVE-2026-30998 | FFmpeg 7.1.5 | 7.5 (v3.1) | 0.0042 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 12 | CVE-2026-66036 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0040 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 13 | CVE-2025-25468 | FFmpeg 7.1.5 | 6.5 (v3.1) | 0.0038 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 14 | CVE-2026-107696 | FFmpeg 7.1.5 | 6.5 (v3.1) | 0.0036 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 15 | CVE-2026-30997 | FFmpeg 7.1.5 | 7.5 (v3.1) | 0.0035 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 16 | CVE-2026-66037 | FFmpeg 7.1.5 | 5.5 (v3.1) | 0.0035 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 17 | CVE-2025-10256 | FFmpeg 7.1.5 | 5.5 (v3.1) | 0.0034 | no | reachable | upgrade FFmpeg from 7.1.5 to 8.0 or later |
| 18 | CVE-2026-64832 | FFmpeg 7.1.5 | 8.8 (v3.1) | 0.0034 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 19 | CVE-2026-65703 | FFmpeg 7.1.5 | 7.8 (v3.1) | 0.0033 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 20 | CVE-2026-107697 | FFmpeg 7.1.5 | 4.3 (v3.1) | 0.0032 | no | reachable | upgrade FFmpeg from 7.1.5 to 8.1.3 or later |
| 21 | CVE-2026-66039 | FFmpeg 7.1.5 | 7.8 (v3.1) | 0.0031 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 22 | CVE-2026-66038 | FFmpeg 7.1.5 | 6.5 (v3.1) | 0.0024 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 23 | CVE-2026-70632 | FFmpeg 7.1.5 | 7.8 (v3.1) | 0.0023 | no | reachable | upgrade FFmpeg from 7.1.5 to 9 or later |
| 24 | CVE-2026-64833 | FFmpeg 7.1.5 | 7.1 (v3.1) | 0.0021 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |
| 25 | CVE-2026-65705 | FFmpeg 7.1.5 | 7.8 (v3.1) | 0.0019 | no | reachable | no fixed version is named in the NVD data for FFmpeg 7.1.5; read the vendor advisory, then upgrade or mitigate |

