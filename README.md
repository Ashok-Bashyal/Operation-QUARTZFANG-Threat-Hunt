# Operation-QUARTZFANG-Threat-Hunt


## Project Overview

Operation QUARTZFANG is a hands-on SOC threat-hunting investigation involving a simulated AI-assisted cyberattack against **SemiCrest Technologies**.

I used **Microsoft Azure Log Analytics** and **Kusto Query Language (KQL)** to investigate suspicious activity across multiple systems, identify attacker behavior, and reconstruct the attack timeline.

The investigation also focused on understanding how AI was used during the attack and distinguishing legitimate system activity from malicious behavior.

## Tools and Technologies

- **Microsoft Azure Log Analytics** – Investigating and analyzing security logs.
- **Kusto Query Language (KQL)** – Searching, filtering, and correlating security events.
- **MITRE ATT&CK** – Mapping attacker tactics and techniques.
- **Linux Syslog** – Investigating system and PostgreSQL activity.
- **Endpoint and Network Logs** – Tracking suspicious processes and connections.


## Investigation Findings

### 1. Initial Access

The investigation started with suspicious requests targeting the web portal's document preview functionality.

By analyzing web access logs and process execution events, I identified evidence of remote code execution on `sc-portal01`, including a Python reverse-shell command.

### 2. Credential Access

After gaining access, the attacker accessed `/etc/semicrest/portal.conf`, an application configuration file containing credentials for internal services.

The compromised credentials included accounts used by the PostgreSQL database and Harbor container registry.

### 3. Lateral Movement

The attacker used compromised credentials to explore internal services, including the PostgreSQL database, Harbor container registry, and administrative API.

I investigated suspicious database queries and registry operations. An administrative API request attempting to access secrets returned **HTTP 403 (Forbidden)**.

### 4. AI Hallucination Investigation

The AI agent reported successfully obtaining sensitive information from internal services.

However, some of these claims were not supported by actual security logs. This demonstrated the importance of verifying AI-generated results against independent evidence.

### 5. Data Exfiltration and Persistence

I identified suspicious activity involving an encrypted archive, followed by an unusual outbound HTTPS connection.

The attacker also created a local account named `svc_monitor` and added it to the sudo group, indicating a potential persistence mechanism.

### 6. Reconnaissance and Automation

I analyzed automated web requests and compared suspicious external scanning activity against legitimate internal Nessus scanning.

Request frequency, source IP addresses, and user-agent information helped distinguish reconnaissance from authorized vulnerability scanning.

### 7. AI Autonomy Investigation

The AI agent logs showed that human operators approved important stages of the attack while the AI performed technical tasks such as payload adaptation, credential harvesting, and database queries.

### 8. False Positive Investigation

The final stage involved identifying legitimate activities that appeared suspicious.

I investigated normal service account usage, scheduled PostgreSQL backups, and a database connection spike.

By analyzing timestamps, historical activity, and query behavior, I was able to distinguish normal system operations from confirmed malicious activity.

---

## KQL Investigation Queries

The following KQL queries were used during the investigation to analyze different stages of the attack.

**Note:** The simulated attack occurred on September 20, 2026, while some AI agent logs were ingested on October 24, 2026. Set the Log Analytics time range to **Set in query** when running these examples.

### Query 1: Initial Compromise – Suspicious Process Execution

This query searches for process execution events on the compromised web server during the initial attack.

```kql
DeviceProcessEvents_CL
| where TimeGenerated between (datetime(2026-09-20 06:50:00) .. datetime(2026-09-20 07:00:00))
| where DeviceName == "sc-portal01"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Findings:**

The query identified a suspicious `python3` command executed on `sc-portal01` at approximately 06:52:52 UTC.

The command contained socket and subprocess functionality consistent with reverse-shell activity, supporting the finding of remote code execution.

<img width="848" height="357" alt="Initial Compromise" src="https://github.com/user-attachments/assets/cb909b0a-0417-4c8c-bb83-4e9528a9120c" />


### Query 2: Credential Harvesting – Configuration File Access

This query identifies suspicious commands used to access application configuration files on the compromised web server.

```kql
DeviceProcessEvents_CL
| where TimeGenerated between (datetime(2026-09-20 06:55:00) .. datetime(2026-09-20 07:15:00))
| where DeviceName == "sc-portal01"
| where ProcessCommandLine contains "portal.conf"
    or ProcessCommandLine contains "cat "
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Findings:**

The attacker executed `cat /etc/semicrest/portal.conf` on `sc-portal01` at approximately 07:05 UTC. The file contained service account credentials associated with PostgreSQL and Harbor, making it a key target for credential harvesting.

<img width="868" height="573" alt="Credential Harvesting" src="https://github.com/user-attachments/assets/0eea4c68-913c-4f41-b484-00bfab6aa062" />



### Query 3: PostgreSQL Activity – Investigating Database Connections

This query examines PostgreSQL and system activity on `sc-db01` during a suspicious connection spike.

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:25:00) .. datetime(2026-09-20 07:35:00))
| where Computer == "sc-db01"
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

**Findings:**

The query returned PostgreSQL activity, including SQL statements, scheduled maintenance tasks, and database connection events.

Further investigation showed connection-limit errors alongside normal application queries. This helped distinguish the connection spike from confirmed attacker enumeration.

<img width="910" height="818" alt="PostgreSQL Activity" src="https://github.com/user-attachments/assets/e73ec177-985f-4152-82e1-376809dfa761" />


### Query 4: AI-Assisted Attack – Agent Tool Activity

This query filters AI agent logs to display attack-related automated actions.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24) .. datetime(2026-10-25))
| where HuntName == "quartzfang"
| where tool_name in (
    "scan_complete",
    "fuzz_schemes",
    "adapt_payload",
    "rce_confirmed",
    "harvest_creds",
    "query_database",
    "inspect_registry"
)
| project TimeGenerated, tool_name, tool_result
| order by TimeGenerated asc
```

**Findings:**

The query identified seven AI agent activities involving:

- **Reconnaissance:** `scan_complete`, `fuzz_schemes`
- **Exploitation:** `adapt_payload`, `rce_confirmed`
- **Credential Harvesting:** `harvest_creds`
- **Database Access:** `query_database`
- **Registry Investigation:** `inspect_registry`

The results demonstrated how AI was used to automate different attack stages.

However, some AI-generated claims were not verified by independent security logs, highlighting the importance of validating automated findings.

<img width="835" height="567" alt="AI-Assisted Attack" src="https://github.com/user-attachments/assets/0dfb23c0-ce5e-45de-b9d6-895260fe6c63" />

---


## Skills Demonstrated

- Threat hunting and incident investigation.
- Writing and troubleshooting KQL queries.
- Investigating credential theft and lateral movement.
- Analyzing suspicious processes and database activity.
- Correlating evidence across multiple log sources.
- Investigating AI-assisted cyberattacks.
- Identifying false positives through baseline analysis.
- Applying the MITRE ATT&CK framework.

## Conclusion

Operation QUARTZFANG helped me gain practical experience investigating a simulated cyberattack using **Microsoft Azure Log Analytics and KQL**.

I learned how to trace suspicious activity across multiple systems, investigate attacker techniques, and verify findings using different security logs.

One of my biggest takeaways was that **not every suspicious event is malicious**, and AI-generated information should always be verified against actual evidence.

This project strengthened my understanding of SOC operations, threat hunting, and incident investigation.



---

*This project was completed in an authorized cybersecurity training environment using simulated attack data.*
