
# Operation QUARTZFANG – Complete Threat Hunting Investigation Report

**Microsoft Azure | KQL | SOC Investigation | MITRE ATT&CK**

## Project Overview

Operation QUARTZFANG is a hands-on SOC threat-hunting investigation involving a simulated AI-assisted cyberattack against **SemiCrest Technologies**. I used Microsoft Azure Log Analytics and Kusto Query Language (KQL) to analyze security events, investigate suspicious activity, and reconstruct the attacker's actions across multiple systems.

This report documents all 28 investigation flags across eight sections, including the KQL queries, findings, and reasoning behind each investigation.

## Investigation Environment

**Log Analytics Workspace:** `LAW-HuntPractice`


---

# Section 1: Initial Access

## Flag 1 – Vulnerable endpoint

### Objective

Identify which endpoint the attacker targeted during the initial compromise.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:45:00) .. datetime(2026-09-20 07:00:00))
| project TimeGenerated, SrcIpAddr, HttpStatusCode, UserAgent, RawEvent=pack_all()
| order by TimeGenerated asc
```

<img width="1167" height="518" alt="image" src="https://github.com/user-attachments/assets/b897a17b-eb70-4f37-8da1-607946ae368d" />


### Findings

Suspicious requests targeted the web portal's document preview functionality around 06:52 UTC. The requests occurred shortly before unusual process execution was observed on the web server.

### Investigation Reasoning

I started by searching the web access logs around the alert timestamp and comparing the source addresses, requests, and HTTP response codes. This helped me narrow down the targeted functionality and identify the activity associated with the initial exploitation attempt.

---

## Flag 2 – The Self-correct

### Objective

Identify the URL schemes involved in the exploitation attempts and compare their timing.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:52:00) .. datetime(2026-09-20 06:53:00))
| project TimeGenerated, SrcIpAddr, HttpStatusCode, RawEvent=pack_all()
| order by TimeGenerated asc
```

<img width="1151" height="329" alt="image" src="https://github.com/user-attachments/assets/cfed2e2c-16ce-405d-bac0-aa7126a43558" />


### Findings

Two suspicious document preview requests occurred within seconds of each other. The first request was rejected, while the following request was accepted. The AI agent logs also showed URL scheme testing and payload modification during this period.

### Investigation Reasoning

I compared the timestamps and HTTP response codes of the suspicious requests to understand how the attack progressed. The change between attempts suggested that the attacker adjusted the exploitation technique after the initial failure. The exact schemes and time gap should be confirmed against the original request records.

---

## Flag 3 – Exploit source

### Objective

Determine which external IP address originated the initial exploitation attempts.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:52:00) .. datetime(2026-09-20 06:53:00))
| summarize RequestCount=count() by SrcIpAddr
| order by RequestCount desc
```

<img width="404" height="156" alt="image" src="https://github.com/user-attachments/assets/6be07806-f654-4962-969b-c9057c40bd48" />


### Findings

The suspicious external source was identified by examining the IP addresses associated with requests during the exploitation window and matching them to the document preview activity.

### Investigation Reasoning

I grouped requests by their source IP addresses to identify which systems were communicating with the web application during the attack. Rather than assuming that the source generating the most traffic was malicious, I focused on the address associated with the suspicious exploitation attempts.

---

## Flag 4 – Exploitation chain

### Objective

Determine whether the attacker successfully executed commands on the web server.

### KQL Query

```kql
DeviceProcessEvents_CL
| where TimeGenerated between (datetime(2026-09-20 06:50:00) .. datetime(2026-09-20 07:00:00))
| where DeviceName == "sc-portal01"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="865" height="300" alt="image" src="https://github.com/user-attachments/assets/dce28ed0-53de-430c-a3b2-08ef32c1cdd1" />


### Findings

A suspicious `python3` command executed on `sc-portal01` at approximately 06:52:52 UTC. The command contained Python socket and subprocess functionality consistent with reverse-shell execution, indicating that the attacker had progressed beyond simply sending requests to the web application.

### Investigation Reasoning

A successful HTTP request alone does not prove that a server was compromised, so I compared the web access activity with endpoint process execution logs. The unexpected Python command appeared immediately after the suspicious requests, providing stronger evidence that the exploitation attempt resulted in remote code execution.


---

# Section 2: Credential Harvest

## Flag 5 – Configuration file and process tree

### Objective

Determine which configuration file the attacker accessed after compromising the web server.

### KQL Query

```kql
DeviceProcessEvents_CL
| where TimeGenerated between (datetime(2026-09-20 06:55:00) .. datetime(2026-09-20 07:15:00))
| where DeviceName == "sc-portal01"
| where ProcessCommandLine contains "portal.conf"
    or ProcessCommandLine contains "cat "
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="673" height="241" alt="image" src="https://github.com/user-attachments/assets/463d6be0-d1ad-445b-bfbd-f719eb0a21ae" />


### Findings

The attacker executed `cat /etc/semicrest/portal.conf` on `sc-portal01` at approximately 07:05:15 UTC. The targeted file was an application configuration file associated with credentials used by internal services.

### Investigation Reasoning

After confirming the initial compromise, I investigated commands executed on the affected server to determine what the attacker accessed next. The `cat` command showed that the configuration file was read during the credential-harvesting stage, helping connect the initial compromise to the attacker's later attempts to access internal systems.



---

## Flag 6 – Database credential

### Objective

Identify the database service account exposed during credential harvesting.

### KQL Query

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24) .. datetime(2026-10-25))
| where HuntName == "quartzfang"
| where tool_name == "harvest_creds"
| project TimeGenerated, tool_name, tool_result
| order by TimeGenerated asc
```

<img width="675" height="180" alt="image" src="https://github.com/user-attachments/assets/955e4b2b-ad30-45da-a3ac-b8a3214eb9ec" />


### Findings

The credential-harvesting investigation identified the PostgreSQL service account `portal_svc`, associated with the database destination `10.5.0.20:5432`. The password is intentionally excluded from this public report.

### Investigation Reasoning

I reviewed the AI agent's credential-harvesting records and connected the identified service account to the configuration file accessed on the compromised server. This helped explain how the attacker obtained information that could be used to authenticate to the internal PostgreSQL database.

---

## Flag 7 – Registry credential

### Objective

Determine which account was used to access the Harbor container registry.

### KQL Query

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24) .. datetime(2026-10-25))
| where HuntName == "quartzfang"
| where tool_name == "harvest_creds"
| project TimeGenerated, tool_name, tool_result
```

<img width="714" height="173" alt="image" src="https://github.com/user-attachments/assets/66a8d3de-fc93-432e-8f09-d1b6cdc0651d" />


### Findings

The investigation identified the `ci-builder` account associated with the Harbor container registry at `10.5.0.30`. This account was another set of service credentials referenced during the attacker's credential-harvesting activity.

### Investigation Reasoning

I examined the credential-harvesting results to determine whether the compromised configuration file exposed access to additional internal services. Identifying the Harbor service account helped explain how the attacker could move beyond the web application and begin exploring the container registry.

---

## Flag 8 – Visibility Gap

### Objective

Determine whether environment variables exposed additional credentials.

### KQL Query

```kql
DeviceProcessEvents_CL
| where DeviceName == "sc-portal01"
| where TimeGenerated between (datetime(2026-09-20 07:00:00) .. datetime(2026-09-20 07:10:00))
| where FileName == "env"
    or ProcessCommandLine contains "env"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="825" height="268" alt="image" src="https://github.com/user-attachments/assets/4a7e3782-1ad0-47b0-9cbb-665e134fa410" />


### Findings

The attacker executed an environment-variable command, but the available logs did not capture its output. As a result, there was insufficient evidence to confirm whether additional credentials were successfully obtained through environment variables.

### Investigation Reasoning

I examined process execution records to determine whether the attacker attempted to collect credentials beyond those stored in the configuration file. Although the logs showed command execution, they did not reveal the actual environment-variable values, demonstrating why investigators must distinguish observed actions from confirmed outcomes.

---

# Section 3: Lateral Movement

## Flag 9 – Database query discrimination

### Objective

Determine how the attacker's PostgreSQL queries differed from legitimate application activity.

### KQL Query

```kql
Syslog
| where Computer == "sc-db01"
| where TimeGenerated between (datetime(2026-09-20 07:00:00) .. datetime(2026-09-20 08:00:00))
| where SyslogMessage contains "statement:"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<img width="947" height="543" alt="image" src="https://github.com/user-attachments/assets/17f232f0-39ad-4814-8d6e-116e049b02f7" />


### Findings

The attacker's database activity differed from normal application behavior through broader query scope and rapid execution. The suspicious queries involved multiple areas of the database rather than only the information normally required by the application.

### Investigation Reasoning

I compared the SQL statements associated with suspicious activity against ordinary application queries, focusing on the type of information requested and how quickly queries were executed. The broader query patterns and increased activity helped distinguish database enumeration from legitimate application operations.

---

## Flag 10 – Queried tables

### Objective

Determine which PostgreSQL tables the attacker accessed.

### KQL Query

```kql
Syslog
| where Computer =~ "sc-db01"
| where SyslogMessage has "statement: SELECT *" or SyslogMessage has "information_schema" or SyslogMessage has "pg_catalog"
| project TimeGenerated, SyslogMessage
```

<img width="833" height="211" alt="image" src="https://github.com/user-attachments/assets/7a36d9b2-4515-4e01-8315-0fa22acbcd57" />


### Findings

The investigation identified suspicious queries involving the `customers`, `projects`, `users`, and `pg_catalog` tables. These queries covered application information as well as PostgreSQL system metadata.

### Investigation Reasoning

I examined the SQL statements to identify the tables referenced during the suspicious activity. Accessing information across several application tables and the PostgreSQL system catalog suggested broader database exploration rather than a limited set of routine application requests.

---

## Flag 11 – Registry enumeration

### Objective

Identify suspicious operations performed against the internal Harbor container registry.

### KQL Query

```kql
ContainerRegistryLog_CL
| where Computer =~ "sc-registry01"
| where Username == "ci-builder" and SrcIpAddr == "10.5.0.10"
| project TimeGenerated, Operation, Repository, HttpStatusCode
```

<img width="707" height="192" alt="image" src="https://github.com/user-attachments/assets/62e85f55-f77d-4617-bb1f-1cfdadf447c7" />


### Findings

The suspicious container registry activity involved operations such as `login`, `list_repository`, `pull_manifest`, and `inspect_layer`. These operations indicated that the attacker was exploring the registry and inspecting container-related resources.

### Investigation Reasoning

I compared registry activity associated with the compromised portal server against expected CI/CD operations. Legitimate automation primarily performed routine artifact operations, while the additional repository enumeration and image inspection activity suggested that the attacker was gathering information from the registry.

---

## Flag 12 – Admin API response

### Objective

Determine whether the attacker successfully accessed the administrative API secrets endpoint.

### KQL Query

```kql
Syslog
| where Computer =~ "sc-admin01"
| where SyslogMessage has "secrets" and SyslogMessage has "10.5.0.10"
| project TimeGenerated, SyslogMessage
```

<img width="613" height="160" alt="image" src="https://github.com/user-attachments/assets/8709782d-0935-48a7-be9e-06436aacd2ea" />


### Findings

The investigation identified administrative API activity involving secrets-related requests originating from the compromised portal server at `10.5.0.10`. The attacker's request returned HTTP 403 Forbidden, indicating that access was denied.

### Investigation Reasoning

I searched the administrative server's Syslog records for messages containing both the secrets-related activity and the compromised portal server's IP address. This helped isolate the attacker's requests from other API activity, and the HTTP response provided evidence that the attempted access was unsuccessful.

---

# Section 4: AI Hallucination

## Flag 13 – Secrets store Hallucination

### Objective

Determine whether the AI agent's claim of successfully accessing secrets was supported by actual security logs.

### KQL Query

```kql
LLMAgentLogs_CL
| where model_response has "secrets"
| where TimeGenerated > datetime(2026-09-20T07:45:00Z)
| project TimeGenerated, model_response
```
<img width="1138" height="282" alt="image" src="https://github.com/user-attachments/assets/9abf5eab-60bc-488d-84dc-95d4d838bc7e" />


### Findings

The AI agent reported information suggesting that sensitive secrets had been obtained. However, the administrative API evidence showed that the attacker's request was denied with an HTTP 403 response, leaving the claim unsupported by independent security logs.

### Investigation Reasoning

I searched the AI agent's responses for references to secrets and compared those statements with the administrative server's actual logs. The difference between the AI's reported success and the denied API request demonstrated why AI-generated findings should be validated against system telemetry before being considered accurate.

---


## Flag 14 – Registry credential hallucination

### Objective

Determine whether the AI agent actually discovered administrative database credentials inside a container image layer.

### KQL Query

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 07:00:00) .. datetime(2026-09-20 08:30:00))
| extend Evidence=tostring(pack_all())
| where Evidence contains "inspect_layer"
| project TimeGenerated, Evidence
| order by TimeGenerated asc
```

<img width="1148" height="193" alt="image" src="https://github.com/user-attachments/assets/755f858d-7742-416c-8ac9-5accef5cd945" />


### Findings

The registry logs showed that the `ci-builder` account performed an `inspect_layer` operation on `sc-registry01` at approximately 07:33 UTC, originating from `10.5.0.10`. Although the AI agent claimed it discovered administrative database credentials inside the image layer, the registry logs only confirmed that the inspection occurred and did not verify the reported credentials.

### Investigation Reasoning

I compared the AI agent's claim with the actual container registry activity to determine whether the reported credentials were supported by evidence. The logs confirmed the image-layer inspection but did not show that administrative credentials were retrieved. This indicated that the AI's claim was unverified and demonstrated why AI-generated findings must be checked against actual security logs.


---


## Flag 15 – Hallucination as autonomy limitation

### Objective

Understand the limitations of AI-assisted attacks and why human involvement is still important.

### KQL Query

```kql
LLMAgentLogs_CL
| where isnotempty(user_input)
| project TimeGenerated, user_input, model_response
| order by TimeGenerated asc
```

### Findings

The AI agent logs recorded human instructions alongside AI-generated responses. During the investigation, some AI-generated claims about accessing sensitive information were not supported by actual security logs, showing that the AI could produce inaccurate results.

### Investigation Reasoning

I compared the human operator's instructions with the AI agent's responses to understand how the attack was directed. I also considered the earlier findings where the AI claimed to obtain sensitive information without supporting evidence. This showed that AI could automate parts of the attack but still required human oversight to verify results and make important decisions.


---

# Section 5: Data Exfiltration and Persistence


## Flag 16 – Exfil destination and staging path

### Objective

Identify the suspicious outbound network connection and the encrypted file associated with potential data exfiltration.

### KQL Query 1 – Network Evidence

```kql
DeviceNetworkEvents_CL
| where DeviceName =~ "sc-portal01"
| where RemoteIP == "198.51.100.210"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="675" height="229" alt="image" src="https://github.com/user-attachments/assets/72dd3bc9-387e-49f5-9bea-d03f8023bcf9" />


### KQL Query 2 – File Evidence

```kql
DeviceFileEvents_CL
| where DeviceName =~ "sc-portal01"
| where FileName =~ "report.tar.gz.enc"
| project Timestamp, FileName, FolderPath, ActionType
```
<img width="686" height="193" alt="image" src="https://github.com/user-attachments/assets/3a257b49-96d9-4d37-aaae-a2a94593cca2" />


### Findings

The investigation identified an outbound HTTPS connection from `sc-portal01` to `198.51.100.210:443`, along with an encrypted archive named `report.tar.gz.enc` stored under `/tmp/portal-cache/`. The archive was prepared before the suspicious connection, suggesting that the attacker may have staged collected information for exfiltration. However, the available evidence did not confirm the exact amount of data transferred.

### Investigation Reasoning

I examined the network logs to identify unusual outbound connections from the compromised server and compared them with file activity involving the encrypted archive. By correlating the archive's creation with the later connection to an external IP address, I identified a pattern consistent with possible data exfiltration. This provided stronger evidence than treating the HTTPS connection alone as malicious.


---

## Flag 17 – Staging tools

### Objective

Determine which commands the attacker used to prepare collected data.

### KQL Query

```kql
DeviceProcessEvents_CL
| where DeviceName == "sc-portal01"
| where TimeGenerated between (datetime(2026-09-20 07:50:00) .. datetime(2026-09-20 08:15:00))
| where FileName in ("tar", "gzip", "openssl")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1107" height="260" alt="image" src="https://github.com/user-attachments/assets/d4e3b8a5-641d-47f7-930d-42d439e510f2" />


### Findings

The attacker used `tar`, `gzip`, and `openssl` to archive, compress, and encrypt data. The resulting staged archive was identified as `/tmp/portal-cache/report.tar.gz.enc`, which was prepared before the suspicious outbound connection.

### Investigation Reasoning

I reviewed the process execution sequence to determine how the attacker handled the collected information. The use of archiving, compression, and encryption tools suggested that data was being prepared for transfer, especially when correlated with the later outbound HTTPS connection.

---

## Flag 18 – Persistence Mechanism

### Objective

Determine how the attacker attempted to maintain access to the compromised system.

### KQL Query

```kql
DeviceProcessEvents_CL
| where DeviceName == "sc-portal01"
| where TimeGenerated between (datetime(2026-09-20 08:20:00) .. datetime(2026-09-20 08:35:00))
| where FileName in ("useradd", "usermod")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="597" height="179" alt="image" src="https://github.com/user-attachments/assets/60db4ed4-b5d0-475a-8e85-cf3ee169fae8" />


### Findings

The attacker created a local account named `svc_monitor` and added it to the `sudo` group. This gave the newly created account elevated privileges on the compromised system.

### Investigation Reasoning

I investigated account creation and modification commands executed after the initial compromise. The unexpected creation of a privileged local account suggested that the attacker was attempting to establish a way to maintain access to the system.

---

## Flag 19 – Exfil vs legitimate HTTPS

### Objective

Explain why the suspicious outbound connection differed from legitimate HTTPS communication.

### KQL Query

```kql
DeviceProcessEvents_CL
| where DeviceName == "sc-portal01"
| where TimeGenerated between (datetime(2026-09-20 08:00:00) .. datetime(2026-09-20 08:20:00))
| where FileName in ("tar", "gzip", "openssl", "curl")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1086" height="274" alt="image" src="https://github.com/user-attachments/assets/cef1012f-3acb-46f7-834a-8754f7e72ef5" />


### Findings

The suspicious HTTPS connection occurred after encrypted archive preparation and targeted an unusual external IP address. These surrounding activities made the connection more concerning than ordinary application traffic over port 443.

### Investigation Reasoning

HTTPS traffic alone is not enough to classify an event as malicious, so I examined the surrounding process and file activity. The relationship between encrypted data staging, connection timing, and the external destination provided stronger evidence of possible exfiltration.

---

# Section 6: Reconnaissance and Timing

## Flag 20 – Scanner IPs

### Objective

Identify suspicious external scanning sources and the legitimate internal vulnerability scanner.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:00:00) .. datetime(2026-09-20 07:00:00))
| summarize RequestCount=count() by SrcIpAddr
| order by RequestCount desc
```

<img width="445" height="653" alt="image" src="https://github.com/user-attachments/assets/5336e8cf-9591-47af-b834-7b184bc8e650" />


### Findings

The external scanning addresses included `198.51.100.31`, `198.51.100.45`, and `198.51.100.62`, while the legitimate internal Nessus scanner used `10.5.0.250`. These sources generated web requests during the reconnaissance period.

### Investigation Reasoning

I grouped web requests by their source addresses to identify systems generating repeated scanning activity. I then compared those addresses against the known internal vulnerability scanner to distinguish external reconnaissance from authorized scanning.

---

## Flag 21 – Recon vs Nessus discrimination

### Objective

Identify the differences between suspicious reconnaissance and legitimate vulnerability scanning.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:00:00) .. datetime(2026-09-20 07:00:00))
| summarize
    RequestCount=count(),
    Agents=make_set(UserAgent),
    StatusCodes=make_set(HttpStatusCode)
    by SrcIpAddr
| order by RequestCount desc
```
<img width="935" height="653" alt="image" src="https://github.com/user-attachments/assets/59a90bd2-c0f2-45ee-ad54-a0ee9bc1ae97" />


### Findings

The external scanning activity commonly used `python-requests/2.31.0`, while legitimate internal scanning used `Nessus/10.6.2`. The external traffic also showed rapid request bursts and unsuccessful HTTP responses.

### Investigation Reasoning

I compared the user agents, source addresses, request frequency, and HTTP responses to understand the purpose of the activity. The differences between the external requests and expected Nessus behavior helped distinguish suspicious reconnaissance from authorized vulnerability scanning.

---

## Flag 22 – Timing signature

### Objective

Determine whether the scanning activity appeared automated or manually executed.

### KQL Query

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:00:00) .. datetime(2026-09-20 07:00:00))
| where SrcIpAddr in (
    "198.51.100.31",
    "198.51.100.45",
    "198.51.100.62"
)
| summarize RequestCount=count()
    by SrcIpAddr, bin(TimeGenerated, 1s)
| order by RequestCount desc
```

### Findings

The web access logs showed multiple requests occurring within individual seconds, often following repeated patterns. This behavior was consistent with automated scanning rather than individual manual requests.

### Investigation Reasoning

I grouped requests into one-second intervals to examine how quickly the scanning activity occurred. The rapid and repetitive nature of the traffic suggested automation, although duplicate log records could affect the exact request counts.

---

# Section 7: Autonomy

## Flag 23 – Operator decision gates

### Objective

Identify where the human operator gave instructions or authorized the next stage of the attack.

### KQL Query

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24) .. datetime(2026-10-25))
| where HuntName == "quartzfang"
| where isnotempty(user_input)
| project TimeGenerated, user_input, gate_decision
| order by TimeGenerated asc
```

<img width="903" height="647" alt="image" src="https://github.com/user-attachments/assets/fe52fdb7-b815-4665-bb3e-396449d1cf00" />


### Findings

The AI agent logs contained human instructions involving initial reconnaissance, credential harvesting, lateral movement, data collection, staging, and exfiltration. These instructions showed that human involvement continued throughout important parts of the operation.

### Investigation Reasoning

I reviewed the AI agent's input records to identify instructions that directed or approved different stages of the attack. The presence of these instructions demonstrated that the AI performed technical activities while a human operator remained involved in major decisions. The exact number recognized by the lab as formal decision gates was not conclusively verified.

---


## Flag 24 – Autonomy placement

### Objective

Determine whether the attack was controlled by a human, executed autonomously, or involved both human decisions and AI automation.

### KQL Query 1 – Human Involvement

```kql
LLMAgentLogs_CL
| where isnotempty(user_input)
| project TimeGenerated, user_input
```
<img width="1136" height="541" alt="image" src="https://github.com/user-attachments/assets/b65e1bea-1069-49b8-8084-249ed2a1da56" />


### KQL Query 2 – Machine-Speed Execution

```kql
PortalAccessLog_CL
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode
```

<img width="1122" height="175" alt="image" src="https://github.com/user-attachments/assets/58ba94e3-02ba-4b03-b9e2-d9fe1de8556f" />


### Findings

The attack was classified as **human-directed and AI-executed**. The AI agent logs showed five human operator instructions, while the web access logs revealed rapid exploitation attempts, including an 18-second adjustment between requests. This demonstrated that humans made important decisions while the AI handled much of the technical execution.

### Investigation Reasoning

I compared human instructions in `LLMAgentLogs_CL.user_input` with the rapid web requests recorded in `PortalAccessLog_CL.TimeGenerated`. The human instructions showed that an operator directed the attack at important stages, while the fast request patterns demonstrated automated execution. This helped me determine that the operation was human-assisted rather than completely manual or fully autonomous.


## Flag 25 – Novel ATT&CK technique

### Objective

Identify the MITRE ATT&CK technique associated with acquiring AI capabilities for offensive purposes.

### KQL Query

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24) .. datetime(2026-10-25))
| where HuntName == "quartzfang"
| where isnotempty(tool_name)
| summarize
    TotalEvents=count(),
    Tools=make_set(tool_name)
```

### Findings

The relevant MITRE ATT&CK technique was **T1588.007 – Obtain Capabilities: Artificial Intelligence**, which belongs to the Resource Development tactic and addresses acquiring AI capabilities for offensive use.

### Investigation Reasoning

I used the question's reference to Resource Development and offensive AI capabilities to locate the appropriate MITRE ATT&CK technique. The AI agent logs supported the presence of AI-assisted activity, while the MITRE ATT&CK framework provided the actual technique classification.


---

# Section 8: Real or Noise

## Flag 26 – Credential reuse across services (Real or Noise)

### Objective

Determine how to distinguish legitimate `portal_svc` activity from attacker activity.

### KQL Query

```kql
Syslog
| where Computer == "sc-db01"
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where SyslogMessage contains "portal_svc"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```
<img width="1075" height="463" alt="image" src="https://github.com/user-attachments/assets/ea45e1a6-e5f8-4548-8ee6-7f19027c5d1f" />


### Findings

The primary distinguishing property was the source IP address or originating host. Although both the attacker and legitimate application used the `portal_svc` account, their activity could be investigated based on where the sessions originated.

### Investigation Reasoning

I examined the source of the database connections because the account name alone could not distinguish malicious activity from expected application behavior. Comparing the originating systems helped identify suspicious sessions without assuming that every use of the shared service account was malicious.

---

## Flag 27 – pg_dump disconfirmation

### Objective

Determine whether the scheduled `pg_dump` backup was associated with the intrusion.

### KQL Query

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-18) .. datetime(2026-09-21))
| where Computer == "sc-db01"
| where SyslogMessage contains "pg_dump"
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```
<img width="1012" height="222" alt="image" src="https://github.com/user-attachments/assets/f7adb8ab-25de-425f-8e50-f672fb4202e7" />


### Findings

The PostgreSQL backup was identified as legitimate baseline activity. The logs showed that the backup ran at approximately 03:00 and that similar activity had occurred before the intrusion, making it consistent with an established backup schedule.

### Investigation Reasoning

Although the backup used the same service account involved in the attack, I reviewed historical logs to determine whether the activity existed before the compromise. The recurring schedule helped demonstrate that the backup was a normal system operation rather than part of the attack.

---

## Flag 28 – Connection spike dead end

### Objective

Determine whether the PostgreSQL connection spike around 07:30 was part of the attack.

### KQL Query

```kql
Syslog
| where Computer == "sc-db01"
| where TimeGenerated between (datetime(2026-09-20 07:29:00) .. datetime(2026-09-20 07:35:00))
| where SyslogMessage has_any (
    "statement",
    "connection",
    "FATAL"
)
| summarize EventCount=count() by SyslogMessage
| order by EventCount desc
```

<img width="1137" height="482" alt="image" src="https://github.com/user-attachments/assets/67c0c8c1-ceda-4ed3-93ba-6e1485e9ca9e" />


### Findings

The connection spike was classified as noise associated with database connection exhaustion. The logs included errors such as `FATAL: sorry, too many clients already`, along with ordinary application SQL statements that differed from the attacker's earlier enumeration queries.

### Investigation Reasoning

The high connection volume initially appeared suspicious because it resembled automated database enumeration. However, after examining the SQL statements and connection-limit errors, I found that the visible activity was consistent with an application-related connection exhaustion event. This demonstrated why the content and context of database activity are more important than connection volume alone.


---

# Overall Investigation Summary

Operation QUARTZFANG involved a simulated AI-assisted cyberattack against SemiCrest Technologies. Throughout the investigation, I analyzed web application exploitation, remote code execution, credential harvesting, lateral movement, database enumeration, suspicious outbound network activity, persistence, and AI-assisted execution.

The investigation also demonstrated the importance of independently verifying AI-generated claims and distinguishing legitimate system operations from malicious activity. By correlating evidence across multiple log sources, I was able to reconstruct the attacker's actions and identify areas where the available telemetry did not support a definitive conclusion.

## Skills Demonstrated

- Writing and troubleshooting KQL queries
- Investigating security alerts using Azure Log Analytics
- Correlating web, endpoint, database, and network logs
- Identifying credential access and lateral movement
- Investigating persistence and possible exfiltration
- Evaluating AI-generated security information
- Distinguishing legitimate activity from malicious behavior
- Using MITRE ATT&CK to categorize attacker techniques
- Documenting technical findings and supporting evidence

---
