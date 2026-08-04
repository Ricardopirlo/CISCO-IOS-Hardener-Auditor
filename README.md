# 🛡️ Cisco IOS Hardening Auditor

An automated Python tool designed for security analysts and network administrators to audit Cisco IOS configuration files against industry hardening standards. 

This tool parses router/switch configurations using optimized Regular Expressions (RegEx), evaluates critical security controls, and generates a compliance score along with a professional **Markdown Remediation Report**.

## 📊 Key Security Controls Audited

The tool validates critical baseline rules aligned with hardening frameworks:

* **Protocol Security:** Detects insecure SSHv1 and plain-text Telnet access.
* **Authentication & Access Control:** Audits VTY line local authentication requirements and source IP filtering (`access-class`).
* **Privilege Escalation:** Verifies robust hashing (`enable secret`) versus obsolete encryption types.
* **Telemetry & Forensics:** Checks for centralized SIEM logging (`syslog host`) and accurate NTP time synchronization.
* **Information Leakage:** Identifies unsecure MOTD banners exposing operating system versions or hardware models.

---

## 🚀 How It Works & Architecture

1. **Scanner Stage:** Reads and cleans raw configuration text, stripping native Cisco comments (`!`, `#`) and blank lines.
2. **Analysis Stage:** Utilizes pre-compiled, case-insensitive regular expressions to track session block states (such as active VTY submodes) and flag global misconfigurations.
3. **Reporting Stage:** Structures findings dynamically into severity matrices (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and outputs both a clean CLI summary and an exportable `.md` report.

---

## 🚀 Architecture & Overview


---
### 📂 Directory Setup

Clone the repository and ensure your local workspace matches this clean structure:

```text
cisco-ios-hardening-auditor/
│
├── net_hardener.py          # Core audit scanner & logic engine
├── router_vulnerable.conf   # Sample vulnerable Cisco IOS configuration
├── .gitignore               # Excludes python cache and local outputs
└── README.md                # Project documentation
```


---

### 🚀 Usage

1. Place your target Cisco configuration file in the project directory (default expected filename in script main block: `router_vulnerable.conf`).
2. Execute the script from your terminal:

```bash
python net_hardener.py
```


---

## 📋 Sample Outputs

### 🖥️ Terminal Dashboard View

When executed, the script outputs a clean, structured compliance dashboard directly to the CLI interface:

```text
[+] File 'router_vulnerable.conf' loaded successfully. Total lines to evaluate: 142

[+] Initiating compliance security audit...
----------------------------------------------------------------------

======================================================================
ID         | SECURITY RULE                  | SEVERITY   | STATUS    
======================================================================
RULE-01    | SSH Protocol Version           | HIGH       | 🔴 FAIL   
RULE-02    | Secure Shell Enforce [Telnet]  | HIGH       | 🟢 PASS   
RULE-03    | VTY Line Timeout               | MEDIUM     | 🔴 FAIL   
RULE-04    | Centralized Logging (Syslog)   | MEDIUM     | 🔴 FAIL   
RULE-05    | Unsecure MOTD Banner           | LOW        | 🟢 PASS   
======================================================================

[💾] Markdown report successfully saved to: 'Audit_Report.md'

```

---

### 📝 Generated Executive Report (`Audit_Report.md`)

The script automatically writes a complete remediation plan. Failed rules explicitly display their exact risk descriptions and the required Cisco IOS mitigation commands:

> ### ❌ [RULE-01] SSH Protocol Version (Severity: HIGH)
> 
> 
> * **Risk Description:** Insecure SSHv1 protocol is allowed.
> * **Mitigation Command(s):** Enforce SSHv2 by configuring `ip ssh version 2` in global configuration mode.
> 
> 

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
