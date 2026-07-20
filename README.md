\# 🛡️ Cisco IOS Hardening Auditor



An automated Python tool designed for security analysts and network administrators to audit Cisco IOS configuration files against industry hardening standards.



This tool parses router/switch configurations using optimized Regular Expressions (RegEx), evaluates critical security controls, and generates a compliance score along with a professional \*\*Markdown Remediation Report\*\*.



\## 📊 Key Security Controls Audited

The tool validates 11 critical baseline rules aligned with hardening frameworks:

\* \*\*Protocol Security:\*\* Detects insecure SSHv1 and plain-text Telnet access.

\* \*\*Authentication \& Access Control:\*\* Audits VTY line local authentication requirements and source IP filtering (`access-class`).

\* \*\*Privilege Escalation:\*\* Verifies robust hashing (`enable secret`) versus obsolete encryption types.

\* \*\*Telemetry \& Forensics:\*\* Checks for centralized SIEM logging (`syslog host`) and accurate NTP time synchronization.

\* \*\*Information Leakage:\*\* Identifies unsecure MOTD banners exposing operating system versions or hardware models.



\---



\## 🚀 How It Works \& Architecture



1\. \*\*Scanner Stage:\*\* Reads and sanitizes raw configuration text, stripping native Cisco comments (`!`, `#`) and blank lines.

2\. \*\*Analysis Stage:\*\* Utilizes pre-compiled, case-insensitive regular expressions to track session block states (such as active VTY submodes) and flag global misconfigurations.

3\. \*\*Reporting Stage:\*\* Structure findings dynamically into severity matrices (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and outputs both a clean CLI summary and an exportable `.md` report.



\---



\## 🛠️ Installation \& Usage



\### Prerequisites

\* Python 3.x

\* No external libraries required (\*\*Standard Library only\*\* - zero dependencies).



\### Running the Tool

1\. Clone this repository:

&#x20;  ```bash

&#x20;  git clone \[https://github.com/YOUR\_USERNAME/cisco-ios-hardening-auditor.git](https://github.com/YOUR\_USERNAME/cisco-ios-hardening-auditor.git)

&#x20;  cd cisco-ios-hardening-auditor

