import re
import sys
from datetime import datetime

def scanner(path_file): 
    try:    
        # Open the file in read-only mode ('r') using a 'with' block 
        # to guarantee the file handles are closed automatically.
        with open(path_file, 'r') as file:
            raw_lines = [line.strip() for line in file.readlines()]
            
            # Filter out blank lines and Cisco native comments (! or #).
            lines = [line for line in raw_lines if line and not line.startswith(('!', '#'))]
            return lines
    except FileNotFoundError:
        # If the file does not exist, display an explicit error and safely abort execution.
        print(f"[❌ ERROR] The file could not be found: {path_file}")
        sys.exit(1)
    

def audit_conf(lines):
    print("\n[+] Initiating compliance security audit...")
    print("-" * 70)
    
    # Flags to track audit compliance findings
    ssh_v1_detected = False
    telnet_detected = False
    exec_timeout_conf = False
    syslog_conf = False
    banner_info_leak = False
    enable_password_detected = False  # Obsolete Type 7 password
    enable_secret_detected = False    # Secure Hashed password
    snmp_default_ro_detected = False  
    snmp_default_rw_detected = False
    inside_vty_block = False
    ntp_conf = False 
    http_server_active = False         
    https_secure_active = False 
    vty_access_class_conf = False   

    # --- REGULAR EXPRESSIONS (REGEX) COMPILATION ---

    # SSH v1: Detects "ssh version 1" or decimal variants (e.g., "version 1.5").
    # Uses word boundaries (\b) to avoid false positives like "version 12".
    patron_ssh = re.compile(r"ssh\s+version\s+1(?:\.\d+)?\b", re.IGNORECASE)
    
    # Telnet: Detects if "telnet" or "all" is permitted within the "transport input" command.
    # Ignores intermediate protocols if present (e.g., skips "ssh" in "transport input ssh telnet").
    patron_telnet = re.compile(r"transport\s+input\s+(?:.*?\s+)?(telnet|all)\b", re.IGNORECASE)

    # Exec-timeout: Validates the command presence followed by its numerical values in minutes/seconds.
    patron_timeout = re.compile(r"exec-timeout\s+\d+", re.IGNORECASE)
    
    # Syslog: Validates the "logging host" command and extracts the IP address.
    # Supports traditional IPv4 formats (X.X.X.X) and IPv6 hexadecimal blocks.
    patron_syslog = re.compile(r"logging\s+host\s+(?:ipv[46]\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})", re.IGNORECASE)    
    
    # Banner MOTD Leak: Identifies if the banner exposes vendors, OS versions, or hardware models.
    patron_banner_leak = re.compile(r"banner\s+motd.*(cisco|ios|version|7200|\d{4})", re.IGNORECASE)

    # Privilege Mode Passwords: Differentiates between insecure (password) and robust (secret) hashes.
    patron_enable_password = re.compile(r"enable\s+password\b", re.IGNORECASE)
    patron_enable_secret = re.compile(r"enable\s+secret\b", re.IGNORECASE)
    
    # Default SNMP Communities: Identifies predictable strings in Read-Only (RO) or Read-Write (RW) modes.
    patron_snmp_ro = re.compile(r"snmp-server\s+community\s+(public|admin|manager)\s+ro\b", re.IGNORECASE)
    patron_snmp_rw = re.compile(r"snmp-server\s+community\s+(private|admin|manager|secret)\s+rw\b", re.IGNORECASE)
    
    # VTY Line Blocks: Tracks the opening, internal settings, and end boundaries of the virtual terminal submode.
    patron_vty_start = re.compile(r"^line\s+vty\s+\d+", re.IGNORECASE)
    patron_vty_login = re.compile(r"^\s*login(\s+local)?\b", re.IGNORECASE)
    patron_block_end = re.compile(r"^(!|line\s+|interface\s+|router\s+)", re.IGNORECASE)

    # NTP: Detects time synchronization targets using either IP addresses or FQDN domain names.
    patron_ntp = re.compile(r"ntp\s+server\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+)", re.IGNORECASE)
    
    # Web Management (HTTP vs HTTPS): Identifies if web administration uses unencrypted or secure channels.
    patron_http = re.compile(r"^ip\s+http\s+server\b", re.IGNORECASE)
    patron_https = re.compile(r"^ip\s+http\s+secure-server\b", re.IGNORECASE)
    
    # VTY Access Filtering (access-class): Validates that an ACL is applied to incoming management traffic (in).
    patron_access_class = re.compile(r"^\s*access-class\s+\S+\s+in\b", re.IGNORECASE)
    
# --- PARSING AND LINE PROCESSING LOGIC ---
    for line in lines:
        
        # Tracking state logic inside VTY blocks
        if patron_vty_start.search(line):
            inside_vty_block = True
            
        if inside_vty_block:
            if patron_vty_login.search(line):
                vty_login_conf = True
            if patron_access_class.search(line):     # Access control through ACL assignment
                vty_access_class_conf = True
            # If a new block delimiter is found and it is not a new VTY line, exit block context
            elif patron_block_end.search(line) and not patron_vty_start.search(line):
                inside_vty_block = False
        
        # Global security parameter evaluation
        if patron_ssh.search(line):
            ssh_v1_detected = True
        if patron_telnet.search(line):
            telnet_detected = True
        if patron_timeout.search(line):     
            exec_timeout_conf = True
        if patron_syslog.search(line):    
            syslog_conf = True
        if patron_banner_leak.search(line): 
            banner_info_leak = True
        if patron_enable_password.search(line):  
            enable_password_detected = True
        if patron_enable_secret.search(line):    
            enable_secret_detected = True
        if patron_snmp_ro.search(line):         
            snmp_default_ro_detected = True
        if patron_snmp_rw.search(line):         
            snmp_default_rw_detected = True 
        if patron_ntp.search(line):            
            ntp_conf = True   
        if patron_http.search(line):             
            http_server_active = True
        if patron_https.search(line):           
            https_secure_active = True


# --- ESTRUCTURACIÓN DE LOS RESULTADOS (REGLAS DE NEGOCIO) ---
    results = []

    # Regla 1: SSHv1
    results.append({
        "id": "RULE-01",
        "name": "SSH Protocol Version",
        "status": "FAIL" if ssh_v1_detected else "PASS",
        "severity": "HIGH",
        "desc": "Insecure SSHv1 protocol is allowed.",
        "mitigation": "Enforce SSHv2 by configuring 'ip ssh version 2' in global configuration mode."
    })
    #Regla 2: Telnet
    results.append({
        "id": "RULE-02",
        "name": "Secure Shell Enforce (VTY) Telnet",
        "status": "PASS" if not telnet_detected else "FAIL",
        "severity": "HIGH",
        "desc": "Unsecure Telnet protocol is allowed on VTY lines, exposing credentials in plain text over the network.",
        "mitigation": "Enforce SSH and block Telnet by configuring 'transport input ssh' under VTY configurations."
    })

    # Regla 3: Exec Timeout
    results.append({
        "id": "RULE-03",
        "name": "VTY Line Timeout",
        "status": "PASS" if exec_timeout_conf else "FAIL",
        "severity": "MEDIUM",
        "desc": "VTY terminal sessions do not automatically time out after inactivity.",
        "mitigation": "Configure 'exec-timeout 5 0' under 'line vty 0 4' to auto-disconnect inactive sessions."
    })

    # Regla 4: Syslog Log Host
    results.append({
        "id": "RULE-04",
        "name": "Centralized Logging (Syslog)",
        "status": "PASS" if syslog_conf else "FAIL",
        "severity": "MEDIUM",
        "desc": "No centralized logging server is defined. Logs are kept only locally and are easily alterable by intruders.",
        "mitigation": "Configure a remote logging server using 'logging host [SIEM_IP]' to maintain forensic integrity."
    })

    # Regla 5: Banner Leak
    results.append({
        "id": "RULE-05",
        "name": "Unsecure MOTD Banner",
        "status": "FAIL" if banner_info_leak else "PASS",
        "severity": "LOW",
        "desc": "MOTD banner reveals system information, welcomes users, or lacks strong legal warnings.",
        "mitigation": "Configure a secure banner warning of prosecution and avoiding system info: 'banner motd ^C UNAUTHORIZED ACCESS PROHIBITED ^C'."
    })

    # Regla 6: Enable Password vs Secret
    if enable_password_detected:
        res_enable = {"status": "FAIL", "severity": "CRITICAL", "desc": "Insecure 'enable password' (Type 7 encryption) detected.", "mitigation": "Remove 'enable password' and enforce strong hashing using 'enable secret [password]'."}
    elif not enable_password_detected and not enable_secret_detected:
        res_enable = {"status": "FAIL", "severity": "CRITICAL", "desc": "No privilege access restriction configured ('enable' password is missing).", "mitigation": "Instantly secure privileged mode by configuring 'enable secret [password]'."}
    else:
        res_enable = {"status": "PASS", "severity": "CRITICAL", "desc": "", "mitigation": ""}
    
    results.append({
        "id": "RULE-06",
        "name": "Privileged Mode Protection",
        **res_enable
    })

    # Regla 7: SNMP Communities
    if snmp_default_rw_detected:
        res_snmp = {"status": "FAIL", "severity": "CRITICAL", "desc": "SNMP community string uses default values (e.g., 'private') with Write Access (RW).", "mitigation": "Immediately change community strings to unique values, or migrate to SNMPv3."}
    elif snmp_default_ro_detected:
        res_snmp = {"status": "FAIL", "severity": "HIGH", "desc": "SNMP community string uses default values (e.g., 'public') in Read-Only (RO) mode.", "mitigation": "Use secure, non-guessable community names and restrict access via ACLs."}
    else:
        res_snmp = {"status": "PASS", "severity": "HIGH", "desc": "", "mitigation": ""}
        
    results.append({
        "id": "RULE-07",
        "name": "SNMP Community Security",
        **res_snmp
    })

    # Regla 8: VTY Login Authentication
    results.append({
        "id": "RULE-08",
        "name": "VTY Line Authentication",
        "status": "PASS" if vty_login_conf else "FAIL",
        "severity": "CRITICAL",
        "desc": "VTY lines allow connection without requesting password or username ('login' directive is missing).",
        "mitigation": "Configure local authentication using 'login local' under 'line vty' configurations."
    })

    # Regla 9: NTP Synchronization
    results.append({
        "id": "RULE-09",
        "name": "NTP Time Synchronization",
        "status": "PASS" if ntp_conf else "FAIL",
        "severity": "HIGH",
        "desc": "Device clock is not synchronized. Syslog telemetry lacks forensic timeline and correlation value.",
        "mitigation": "Configure 'ntp server [IP/FQDN]' to align device telemetry with the SOC SIEM."
    })

    # Regla 10: Web Management (HTTP/HTTPS)
    if http_server_active and not https_secure_active:
        res_web = {"status": "FAIL", "severity": "CRITICAL", "desc": "Unencrypted HTTP server is enabled for device management.", "mitigation": "Disable HTTP ('no ip http server') and enforce HTTPS using 'ip http secure-server'."}
    else:
        res_web = {"status": "PASS", "severity": "CRITICAL", "desc": "", "mitigation": ""}

    results.append({
        "id": "RULE-10",
        "name": "Web Console Management",
        **res_web
    })

    # Regla 11: Access-Class
    results.append({
        "id": "RULE-11",
        "name": "VTY Terminal IP Filtering",
        "status": "PASS" if vty_access_class_conf else "FAIL",
        "severity": "HIGH",
        "desc": "Unrestricted VTY Access: No source IP filtering ('access-class') is applied to terminal lines.",
        "mitigation": "Create a standard ACL and bind it using 'access-class [ACL] in' under VTY configurations."
    })

    
    # 5. RETORNAR RESULTADOS para generar el reporte
    return results

def generate_markdown_report(results, filename="Audit_Report.md"):
    
    #Generates an elegant and professional security audit report in Markdown format (.md)
    
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate quick metrics
    total_rules = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total_rules - passed
    percentage = int((passed / total_rules) * 100)
    
    markdown_content = f"""# 🛡️ Cisco IOS Hardening - Security Audit Report

This report was automatically generated by **NetHardener Scanner** after auditing the provided device configuration file.

## 📊 Executive Summary
* **Assessment Date:** `{current_date}`
* **Overall Compliance Status:** {"🟢 COMPLIANT" if percentage >= 80 else "🔴 NON-COMPLIANT"}
* **Compliance Score:** `{percentage}%` ({passed} of {total_rules} rules approved)

| Metric | Value |
|---|---|
| **Total Rules Evaluated** | {total_rules} |
| **Passed Rules (PASS)** | {passed} |
| **Vulnerabilities Found (FAIL)** | {failed} |

---

## 🔍 Detailed Assessment Findings

| ID | Security Rule | Severity | Status |
|---|---|---|---|
"""
    # Summary Findings Table
    for r in results:
        status_emoji = "🟢 PASS" if r["status"] == "PASS" else "🔴 FAIL"
        markdown_content += f"| `{r['id']}` | {r['name']} | **{r['severity']}** | {status_emoji} |\n"
        
    markdown_content += "\n---\n\n## 🛠️ Remediation & Action Plan\n\n"
    
    # List failed rules only for clean admin interaction
    vulnerabilities = [r for r in results if r["status"] == "FAIL"]
    
    if not vulnerabilities:
        markdown_content += "🎉 Excellent! The device is 100% compliant with all audited security hardening standards.\n"
    else:
        for v in vulnerabilities:
            markdown_content += f"""### ❌ [{v['id']}] {v['name']} (Severity: {v['severity']})
* **Risk Description:** {v['desc']}
* **Mitigation Command(s):** 
  ```text
  {v['mitigation']}
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"\n[💾] Markdown report successfully saved to: '{filename}'")


# Main Execution Block
if __name__ == "__main__":
    route = "router_vulnerable.conf"
    conf_lines = scanner(route)
    print(f"[+] File '{route}' loaded successfully. Total lines to evaluate: {len(conf_lines)}")

    # Run audit logic and retrieve findings
    audit_results = audit_conf(conf_lines)

    # --- PRINT RESULTS TO CONSOLE (Clean, Structured & Readable) ---
    print("\n" + "="*70)
    print(f"{'ID':<10} | {'SECURITY RULE':<30} | {'SEVERITY':<10} | {'STATUS':<10}")
    print("="*70)

    for r in audit_results:
        status_emoji = "🟢 PASS" if r["status"] == "PASS" else "🔴 FAIL"
        print(f"{r['id']:<10} | {r['name']:<30} | {r['severity']:<10} | {status_emoji:<10}")
    
    print("="*70)

    # Write findings to the interactive Markdown report
    generate_markdown_report(audit_results)
            
