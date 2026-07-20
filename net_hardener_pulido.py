import sys  # System module to handle safe application exits.
import re   # Necessary module for regular expression pattern matching.

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
    vty_login_configured = False
    ntp_configured = False 
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
                vty_login_configured = True
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
            ntp_configured = True   
        if patron_http.search(line):             
            http_server_active = True
        if patron_https.search(line):           
            https_secure_active = True
   
   
    # ---- [ AUDIT REPORT RESULTS ] ----
    
    # Report Rule 1: SSH Ciphers
    if ssh_v1_detected:
        print("[🔴 CRITICAL] SSH Version 1 has been detected.")
        print("    👉 Mitigation: Configure 'ip ssh version 2' to enforce secure cryptographic standards.")
    else:
        print("[🟢 OK] SSH Cryptography: No usage of version 1 detected.")
    print("-" * 70)

    # Report Rule 2: Telnet
    if telnet_detected:
        print("[🔴 CRITICAL] Insecure protocol detected: Telnet access is allowed (unencrypted cleartext traffic).")
        print("    👉 Mitigation: Restrict remote management to encrypted channels using 'transport input ssh' exclusively.")
    else:
        print("[🟢 OK] Secure Access: Telnet is disabled for remote management.")
    print("-" * 70)

    # Report Rule 3: Exec Timeout
    if not exec_timeout_conf:  
        print("[🟡 HIGH] Absence of 'exec-timeout' configured under terminal lines.")
        print("    👉 Mitigation: Enforce automatic idle session termination using 'exec-timeout 5 0'.")
    else:
        print("[🟢 OK] Session Management: Inactivity session timeouts are correctly enforced.")
    print("-" * 70)

    # Report Rule 4: Syslog Telemetry
    if not syslog_conf:  
        print("[🟡 HIGH] Lack of centralized logging telemetry and log forwarding (Syslog).")
        print("    👉 Mitigation: Ensure infrastructure visibility for the SOC team using 'logging host [SIEM_IP]'.")
    else:
        print("[🟢 OK] Telemetry Visibility: Device is successfully forwarding logs to the remote Syslog server.")
    print("-" * 70)

    # Report Rule 5: Banner Info Leak
    if banner_info_leak:  
        print("[🟡 MEDIUM] Information disclosure leak detected in Banner MOTD.")
        print("    👉 Mitigation: Sanitize banners to display legal warnings only, hiding hardware architecture or OS data.")
    else:
        print("[🟢 OK] Information Disclosure: Banner configuration sanitized.")
    print("-" * 70)

    # Report Rule 6: Privilege Escalation Security (Enable Password vs Secret)
    if enable_password_detected:
        print("[🔴 CRITICAL] Insecure 'enable password' (obsolete Type 7 encryption) detected.")
        print("    👉 Mitigation: Remove it and enforce strong mathematical hashing using 'enable secret [password]'.")
    elif not enable_password_detected and not enable_secret_detected:
        print("[🔴 CRITICAL] Total Exposure: Privileged mode is completely unprotected ('enable' password is missing).")
        print("    👉 Mitigation: Instantly secure privileged execution mode by configuring 'enable secret [password]'.")
    else:
        print("[🟢 OK] Privilege Escalation: Privileged mode safely protected with secure modern hashing (enable secret).")
    print("-" * 70)

    # Report Rule 7: SNMP Community String Security
    if snmp_default_rw_detected:
        print("[🔴 CRITICAL] Active SNMP community string uses default values (e.g., 'private') with Write Access (RW).")
        print("    👉 Mitigation: Immediately change community strings to unique, complex values, or migrate to SNMPv3.")
    elif snmp_default_ro_detected:
        print("[🟡 HIGH] Active SNMP community string uses default guessable values (e.g., 'public') in Read-Only (RO) mode.")
        print("    👉 Mitigation: Define secure, non-guessable community names and restrict access using ACLs.")
    else:
        print("[🟢 OK] SNMP Management: No default community strings (public/private) detected.")
    print("-" * 70)

    # Report Rule 8: VTY Line Authentication
    if not vty_login_configured:
        print("[🔴 CRITICAL] VTY lines have NO authentication parameters configured ('login' or 'login local' is missing).")
        print("    👉 Mitigation: Instantly restrict terminal line access by adding 'login local' under 'line vty 0 4'.")
    else:
        print("[🟢 OK] VTY Authentication: Terminal lines strictly require authentication to grant system access.")
    print("-" * 70)

    # Report Rule 9: Time Synchronization (NTP)
    if not ntp_configured:
        print("[🟡 HIGH] Time synchronization via NTP is missing.")
        print("    👉 Mitigation: Configure 'ntp server [IP/FQDN]'. Without synchronized clocks, syslog telemetry loses forensic and log-correlation value.")
    else:
        print("[🟢 OK] Time Synchronization: Device internal clock is synchronized via NTP.")
    print("-" * 70)

    # Report Rule 10: Web Management Security (HTTP vs HTTPS)
    if http_server_active and not https_secure_active:
        print("[🔴 CRITICAL] Unencrypted HTTP Web Server is enabled for device administration.")
        print("    👉 Mitigation: Instantly disable the plain text HTTP server ('no ip http server') and enforce HTTPS via 'ip http secure-server'.")
    else:
        print("[🟢 OK] Web Management: Plain HTTP server is disabled or safely secured via HTTPS.")
    print("-" * 70)

    # Report Rule 11: VTY Terminal Access Filtering (access-class)
    if not vty_access_class_conf:
        print("[🟡 HIGH] Unrestricted VTY Access: No source IP filtering ('access-class') is applied to terminal lines.")
        print("    👉 Mitigation: Generate an ACL and bind it using 'access-class [ACL_NAME_OR_NUM] in' within the 'line vty' context.")
    else:
        print("[🟢 OK] VTY Access Filtering: Remote management is restricted to authorized IP addresses via ACL.")
    print("-" * 70)


# Main Execution Block
if __name__ == "__main__":
    route = "router_vulnerable.conf"
    conf_lines = scanner(route)
    print(f"[+] File '{route}' uploaded successfully. Total lines to evaluate: {len(conf_lines)}")
    audit_conf(conf_lines)