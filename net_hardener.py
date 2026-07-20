

import sys

 #We import the sys (System) module. It's a library that comes with Python by default. We use it in this script specifically to be able to safely close the program (with sys.exit()) if a serious error occurs, such as the configuration file not existing.

import re

#it's necesary for do queries, and doing researches with more range

def scanner(path_file):

#funtion with an input
   
    try:   #it's a block that try to execute the first line, if something wrong come up just move foward with the next guideline
        with open(path_file, 'r') as file:
            # with open the file in these case read it, as soon the file is completely read, the command will close ensuring the integrity and preventing security breaches  
            raw_lines = [line.strip() for line in file.readlines()]

            # We ignore blank lines and comment lines so they can never be mistaken.
            lines = [line for line in raw_lines if line and not line.startswith(('!', '#'))]
            return lines
            #this command convert the whole file in a list, hopping line by line, clearing and deleting blank spaces, in that way python could read it. 
    except FileNotFoundError:
        print(f"[❌ ERROR] No se pudo encontrar el archivo: {path_file}")
        sys.exit(1)
        # in case the file is had not read succesfully, print a message "[❌ ERROR] No se pudo encontrar el archivo", so with close sys.exit(1)
     

def audit_conf(lines):
    """Analiza las líneas de configuración buscando fallos de seguridad."""
    print("\n[+] initiating audit compliance...")
    print("-" * 70)

    # Creamos variables booleanas (True/False) para rastrear lo que encontramos
    ssh_v1_detected = False

    telnet_detected = False

    exec_timeout_configured = False

    syslog_configured = False

    banner_info_leak = False

    enable_password_detected = False  # <-- NUEVO: Detecta si usa la clave insegura Tipo 7

    enable_secret_detected = False    # <-- NUEVO: Detecta si usa el hash seguro

    snmp_default_ro_detected = False  # <-- NUEVO: Detecta community string 'public' o por defecto en lectura (RO)

    snmp_default_rw_detected = False

    inside_vty_block = False          # Nos dice si el bucle está leyendo la sección de VTY

    vty_login_configured = False      # Cambiará a True si encontramos 'login' o 'login local'

    ntp_configured = False  #se usa para sincronizar todos los dispositivos de nuestra red con la misma hr

    http_server_active = False         # Detecta si el servidor web inseguro (HTTP) está encendido
    
    http_secure_active = False

    vty_access_class_configured = False #Restringir el acceso administrativo para que solo equipos autorizados puedan conectarse, access class .

# Esta expresión busca patrones flexibles. Explicación:

    #ssh: Matches the literal string "ssh".
    #\s+: Matches one or more spaces or tabs.
    #version: Matches the literal string "version".
    #\s+: Matches one or more spaces.
    #1: Matches the literal number 1.
    #(?:\.\d+)?: An optional group that matches a dot followed by digits (e.g., .0, .51). This allows the pattern to match both "version 1" and "version 1.5".
    #\b: A word boundary anchor. It prevents false positives by ensuring the match doesn't trigger on numbers like "version 12".
    patron_ssh = re.compile(r"ssh\s+version\s+1(?:\.\d+)?\b", re.IGNORECASE)
    
    patron_timeout = re.compile(r"exec-timeout\s+\d+", re.IGNORECASE)
    # in that case we use the same a regex patron for our timeout, 
    # exec-timeout: seek for this exact text
    # \s+: Busca uno o más espacios en blanco que separan el comando de los números. 
    # \d+: Busca uno o más dígitos (los minutos configurados, por ejemplo: exec-timeout 5 0

    patron_syslog = re.compile(r"logging\s+host\s+(?:ipv[46]\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})", re.IGNORECASE)
    # logging\s+host\s+: Matches the start of the Cisco command, allowing for any number of spaces.
    #(?:ipv[46]\s+)?: Optionally matches the prefix ipv4  or ipv6  before the IP. If it is not there, it bypasses it.
    #( IPv4 | IPv6 ): The capture group that extracts the actual IP address. It uses an OR (|) operator to match either:
    #IPv4 Pattern: Groups of 1 to 3 digits separated by dots (X.X.X.X).
    #IPv6 Pattern: Hexadecimal blocks (0-9, a-f) separated by colons, which supports abbreviations using ::.
    #re.IGNORECASE: Ensures the search is case-insensitive (matching both uppercase and lowercase letters).

    patron_banner_leak = re.compile(r"banner\s+motd.*(cisco|ios|version|7200|\d{4})", re.IGNORECASE)
    #banner\s+motd: Searches for the beginning of the banner command.
    #.*: Allows any text or space in between.
    #(cisco|ios|version|7200|\d{4}): Uses the logical OR operator (|). If the line contains the word cisco, ios, version, the model 7200, or any 4-digit number (\d{4}) that resembles a model or year, it will trigger the pattern.

    patron_telnet = re.compile(r"transport\s+input\s+(?:.*?\s+)?(telnet|all)\b", re.IGNORECASE)
    #transport\s+input\s+: Matches the literal command transport input followed by one or more spaces.
    #(?:.*?\s+)?: An optional, non-capturing group that matches and ignores any other protocols listed first (e.g., skips ssh  in transport input ssh telnet).
    #(telnet|all): The capture group that flags the vulnerability. It looks for either the word telnet or all (which includes Telnet).
    #\b: A word boundary ensuring the match stops exactly at the end of the word.
    #re.IGNORECASE: Makes the search case-insensitive (TELNET, Telnet, etc.).

    patron_enable_password = re.compile(r"enable\s+password\b", re.IGNORECASE)
    #enable secret es preferible a enable password, porque usa mecanismos de protección mucho más seguros.como los type 9 (scrypt) 

    patron_enable_secret = re.compile(r"enable\s+secret\b", re.IGNORECASE)
    #type 7 es una forma obsoleta, usa ofuscacion reversible

    patron_snmp_ro = re.compile(r"snmp-server\s+community\s+(public|admin|manager)\s+ro\b", re.IGNORECASE)
    # Rule 7: SNMP Default Community Strings detection
    # Captures: snmp-server community [public|private|...] [RO|RW]

    patron_snmp_rw = re.compile(r"snmp-server\s+community\s+(private|admin|manager|secret)\s+rw\b", re.IGNORECASE)

    #^line\s+vty\s+\d+: Detecta el inicio de la sección VTY (ej: line vty 0 4). El ^ asegura que empiece al inicio de la línea.
    #^\s*login(\s+local)?\b: Busca la palabra login sola o seguida de local, ignorando espacios al inicio (ya que dentro del bloque suele estar indentada).
    #^(!|line\s+|...): Detecta el final del bloque VTY si encuentra un carácter de exclamación ! o si empieza otra sección de configuración.

    patron_vty_start = re.compile(r"^line\s+vty\s+\d+", re.IGNORECASE)
    
    patron_vty_login = re.compile(r"^\s*login(\s+local)?\b", re.IGNORECASE)

    patron_block_end = re.compile(r"^(!|line\s+|interface\s+|router\s+)", re.IGNORECASE)

    # Rule 9: NTP Synchronization (Time Telemetry)
    patron_ntp = re.compile(r"ntp\s+server\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+)", re.IGNORECASE)
    #ntp\s+server: Busca las palabras clave obligatorias para apuntar a un servidor de hora.
    #\s+: Espacio antes de la dirección o dominio.
    #(\d{1,3}\.\d{1,3}\...|[a-zA-Z0-9.-]+): Permite capturar tanto una dirección IPv4 (números y puntos) como un nombre de dominio/FQDN (como pool.ntp.org), que es muy común en configuraciones reales.
    #la ultima parte permite identificar ipv6

    # Rule 10: HTTP (unencrypted) vs HTTPS (secure) Web Management
    patron_http = re.compile(r"^ip\s+http\s+server\b", re.IGNORECASE)

    patron_https = re.compile(r"^ip\s+http\s+secure-server\b", re.IGNORECASE)


    #^\s*access-class\s+: Busca la palabra access-class ignorando los espacios de la indentación inicial.
    #\S+: Busca el identificador de la lista de acceso (puede ser un número como 10 o un nombre como ADMIN-IPs).
    #\s+in\b: Busca obligatoriamente la palabra clave in (que filtra el tráfico entrante de administración).
    patron_access_class = re.compile(r"^\s*access-class\s+\S+\s+in\b", re.IGNORECASE)



    # Recorremos el archivo línea por línea
    for line in lines:

        # --- Lógica de seguimiento de Bloque VTY ---
        if patron_vty_start.search(line):
            inside_vty_block = True
            
        if inside_vty_block:
            if patron_vty_login.search(line):
                vty_login_configured = True
            
            if patron_access_class.search(line):     # <-- NUEVO: Evaluamos si existe la ACL de entrada
                vty_access_class_configured = True

            # Si encontramos un delimitador que indique que salimos del bloque VTY
            elif patron_block_end.search(line) and not patron_vty_start.search(line):
                inside_vty_block = False


        if patron_ssh.search(line):
            ssh_v1_detected = True

        if patron_telnet.search(line):
            telnet_detected = True

        if patron_timeout.search(line):
            exec_timeout_configured = True

        if patron_syslog.search(line):     # <-- Añade este bloque
            syslog_configured = True
        
        if patron_banner_leak.search(line):  # <-- Añade este bloque
            banner_info_leak = True

        if patron_enable_password.search(line):  # <-- NUEVO: Levanta bandera de peligro
            enable_password_detected = True

        if patron_enable_secret.search(line):    # <-- NUEVO: Levanta bandera de seguridad
            enable_secret_detected = True

        if patron_snmp_ro.search(line):         # <-- NUEVO
            snmp_default_ro_detected = True

        if patron_snmp_rw.search(line):         # <-- NUEVO
            snmp_default_rw_detected = True
 
        if patron_ntp.search(line):             # <-- NUEVO, Server de tiempo
            ntp_configured = True

        if patron_http.search(line):             # <-- NUEVO
            http_server_active = True

        if patron_https.search(line):            # <-- NUEVO
            http_secure_active = True




            
    # ---- [ AUDIT RESULTS ] ----
    
# Reporte Rule 1
    if ssh_v1_detected:
        print("[🔴 CRITIC] SSH Versión 1 detected.")
        print("    👉 Mitigation: Configurate 'ip ssh version 2' safe cryptography use.")
    else:
        print("[🟢 OK] Criptography SSH: versión 1 use not.")

    print("-" * 70)

# Report Rule 2: Telnet
    if telnet_detected:
        print("[🔴 CRITIC] Insecure protocol detected: Telnet access is allowed (unencrypted).")
        print("    👉 Mitigation: Restrict remote management using 'transport input ssh' only.")
    else:
        print("[🟢 OK] Secure Access: Telnet is not enabled for remote management.")
        print("-" * 70)

# Report Rule 3
    if not exec_timeout_configured:  # Si la bandera sigue siendo False...
        print("[🟡 HIGH] Absence of 'exec-timeout' under line configuration.")
        print("    👉 Mitigation: Enforce automatic session termination with 'exec-timeout 5 0'.")
    else:
        print("[🟢 OK] Session Management: Inactivity timeouts are correctly enforced.")

#Report Rule 4
    if not syslog_configured:  # Si la bandera sigue en False, el SOC está ciego
        print("[🟡 HIGH] Lack of centralized logging telemetry (Syslog).")
        print("    👉 Mitigation: Ensure visibility for the SOC team using 'logging host [SIEM_IP]'.")
    else:
        print("[🟢 OK] Telemetry Visibility: Device successfully forwarding logs to Syslog server.")


# Report Rule 5
    if banner_info_leak:  # Si es True, hay fuga de información
        print("[🟡 MEDIUM] Information disclosure leak found in Banner MOTD.")
        print("    👉 Mitigation: Sanitize banners to display only legal warnings, hiding hardware/OS details.")
    else:
        print("[🟢 OK] Information Disclosure: Banner configuration sanitized.")

    # this line, provide a safe way to run the code just if the usser execute it, but not if another program will do it

# Report Rule 6: Privilege Escalation Security (Enable Password vs Secret)
    if enable_password_detected:
        print("[🔴 CRITICAL] Insecure 'enable password' (Type 7 encryption) detected.")
        print("    👉 Mitigation: Remove it and enforce strong hashing using 'enable secret [password]'.")
    elif not enable_password_detected and not enable_secret_detected:
        print("[🔴 CRITICAL] Total exposure: No privilege access restriction configured ('enable' password is missing).")
        print("    👉 Mitigation: Instantly secure privileged mode by configuring 'enable secret [password]'.")
    else:
        print("[🟢 OK] Privilege Escalation: Privileged mode safely protected with secure hashing (enable secret).")
    print("-" * 70)

# Report Rule 7: SNMP Community String Security
    if snmp_default_rw_detected:
        print("[🔴 CRITICAL] Defined SNMP community string uses default values (e.g., 'private') with Write Access (RW).")
        print("    👉 Mitigation: Immediately change community strings to unique, complex values, or migrate to SNMPv3.")
    elif snmp_default_ro_detected:
        print("[🟡 HIGH] SNMP community string uses default values (e.g., 'public') in Read-Only (RO) mode.")
        print("    👉 Mitigation: Use secure, non-guessable community names and restrict access via ACLs.")
    else:
        print("[🟢 OK] SNMP Management: No default community strings (public/private) detected.")
    print("-" * 70)


# Report Rule 8: VTY Line Authentication
    if not vty_login_configured:
        print("[🔴 CRITICAL] VTY lines have NO authentication configured ('login' or 'login local' is missing).")
        print("    👉 Mitigation: Instantly restrict access by adding 'login local' under 'line vty 0 4'.")
    else:
        print("[🟢 OK] VTY Authentication: Terminal lines require authentication to grant access.")
    print("-" * 70)


# Report Rule 9: Time Synchronization (NTP)
    if not ntp_configured:
        print("[🟡 HIGH] NTP synchronization is missing.")
        print("    👉 Mitigation: Configure 'ntp server [IP/FQDN]'. Without synchronized clocks, syslog telemetry loses forensic and correlation value.")
    else:
        print("[🟢 OK] Time Synchronization: Device clock is synchronized via NTP.")
    print("-" * 70)

# Report Rule 10: Web Management Security (HTTP vs HTTPS)
    if http_server_active and not http_secure_active:
        print("[🔴 CRITICAL] Unencrypted HTTP Web Server is enabled for device management.")
        print("    👉 Mitigation: Instantly disable HTTP ('no ip http server') and enforce HTTPS using 'ip http secure-server'.")
    else:
        print("[🟢 OK] Web Management: HTTP server is disabled or safely secured via HTTPS.")
    print("-" * 70)

# Report Rule 11: VTY Terminal Access Filtering (access-class)
    if not vty_access_class_configured:
        print("[🟡 HIGH] Unrestricted VTY Access: No source IP filtering ('access-class') is applied.")
        print("    👉 Mitigation: Create an ACL and bind it using 'access-class [ACL_NAME_OR_NUM] in' under 'line vty' configuration.")
    else:
        print("[🟢 OK] VTY Access Filtering: Remote management is restricted to authorized IP addresses via ACL.")
    print("-" * 70)


#main
if __name__ == "__main__":
    route = "router_vulnerable.conf"
    conf_lines = scanner(route)
    print(f"[+] file '{route}' upload succesfully. Total lines: {len(conf_lines)}")
    audit_conf(conf_lines)