from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

attack_signatures = {
    "Ping of Death": {"protocol": "ICMP", "packet_size": 65535},
    "SYN Flood": {"protocol": "TCP", "flags": "S"},
    "UDP Flood": {"protocol": "UDP", "packet_count_threshold": 100},
    "HTTP Flood": {"protocol": "TCP", "dport": 80, "packet_count_threshold": 200},
    "Slowloris": {"protocol": "TCP", "dport": 80, "flags": "S", "packet_count_threshold": 50},
    "ARP Spoofing": {"protocol": "ARP", "op": 2},
    "DNS Spoofing": {"protocol": "UDP", "dport": 53},
    "FTP Brute Force": {"protocol": "TCP", "dport": 21, "login_attempt_threshold": 10},
    "SSH Brute Force": {"protocol": "TCP", "dport": 22, "login_attempt_threshold": 10},
}

packet_counts = {}
arp_table = {}

def log_intrusion(alert, packet):
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"[ALERT] {alert}: {packet.summary()}\n")
    print(f"[ALERT] {alert} detected!")

def detect_attack(packet):
    global packet_counts, arp_table

    if IP in packet:
        src_ip = packet[IP].src

        # 1️⃣ ICMP Ping of Death
        if ICMP in packet and packet[ICMP].type == 8 and len(bytes(packet)) >= attack_signatures["Ping of Death"]["packet_size"]:
            log_intrusion("Ping of Death", packet)

        # 2️⃣ SYN Flood Attack
        if TCP in packet and packet[TCP].flags == attack_signatures["SYN Flood"]["flags"]:
            log_intrusion("SYN Flood", packet)

        # 3️⃣ UDP Flood Attack
        if UDP in packet:
            packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
            if packet_counts[src_ip] > attack_signatures["UDP Flood"]["packet_count_threshold"]:
                log_intrusion("UDP Flood", packet)
                packet_counts[src_ip] = 0  

        # 4️⃣ HTTP Flood Attack
        if TCP in packet and packet[TCP].dport == 80:
            packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
            if packet_counts[src_ip] > attack_signatures["HTTP Flood"]["packet_count_threshold"]:
                log_intrusion("HTTP Flood", packet)
                packet_counts[src_ip] = 0

        # 5️⃣ Slowloris Attack
        if TCP in packet and packet[TCP].dport == 80 and packet[TCP].flags == attack_signatures["Slowloris"]["flags"]:
            packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
            if packet_counts[src_ip] > attack_signatures["Slowloris"]["packet_count_threshold"]:
                log_intrusion("Slowloris", packet)
                packet_counts[src_ip] = 0

        # 6️⃣ DNS Spoofing Detection (Fake DNS response)
        if UDP in packet and packet[UDP].dport == 53 and src_ip == "192.168.1.1":  
            log_intrusion("DNS Spoofing", packet)

        # 7️⃣ Brute Force Attacks (FTP & SSH)
        for attack in ["FTP Brute Force", "SSH Brute Force"]:
            if TCP in packet and packet[TCP].dport == attack_signatures[attack]["dport"]:
                packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
                if packet_counts[src_ip] > attack_signatures[attack]["login_attempt_threshold"]:
                    log_intrusion(attack, packet)
                    packet_counts[src_ip] = 0

    # 8️⃣ ARP Spoofing Detection (Check for MAC address change)
    if ARP in packet and packet[ARP].op == attack_signatures["ARP Spoofing"]["op"]:
        real_mac = arp_table.get(packet[ARP].psrc)
        if real_mac and real_mac != packet[ARP].hwsrc:
            log_intrusion("ARP Spoofing", packet)
        arp_table[packet[ARP].psrc] = packet[ARP].hwsrc  

print("Starting signature-based IDS...")
sniff(prn=detect_attack, store=False)
