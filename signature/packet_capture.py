from scapy.all import sniff, IP
from datetime import datetime

def capture_packet(packet):
    if IP in packet:
        log_message = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Packet: {packet.summary()}\n"
        
        with open("intrusion_log.txt", "a") as log_file:
            log_file.write(log_message)
        
        print(f"Captured Packet: {packet.summary()}")

print("Starting packet capture...")
sniff(prn=capture_packet, store=False)