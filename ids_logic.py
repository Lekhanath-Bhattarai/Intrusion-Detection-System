from scapy.all import *
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    handlers=[
        logging.FileHandler("ids_log.txt"),
        logging.StreamHandler()
    ]
)


suspicious_ips = ['{Enter sources IP address']

def check_packet(packet, update_gui_callback):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if ip_src in suspicious_ips or ip_dst in suspicious_ips:
            log_message = f"Suspicious packet detected: {ip_src} -> {ip_dst}\n{packet.summary()}"
            logging.info(log_message)
            update_gui_callback(log_message)

def start_sniffing(update_gui_callback, stop_event):
    update_gui_callback("Sniffing started...")
    while not stop_event.is_set():
        sniff(prn=lambda pkt: check_packet(pkt, update_gui_callback), store=0, timeout=1)
    update_gui_callback("Sniffing stopped...")
