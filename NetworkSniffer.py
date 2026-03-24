
from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "OTHER"

        log = f"{protocol} | {ip.src} → {ip.dst}\n"

        # print on screen
        print(log)

        # save to file
        with open("log.txt", "a") as f:
            f.write(log)

sniff(prn=process_packet, store=False)
