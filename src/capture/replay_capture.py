from scapy.all import rdpcap
import time
def replay_pcap(pcap_path, packet_queue, speed=1.0):
  packets = rdpcap(pcap_path)
  for pkt in packets:
    packet_queue.put(pkt)
    time.sleep(0.001 / max(speed, 0.1))
