from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys


def synner(target, port):
    pkt = IP(dst=target) / TCP(dport=int(port), flags='S', sport=RandShort())
    resp = sr1(pkt, timeout=3, verbose=0)

    try:
        if resp is None:
            print("[+] No response")

        elif resp[TCP].flags == 0x12:
             send(IP(dst=target)/TCP(dport=int(port), flags='R', sport=resp[TCP].dport), verbose=0)
             print(f"[+] Port {port}is open!!!")

        elif resp[TCP].flags == 0x14: 
            print(f'[+] Port {port}is closed!!!')


    except Exception as e:
        print(f'[-] Error occurred {e}')



if __name__ == "__main__":
    target = sys.argv[1]
    port = sys.argv[2]
    synner(target, port)
