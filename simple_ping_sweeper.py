from scapy.all import *
from scapy.layers.inet import IP, ICMP, RandShort


def icmp_ping(ip):
    pkt = IP(dst=ip)/ICMP(type="echo-request", id=RandShort(), seq=1)
    reply = sr1(pkt, timeout=4, verbose=0)
    try:
        if reply is None:
            return False, "[-] ICMP ping nope nothing!"


        if reply.haslayer(ICMP):

            if reply[ICMP].type == 0:
                return True, "[+] Yes host is alive"
            elif reply[ICMP].type == 3:
                return False, "[-] Unreachable host"
            elif reply[ICMP].type == 11:
                return False, "[-] TTL failure"
            elif reply[ICMP].type == 43:
                return True, "[+] extended echo reply"
            else:
                return False, "[-] Unknown ICMP type"

    except Exception as e:
        return False, f"Error, maybe check what u used for input {e}"


def simple_icmp_sleeper(network_prefix="192.168.1.", start=1, end=254):

    print(f"[+] Sweeping {network_prefix}{start}-{end}")


    live_hosts = []

    for i in range(start,end + 1):
        target = f"{network_prefix}{i}"

        alive,status = icmp_ping(target)

        if alive:
            print(f"[+] {target:15} -> {status}")
            live_hosts.append(target)
        else:
            print(f"[-] {target:15} -> {status}")
    if live_hosts:
        print(f"[+] Found {len(live_hosts)} hosts {', '.join(live_hosts)}")
    else:
        print("[-] No hosts found!")

if __name__ == '__main__':



    simple_icmp_sleeper()
