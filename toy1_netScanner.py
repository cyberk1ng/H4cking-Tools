from scapy.all import Ether, ARP, srp, scapy

#Network scanner 
def scanner(ip):
    packet2 = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=3, verbose=0)[0]

    clients = []
    for snd, rcv in packet2:
        clients.append({'ip':rcv.psrc, 'mac':rcv.hwsrc})


    ("Available MAC Addresses with their IPs")
    print('IP' + "\t\t\t" + 'MAC')
    for client in clients:
        print(client['ip'], '\t\t', client['mac'])


print_scan = scanner("192.168.0.1/24")