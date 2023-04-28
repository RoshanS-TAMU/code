from scapy.all import *


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")
            # TODO
            send_pkt(10,2);
        elif option == '2':
            print("Listening to all traffic to 8.8.4.4 for 1 minute ...")
            # TODO
            pkt = sniff(iface='ens4', filter='dst 127.0.0.1',prn=print_pkt)
        elif option == '3':
            print("Listening continuously to only ping commands to 8.8.4.4 ...")
            # TODO
            ping = IP(dst="8.8.8.8")/ICMP()
            reply = sr1(ping)
            sniff(filter = "icmp",prn = print_pkt,timeout=10)
        elif option == '4':
            print("Listening continuously to only outgoing telnet commands ...")
            # TODO
            pkt = sniff(iface='ens4', filter='host 127.0.0.1 and tcp port 23',prn=print_pkt)
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(number, interval):
    eth = Ether(src = '00:11:22:33:44:55', dst = )
    ip = ip(src = '192.168.0.4'; dst ='8.8.4.4'; proto = 'tcp')
    tcp = TCP(sport=number;dport=80;chksum=0)
    payload = b'RISC-V Education: https://riscvedu.org/'
    packet = eth/ip/tcp/payload
    print(packet.show())
    # filter = host
    # sniff(filter = 'tcp port 23' and src host = 8.8.4.4 and ttl = 'interval')

    """
    Send a custom packet with the following fields

    #### Ethernet layer

    - Source MAC address: 00:11:22:33:44:55
    - Destination MAC address: 55:44:33:22:11:00

    #### IP layer
    - Source address: 192.168.10.4
    - Destination address: 8.8.4.4
    - Protocol: TCP
    - TTL: 26

    #### TCP layer
    - Source port: 23
    - Destination port: 80
    
    #### Raw payload
    - Payload: "RISC-V Education: https://riscvedu.org/"
    """

    
    sendp(packet)


    # TODO
    pass


def print_pkt(packet):
    """ 
    Print Packet fields
    
    - Source IP
    - Destination IP
    - Protocol number
    - TTL
    - Length in bytes
    - Raw payload (if any)
    """
    print("Source IP:", pkt[IP].src)
    print("Destination IP:", pkt[IP].dst)
    print("Protocol:", pkt[IP].proto)
    print("Protocol:", pkt[IP].ttl)
    print("Protocol:", pkt[IP].length)
    print("Protocol:", pkt[IP].raw(payload))     

    print("\n")
    

    # TODO

    pass


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic to 8.8.4.4 for 1 minute')
    print('3. Listen continuously to only ping commands to 8.8.4.4')
    print('4. Listen continuously to only outgoing telnet commands')
    print('5. Quit')
    print('***********************************************\n')


main()
