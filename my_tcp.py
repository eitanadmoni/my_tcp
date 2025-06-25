from scapy.all import conf


INTERFACE = "Hyper-V Virtual Ethernet Adapter"
MY_MAC = '00155d7d9e4d'
BROADCAST  = 'ffffffffffff'
MAC_LENGTH = 6
DST_MAC_INDEX  = 0
RAW_PACKET_DATA_INDEX = 1


def check_ether(packet):
    if packet == None:
        return False
    dst_mac = packet[DST_MAC_INDEX: DST_MAC_INDEX + MAC_LENGTH].hex()
    if dst_mac == MY_MAC or dst_mac.hex() == BROADCAST:
        return True
    return False


def get_ether_packet():
    while True:
        sock = conf.L2socket(iface=INTERFACE, promisc=True) # Create the socket
        recv = sock.recv_raw()
        packet = recv[RAW_PACKET_DATA_INDEX]
        if check_ether(packet):
            return packet


def main():
    print("sniffing ethernet packets:")
    ethr_packet = get_ether_packet()
    print(f"get ethr packet: {ethr_packet}")


if __name__ == "__main__":
    main()
