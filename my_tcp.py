from scapy.all import conf
import struct


BROADCAST  = bytes.fromhex('ffffffffffff')
RAW_PACKET_DATA_INDEX = 1
ETHR_FRAME_SIZE = 16


class EthernetFrame():
    def __init__(self, packet):
        self.dst_mac, self.src_mac, self.type = struct.unpack('=6s6s4s', packet)


def is_ethr_multicast(addr):
    """
    Function to check if given mac address is a multicast address
    addr: A mac address to check if it multicast
    """
    first_octet, _ = struct.unpack('=b5s', addr)
    if first_octet % 2 == 1:
        return True
    return False


def ether_packet_is_mine(packet, mac_addr):
    """
    Function to check if given packet is intended for specific mac address
    packet: A bytes object that represent packet
    mac_addr: A mac address to check if the packet is for it
    """
    ethr_frame = EthernetFrame(packet[:ETHR_FRAME_SIZE])
    if ethr_frame.dst_mac == mac_addr or is_ethr_multicast(ethr_frame.dst_mac):  
        return True
    return False


def get_ether_packet():
    """
    Function that sniff and catch packet that intended to the user mac.
    """
    interface = input("Enter interface to listen at: ")
    mac_addr = bytes.fromhex(input("Enter your mac address: "))
    sock = conf.L2socket(iface=interface, promisc=True) # Create the socket
    while True:
        recv = sock.recv_raw()
        packet = recv[RAW_PACKET_DATA_INDEX]
        if packet == None:
            continue
        if ether_packet_is_mine(packet, mac_addr):
            return packet


def main():
    print("sniffing ethernet packets:")
    ethr_packet = get_ether_packet()
    print(f"get ethr packet: {ethr_packet}")


if __name__ == "__main__":
    main()