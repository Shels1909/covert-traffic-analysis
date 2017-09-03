"""
Mac Knight

Creates a distribution of the different TCP flags in a pcap file 

"""
from scapy.all import *

def create_dist(tcp_flags):
    # create distribution containing total number of times a flag appears
    flag_distribution = {}
    for flag in tcp_flags:
        if flag not in flag_distribution:
            flag_distribution[flag] = 1.0
        else:
            flag_distribution[flag] += 1.0

    # divide by the total number of packets to get the relative frequency for each flag
    for key in flag_distribution:
        flag_distribution[key] /= len(tcp_flags)

    return flag_distribution

def grab_header_info(packets):
    # for every packet grab its TCP header info
    tcp_flags = []
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_flags.append(packet[TCP].flags)
    return tcp_flags
def main():

    # read the pcap file 
    packets = rdpcap("both.pcap")

    # grab header info from packets
    tcp_flags = grab_header_info(packets)

    # create a distribution of the different TCP flags 
    flag_dist = create_dist(tcp_flags)
    packets = rdpcap("both.pcap")

    # grab header info from packets
    tcp_flags = grab_header_info(packets)

    # create a distribution of the different TCP flags 
    flag_dist = create_dist(tcp_flags)

    print flag_dist

if __name__ == "__main__":
    main()
