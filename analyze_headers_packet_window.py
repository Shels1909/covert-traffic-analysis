"""
Mac Knight

From a pcap file determines which src IP in the traffic is sending covert traffic

"""
from scapy.all import *
import get_dist 
from scipy import stats
from collections import Counter

"""
creates distributions for each key value pair of IP addresses and the packets associated with it 
"""
def create_distribution(packets):


    tcp_flags = get_dist.grab_header_info(packets)
    distribution  = get_dist.create_dist(tcp_flags)

    return distribution

""" 
This method takes in TCP header distributions from different SRC IP addresses, compares  
them to a distribution of regular TCP traffic. Then return the SRC IP most likely sending covert traffic. 
"""

def compare_to_regular_traffic(distribution, regular_dist):
    
    
    entropy = stats.entropy(distribution.values(), regular_dist.values()) 
        
    return entropy

""" 
creates a distribution that models regular TCP fraffic from the already captured regular traffic pcap file
"""

def get_regular_dist():
    # read the pcap file
    packets = rdpcap("regular_traffic.pcap")
       
    # grab header info from packets
    tcp_flags = get_dist.grab_header_info(packets)
             
    # create a distribution of the different TCP flags
    flag_dist = get_dist.create_dist(tcp_flags)

    return flag_dist    
                    

def main():
    #read the pcap file
    packets = rdpcap("both.pcap") 

    # get a regular distribution of TCP traffic
    regular_dist = get_regular_dist()

    # initalize empty list to populate with packets in same time interval
    packet_interval = []

    # set time interval for creating distributions
    packet_window  = 10

    window_counter = 0
    x = 0
    for packet in packets:

        if packet.haslayer(TCP):
                
            if window_counter >= packet_window:

                # create a distribution for the packet window
                distribution = create_distribution(packet_interval)

                # compare the distributions to a regular traffic ditribution
                # and return the IP address that is likely sending covert traffic
                entropy = compare_to_regular_traffic(distribution, regular_dist)
               
                print entropy
                if entropy > 1:
                    print "covert traffic"
                    break

                # clear the packets from the old time interval
                del packet_interval[0]
                x = x +1
            else:

                #increment window counter. no packet analysis until window has 10 packets
                window_counter = window_counter + 1

            # add packet to packet interval for analysis
            packet_interval.append(packet) 

    print x
if __name__ == "__main__":
    main()
