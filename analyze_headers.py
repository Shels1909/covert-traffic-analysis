"""
Mac Knight

From a pcap file determines which src IP in the traffic is sending covert traffic

"""
from scapy.all import *
import get_dist 
from scipy import stats
from collections import Counter

"""
given a list of packets, returns a dictionary with all the different src IP addresses and the packets associated with them
"""
def seperate_IPs(packets):

    seperated_packets = {}
    for packet in packets:
        if packet[IP].src not in seperated_packets:
            seperated_packets[packet[IP].src] = [packet]
        else:
            seperated_packets[packet[IP].src].append(packet) 
    return seperated_packets

"""
creates distributions for each key value pair of IP addresses and the packets associated with it 
"""
def create_distributions(seperated_packets, base_time):

    # create dictinonary that will be populated with the distributions for each time interval
    distributions = {}

    for IP, packets in seperated_packets.iteritems():

        tcp_flags = get_dist.grab_header_info(packets)
        flag_dist = get_dist.create_dist(tcp_flags)
        distributions[IP] = flag_dist

    return distributions

""" 
This method takes in TCP header distributions from different SRC IP addresses, compares  
them to a distribution of regular TCP traffic. Then return the SRC IP most likely sending covert traffic. 
"""

def compare_to_regular_traffic(distributions, regular_dist):
    
    
    largest_entropy_value = 0.0
    largest_entropy_IP = ""
    for IP in distributions:
        entropy = stats.entropy(distributions[IP].values(), regular_dist.values()) 
        if entropy > largest_entropy_value:
            largest_entropy_value = entropy
            largest_entropy_IP = IP
        
    return largest_entropy_IP

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

    # will be populated with the IP addresses that are most likely sending covert traffic
    covert_traffic_count = []

    # initalize empty list to populate with packets in same time interval
    packet_interval = []

    # set time interval for creating distributions
    time_interval = 10

    # initialize the base time as the first packet 
    base_time = datetime.fromtimestamp(packets[0].time)

    for packet in packets:

        if packet.haslayer(TCP):

            # calculate the difference in packets current time and base time for time interval
            current_time = datetime.fromtimestamp(packet.time)
            delta_time = current_time - base_time  

            # are all the packets in the time_inerval accounted for?
            if delta_time.total_seconds() > time_interval:

                # if so seperate the packets into their corresponding src IPs
                seperated_packets = seperate_IPs(packet_interval)

                # and create a distribution for each IP flow
                distributions = create_distributions(seperated_packets,base_time)

                # compare the distributions to a regular traffic ditribution
                # and return the IP address that is likely sending covert traffic
                covert_traffic_IP = compare_to_regular_traffic(distributions, regular_dist)
                
                covert_traffic_count.append(covert_traffic_IP)

                # clear the packets from the old time interval
                del packet_interval[:]

                # calculate a new base time based on the current packet 
                base_time = datetime.fromtimestamp(packet.time)

                # add that base packet to list of packets in new time interval 
                packet_interval.append(packet)

            else:

                # if not add the packet to the rest of the packets in this time interval
                packet_interval.append(packet) 


    # now count which IP address occurs the most. This is the IP address that is most likely sending covert traffic
    IP_count = Counter(covert_traffic_count)
    print IP_count.most_common(1)

if __name__ == "__main__":
    main()
