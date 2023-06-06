"""
                ARP based covert channel reciever code

Description: Intercepts and interprets the last octate in random arp
             requests by the covert sender
             
language: python3.9

"""


import scapy.all as scapy # scapy functions
from scapy.layers.inet import IP, ICMP, Ether #importing scapy IP layers
import random  # random generator 
 
"""
proccess
1 - pass the string and array of seeds
2 - loop over every character and add to its ascii the random number from the corresponding seed
3 - append that number to another array
4 - repeat till the message finishes
5 - return the array (where each one will be the last octet)
"""


# RECIEVER SIDE
def sniffer():
    """
    Intercepts wild ARP requests in the local network. Proccesses the
    intercepted requests to retrieve the destination IP address of
    the ARP requests.
    
    @return: array of octets as string type
    """

    #pkts = scapy.sniff(count=3,filter="arp",prn=lambda x:x.summary())

    capture = scapy.sniff(count=3,filter="arp") # sniff 3 packets of ARP type
    cache = [] # declare empty list to store IP addresses extracted

    for index in range(0, len(capture)): # iterate over captured packets
        cache.append(capture[index].pdst) # append the destination IP of the ARP

    octets = list() # declare empty list to store last octet of IP addresses extracted

    for ip in cache: # iterate over the IP addresses
        octets.append(ip.split('.')[-1]) # append the last octet of each IP 
    print(cache) 
    return octets 

def decoder(seeds, octets):
    """
    decodes the secret msg fragmented into the last octet of the IP addresses.
    Uses a prepared seed to return the original value through subtracting the
    ascii value and turns it into a character. repeated until secret message
    is extracted from the octets.

    @parameter seed: the pre-agreed upon random generator seed with the sender
    @parameter octets: an array of unproccessed octets from intercepted ARP requests

    @return: the decoded secret message as string
    """

    decoded_msg = '' # declare empty decoded msg

    for i in range(0,len(octets)): # iterate over the octets

        random.seed(seeds[i]) # initialize the generator with the seed
     
        r = random.randint(0, 255)  # generate a pesudo random number with the seed
        ascii_value = r - int(octets[i]) # decode the last octet

        decoded_msg += chr(ascii_value)  # translate into character  and append

    print(decoded_msg)
    return decoded_msg




octets = sniffer() #ONE ARP REQUEST IS 10 PACKETS
seeds = [125,30,50]
result = decoder(seeds,octets)

