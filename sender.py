"""
                ARP based covert channel sender code

Description: Encodes a secret message into fragments into a set of the 4th octet of an IP address.
             Deploys the covert communication through ARP broadcasting at layer 2
             
language: python3.9

"""

import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether
import random

"""
1 - pass the string and array of seeds
2 - loop over every character and add to its ascii the random number from the corresponding seed
3 - append that number to another array
4 - repeat till the message finishes
5 - return the array (where each one will be the last octet)
"""

# SENDER SIDE
def encoder(seeds, message):
    """
    encodes a secret message into fragments through random IP addresses.
    Secures the ascii from translation through random number shifting
    of the ascii value. Avoids the use of reserved IP addresses

    @paramater seeds: int array of seeds as  for shifting each character
    @parameter message: string secret message to be encoded

    @return: int array of last octets of an IP hiding the secret message
    """
    
    new_octets = list() # declare empty list
    counter = 0
    
    for char in message: # iterate over each char in the message

        random.seed(seeds[counter]) # initialize seed
    
        r = random.randint(0, 255)  # generate psuedo random seeded number
        new_octet = r - ord(char)   # encode the character

        # avoid negative numbers or reserved addresses
        if new_octet < -1:
            new_octet = new_octet * -1

        elif new_octet <= 1:
            new_octet += 25

        elif new_octet >= 254:
            new_octet -= 25

        new_octets.append(new_octet) # append new octet to list
        counter += 1 # increment counter
    print(new_octets)
    return new_octets


def covert_channel(octets):
    """
    Deploys the covert channel by sending ARP requests with IP addresses
    where the last octet is composed of the encoded secret message fragment.
    Deploys the channel through sending ARP requests on the network, expected
    to be picked up and interpreted by the reciever.

    @paramater: array of ints representing the last octets of the IP adddress
    """

    for i in range(0,len(octets)): # iterate 0 to how many octets we have
        IP = "192.168.160." + str(octets[i]) # append the last octet to the network address

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=IP) # create ARP request with our IP
        #scapy.send(scapy.ARP(op=scapy.ARP.who_has, psrc="10.0.2.4", pdst=IP))

        #del pkt['IP'].len
        #del pkt['IP'].chksum
        #del pkt['ARP'].len
        #del pkt['ARP'].chksum
        #pkt = Ether(pkt.build())
        scapy.sendp(pkt, verbose=False) # disable logs to avoid errors and send
                                        # sendp used to send packets at 2nd protocol layer (MAC)

seeds = [125,30,50]
message = "Ali"
octets = encoder(seeds,message)
covert_channel(octets)
