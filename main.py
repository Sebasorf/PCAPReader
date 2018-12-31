import logging
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import udp, tcp
import binascii

#Parallel processing
from joblib import Parallel, delayed

#Custom modules
from packet_custom_structure import CustomPacket


packet_dump = None


################################################
# User Functions
################################################

def get_available_methods(object = None):
    print('Printing available methods for troubleshooting: ')
    print(dir(object))


def read_packet_dump():
    print('[DEBUG] Starting read_packet() method')
    testcap = open('example.pcap', 'rb')
    packet_dump = savefile.load_savefile(testcap, verbose=True)
    print('[INFO] Packet quantity: ' + str(len(packet_dump.packets)))
    print('[DEBUG] Returning packet dump')
    return packet_dump


def get_ethernet_frame(packet):
    #print('[DEBUG] Starting get_ethernet_frame() method')
    eth_frame = ethernet.Ethernet(packet.raw())
    #print('[DEBUG] Returning ethernet frame')
    return eth_frame


def get_IP_packet(eth_frame):
    #print('[DEBUG] Starting get_ethernet_frame() method')
    ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
    #print('[DEBUG] Returning ethernet frame')
    return ip_packet


def create_data_structure(number):
    #print('[DEBUG] Starting create_data_structure() method')
    packet = packet_dump.packets[number]

    eth_frame = get_ethernet_frame(packet)
    ip_packet = get_IP_packet(eth_frame)

    frame_timestamp = packet.timestamp
    frame_capture_len = packet.capture_len
    eth_mac_source = eth_frame.src
    eth_mac_destination = eth_frame.dst
    eth_payload = eth_frame.payload
    eth_type = 'IP' if eth_frame.type == 2048 else eth_frame.type
    ip_source = ip_packet.src
    ip_destination = ip_packet.dst
    ip_flags = ip_packet.flags
    ip_packet_identification = ip_packet.id
    ip_header_length = ip_packet.hl
    ip_packet_length = ip_packet.len
    ip_frag_offset = ip_packet.off
    ip_opt_parsed = ip_packet.opt_parsed
    ip_protocol = ip_packet.p
    ip_version = ip_packet.v
    ip_type_of_service = ip_packet.tos
    ip_ttl = ip_packet.ttl
    ip_checksum = ip_packet.sum
    ip_padding_bytes = ip_packet.pad

    custom_packet = CustomPacket(frame_timestamp, frame_capture_len, eth_mac_source,
                                eth_mac_destination, eth_payload, eth_type, ip_source,
                                ip_destination, ip_flags, ip_packet_identification,
                                ip_header_length, ip_packet_length,
                                ip_frag_offset, ip_opt_parsed, ip_protocol,
                                ip_version, ip_type_of_service, ip_ttl, ip_checksum,
                                ip_padding_bytes)
    #print('[DEBUG] Returning packet dictionary')
    return custom_packet




################################################
# Application Main
################################################

packet_dump = read_packet_dump()                        # Get all packets
arguments = range(len(packet_dump.packets))             # Get packets number to iterate

#results = Parallel(n_jobs=10, verbose=1, backend="threading")(map(delayed(create_data_structure), arguments))
results = Parallel(n_jobs=10, verbose=1, backend="multiprocessing")(map(delayed(create_data_structure), arguments))  #Iterate and create CustomPacket structures for each packet

print(results[0].returnDataDict())      #Print first packet as example

print('[INFO] Finish parsing packets')
