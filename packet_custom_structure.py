import datetime

class CustomPacket():
    def __init__(self, frame_timestamp = None, frame_capture_len=None, eth_mac_source=None,
                eth_mac_destination=None, eth_payload=None, eth_type=None, ip_source=None,
                ip_destination=None, ip_flags=None, ip_packet_identification=None,
                ip_header_length=None, ip_packet_length=None, ip_frag_offset=None,
                ip_opt_parsed=None, ip_protocol=None, ip_version=None,
                ip_type_of_service=None, ip_ttl=None, ip_checksum=None,
                ip_padding_bytes=None):
        self.frame_timestamp = frame_timestamp
        self.frame_capture_len = frame_capture_len
        self.eth_mac_source = eth_mac_source
        self.eth_mac_destination = eth_mac_destination
        self.eth_payload = eth_payload
        self.eth_type = eth_type
        self.ip_source = ip_source
        self.ip_destination = ip_destination
        self.ip_flags = ip_flags
        self.ip_packet_identification = ip_packet_identification
        self.ip_header_length = ip_header_length
        self.ip_packet_length = ip_packet_length
        self.ip_frag_offset = ip_frag_offset
        self.ip_opt_parsed = ip_opt_parsed
        self.ip_protocol = ip_protocol
        self.ip_version = ip_version
        self.ip_type_of_service = ip_type_of_service
        self.ip_ttl = ip_ttl
        self.ip_checksum = ip_checksum
        self.ip_padding_bytes = ip_padding_bytes

    def returnDataDict(self):
        data = {}
        data['frame_timestamp'] = self.frame_timestamp
        data['frame_capture_len'] = self.frame_capture_len
        data['eth_mac_source'] = self.eth_mac_source
        data['eth_mac_destination'] = self.eth_mac_destination
        data['eth_payload'] = self.eth_payload
        data['eth_type'] = self.eth_type
        data['ip_source'] = self.ip_source
        data['ip_destination'] = self.ip_destination
        data['ip_flags'] = self.ip_flags
        data['ip_packet_identification'] = self.ip_packet_identification
        data['ip_header_length'] = self.ip_header_length
        data['ip_packet_length'] = self.ip_packet_length
        data['ip_frag_offset'] = self.ip_frag_offset
        data['ip_opt_parsed'] = self.ip_opt_parsed
        data['ip_protocol'] = self.ip_protocol
        data['ip_version'] = self.ip_version
        data['ip_type_of_service'] = self.ip_type_of_service
        data['ip_ttl'] = self.ip_ttl
        data['ip_checksum'] = self.ip_checksum
        data['ip_padding_bytes'] = self.ip_padding_bytes
        return data
