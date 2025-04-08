import socket
import struct
import random
import time
import binascii
from collections import namedtuple
import os
import fcntl
import netifaces

# DNS Constants
DNS_PORT = 53
DNS_QUERY = 0x0000
DNS_RESPONSE = 0x8000
DNS_A_RECORD = 1
DNS_CLASS_IN = 1

# Header Structures
IPHeader = namedtuple('IPHeader', [
    'version_ihl', 'tos', 'total_length', 'identification',
    'flags',
    'ttl', 'protocol', 'checksum',
    'src_addrs', 'dest_addrs'
])

UDPHeader = namedtuple('UDPHeader', ['src_port', 'dest_port', 'length', 'checksum'])
DNSHeader = namedtuple('DNSHeader', ['id', 'flags', 'qdcount', 'ancount',
                                     'nscount', 'arcount'])

class DNSResolver:
    def __init__(self, dns_server='8.8.8.8', timeout=2, retries=3):
        self.dns_server = dns_server
        self.timeout = timeout
        self.retries = retries
        self.cache = {}
        self.debug = True  # Enable debug output
        self.sock = None  # Initialize sock to None
        self.raw_socket_available = False  # Initialize raw_socket_available to False
        self.interface = None
        self.src_mac = None
        self.dst_mac = None

        # Creating raw socket with AF_PACKET
        try:
            # Find an active interface and its MAC address - prioritize non-loopback interfaces
            interfaces = netifaces.interfaces()
            non_loopback_interfaces = [iface for iface in interfaces if iface != 'lo']
            
            # First try non-loopback interfaces
            for iface in non_loopback_interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                    self.interface = iface
                    self.src_mac = self.mac_to_bytes(addrs[netifaces.AF_LINK][0]['addr'])
                    self.src_ip = socket.inet_aton(addrs[netifaces.AF_INET][0]['addr'])
                    self.log(f"Using physical interface {iface} with IP {addrs[netifaces.AF_INET][0]['addr']}")
                    break
            
            # If no suitable non-loopback interface found, try loopback as fallback
            if not self.interface:
                for iface in interfaces:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        if iface == 'lo':
                            # For loopback, we need a dummy MAC
                            self.interface = iface
                            self.src_mac = b'\x00\x00\x00\x00\x00\x00'  # Dummy MAC for loopback
                            self.src_ip = socket.inet_aton(addrs[netifaces.AF_INET][0]['addr'])
                            self.log(f"Using loopback interface {iface} with IP {addrs[netifaces.AF_INET][0]['addr']} (not ideal)")
                            break
            
            if not self.interface:
                self.log("No suitable interface found")
                return
                
            # Get gateway MAC address for routing
            try:
                gws = netifaces.gateways()
                if 'default' in gws and netifaces.AF_INET in gws['default']:
                    default_gw = gws['default'][netifaces.AF_INET][0]
                    self.log(f"Default gateway: {default_gw}")
                    
                    # Use ARP to get gateway MAC
                    self.dst_mac = self.get_mac_address(default_gw)
                    if not self.dst_mac:
                        self.log("Could not determine gateway MAC address")
                        # Use broadcast MAC as fallback
                        self.dst_mac = b'\xff\xff\xff\xff\xff\xff'
                        self.log("Using broadcast MAC address")
                else:
                    self.log("No default gateway found")
                    self.dst_mac = b'\xff\xff\xff\xff\xff\xff'
                    self.log("Using broadcast MAC address")
            except Exception as e:
                self.log(f"Error determining gateway: {e}")
                # Use broadcast MAC as fallback
                self.dst_mac = b'\xff\xff\xff\xff\xff\xff'
                self.log("Using broadcast MAC address")
                
            # Create the AF_PACKET socket
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  # ETH_P_IP
            self.sock.bind((self.interface, 0))
            self.raw_socket_available = True
            self.log(f"AF_PACKET socket created successfully on {self.interface}")
            
            # Create a second socket to receive responses - using ETH_P_ALL to capture all packets
            self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
            self.recv_sock.bind((self.interface, 0))
            self.recv_sock.settimeout(self.timeout)

        except ImportError:
            self.log("netifaces module not available")
            self.raw_socket_available = False
        except OSError as e:
            self.log(f"Raw socket creation failed: {e}")
            self.raw_socket_available = False

    def log(self, msg):
        if self.debug:
            print(msg)
            
    def get_mac_address(self, ip):
        """Use ARP to get the MAC address of a given IP address"""
        try:
            import subprocess
            output = subprocess.check_output(['arp', '-n', ip]).decode('utf-8')
            lines = output.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3 and parts[0] == ip:
                    mac = parts[2]
                    return self.mac_to_bytes(mac)
            return None
        except Exception as e:
            self.log(f"ARP lookup failed: {e}")
            return None
    
    def mac_to_bytes(self, mac_str):
        """Convert MAC address string to bytes"""
        return bytes.fromhex(mac_str.replace(':', ''))

    # Building Ethernet Header
    def build_ethernet_header(self, src_mac, dst_mac, eth_type=0x0800):
        return dst_mac + src_mac + struct.pack('!H', eth_type)

    # Building IP Header
    def build_ip_header(self, src_ip, dest_ip, data_length):
        return IPHeader(
            version_ihl=(4 << 4) + 5,  # IPv4 with 5 words (20 bytes)
            tos=0,
            total_length=20 + 8 + data_length,  # IP header + UDP header + data
            identification=random.randint(0, 65535),
            flags=(1 << 14),  # Don't fragment
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            checksum=0,  # Will be filled in later
            src_addrs=src_ip,
            dest_addrs=dest_ip
        )

    # Building UDP Header
    def build_udp_header(self, src_port, data_length):
        return UDPHeader(
            src_port=src_port,
            dest_port=DNS_PORT,
            length=8 + data_length,  # UDP header + data
            checksum=0  # Will be filled in later
        )

    # Building DNS Query
    def build_dns_query(self, domain):
        # Generate random query ID
        query_id = random.randint(0, 65535)
        
        # DNS Header
        # ID, Flags, QDCount, ANCount, NSCount, ARCount
        dns_header = struct.pack('!HHHHHH', query_id, DNS_QUERY, 1, 0, 0, 0)
        
        # DNS Question
        question = b''
        for part in domain.split('.'):
            question += struct.pack('B', len(part)) + part.encode()
        question += b'\0'  # Terminating zero
        question += struct.pack('!HH', DNS_A_RECORD, DNS_CLASS_IN)  # QTYPE and QCLASS
        
        return query_id, dns_header + question

    # Calculating Checksum
    def calculate_checksum(self, data):
        total = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                total += (data[i] << 8) + data[i + 1]
            else:
                total += data[i] << 8
        
        while total >> 16 > 0:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF

    # Sending Query using standard socket as a fallback
    def standard_send_udp_query(self, domain):
        """Use standard UDP socket to send DNS query and receive response"""
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(self.timeout)
            
            # Build the DNS query
            query_id, dns_payload = self.build_dns_query(domain)
            self.log(f"Standard UDP DNS query ID: {query_id}")
            
            # Send the query
            udp_sock.sendto(dns_payload, (self.dns_server, DNS_PORT))
            self.log(f"Standard UDP DNS query sent to {self.dns_server}")
            
            # Receive the response
            response, _ = udp_sock.recvfrom(4096)
            self.log(f"Standard UDP DNS response received, length: {len(response)}")
            
            # Parse the response (just the DNS part, no IP/UDP headers)
            if len(response) < 12:
                self.log("DNS response too short")
                return None
                
            # Parse DNS header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
            header = DNSHeader(id, flags, qdcount, ancount, nscount, arcount)
            
            self.log(f"DNS Response ID: {header.id}, Flags: {header.flags:04x}, Answers: {header.ancount}")
            
            # Check if it's a response
            if (header.flags & DNS_RESPONSE) == 0:
                self.log("Not a DNS response")
                return None

            # Check for errors
            rcode = header.flags & 0x000F
            if rcode != 0:
                self.log(f"DNS error code: {rcode}")
                return None

            answers = []
            offset = 12  # Skip header

            # Skip question section
            for _ in range(header.qdcount):
                if offset >= len(response):
                    self.log("Response too short for question section")
                    return None
                
                # Skip domain name
                while offset < len(response):
                    length = response[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:  # Compression pointer
                        offset += 2
                        break
                    offset += length + 1
                
                if offset + 4 > len(response):
                    self.log("Response too short for question section")
                    return None
                offset += 4  # Skip QTYPE and QCLASS

            # Parsing answers
            for _ in range(header.ancount):
                if offset >= len(response):
                    self.log("Response too short for answer section")
                    break

                try:
                    name, offset = self.parse_dns_name(response, offset)
                    if offset + 10 > len(response):
                        self.log("Response too short for answer record")
                        break

                    atype, aclass, ttl, rdlength = struct.unpack(
                        '!HHIH', response[offset:offset + 10])
                    offset += 10

                    if offset + rdlength > len(response):
                        self.log("Response too short for answer data")
                        break

                    rdata = response[offset:offset + rdlength]
                    offset += rdlength

                    if atype == DNS_A_RECORD and aclass == DNS_CLASS_IN:
                        ip = socket.inet_ntoa(rdata)
                        self.log(f"Found A record: {name.decode() if isinstance(name, bytes) else name} -> {ip}")
                        answers.append((name.decode() if isinstance(name, bytes) else name, ttl, ip))

                except Exception as e:
                    self.log(f"Error parsing answer: {e}")
                    break

            return answers
            
        except socket.timeout:
            self.log("Standard UDP DNS query timed out")
            return None
        except Exception as e:
            self.log(f"Standard UDP DNS query failed: {e}")
            return None
        finally:
            try:
                udp_sock.close()
            except:
                pass

    # Sending Query
    def send_query(self, domain):
        # Ensure only specific domains are resolved
        allowed_domains = ["google.com", "github.com", "wikipedia.com"]
        if domain not in allowed_domains:
            self.log(f"Domain '{domain}' is not supported for DNS resolution.")
            return None  # Return None or handle unsupported domains appropriately

        if not self.raw_socket_available:
            self.log("Raw socket not available, using standard DNS")
            return self.standard_dns_query(domain)
            
        # If interface is loopback, try the standard UDP approach first
        if self.interface == 'lo':
            self.log("Using loopback interface - trying standard UDP DNS query first")
            result = self.standard_send_udp_query(domain)
            if result:
                return result
            self.log("Standard UDP DNS query failed, trying raw socket approach")

        dest_ip = socket.inet_aton(self.dns_server)
        src_port = random.randint(1024, 65535)
        self.log(f"Using source port: {src_port}")

        # Build DNS Payload
        query_id, dns_payload = self.build_dns_query(domain)
        self.log(f"DNS Query ID: {query_id}")

        # Construct IP Header
        ip_header = self.build_ip_header(self.src_ip, dest_ip, len(dns_payload))
        ip_header_bytes = struct.pack(
            '!BBHHHBBH4s4s',
            ip_header.version_ihl,
            ip_header.tos,
            ip_header.total_length,
            ip_header.identification,
            ip_header.flags,
            ip_header.ttl,
            ip_header.protocol,
            ip_header.checksum,
            ip_header.src_addrs,
            ip_header.dest_addrs
        )

        # Construct UDP Header
        udp_header = self.build_udp_header(src_port, len(dns_payload))
        udp_header_bytes = struct.pack(
            '!HHHH',
            udp_header.src_port,
            udp_header.dest_port,
            udp_header.length,
            udp_header.checksum
        )

        # Build Ethernet header
        eth_header = self.build_ethernet_header(self.src_mac, self.dst_mac)

        # Assembling full packet without checksums
        ip_udp_dns_payload = ip_header_bytes + udp_header_bytes + dns_payload

        # Calculate checksum for UDP
        pseudo_header = struct.pack('!4s4sBBH', ip_header.src_addrs, ip_header.dest_addrs, 0, socket.IPPROTO_UDP,
                                     len(udp_header_bytes) + len(dns_payload))
        udp_checksum_data = pseudo_header + udp_header_bytes + dns_payload
        if len(udp_checksum_data) % 2 != 0:
            udp_checksum_data += b'\0'
        udp_checksum = self.calculate_checksum(udp_checksum_data)
        udp_header_bytes = struct.pack('!HHHH', udp_header.src_port, udp_header.dest_port, udp_header.length,
                                        udp_checksum)
        
        # Recombine with updated UDP checksum
        ip_udp_dns_payload = ip_header_bytes + udp_header_bytes + dns_payload

        # Calculate checksum for IP
        ip_checksum = self.calculate_checksum(ip_udp_dns_payload[:20])
        
        # Update IP header with checksum
        ip_header_bytes = struct.pack(
            '!BBHHHBBH4s4s',
            ip_header.version_ihl,
            ip_header.tos,
            ip_header.total_length,
            ip_header.identification,
            ip_header.flags,
            ip_header.ttl,
            ip_header.protocol,
            ip_checksum,
            ip_header.src_addrs,
            ip_header.dest_addrs
        )
        
        # Assemble the final packet
        final_packet = eth_header + ip_header_bytes + udp_header_bytes + dns_payload
        
        # Send the packet
        for attempt in range(self.retries):
            try:
                self.sock.send(final_packet)
                self.log(f"DNS query sent (attempt {attempt+1})")
                
                # Wait for response
                response = self.receive_response(query_id)
                if response:
                    return response
                    
            except Exception as e:
                self.log(f"Error sending DNS query: {e}")
                
        # All retries failed
        self.log("All DNS query attempts failed")
        return None
        
    # Standard DNS resolution as a final fallback
    def standard_dns_query(self, domain):
        self.log(f"Using standard socket DNS resolution for {domain}")
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = []
            for info in addr_info:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)

            if ips:
                return [(domain, 3600, ip) for ip in ips]  # Assume TTL of 3600
            return None
        except socket.gaierror as e:
            self.log(f"Standard DNS resolution failed: {e}")
            return None

    # Parsing the DNS queries
    def parse_dns_response(self, packet):
        self.log(f"Parsing DNS response packet of length {len(packet)}")
        
        # Skip Ethernet header (14 bytes)
        if len(packet) < 14:
            self.log("Packet too short for Ethernet header")
            return None
            
        packet = packet[14:]
        
        if len(packet) < 28:  # Min size for IP + UDP headers
            self.log("Packet too short for IP+UDP headers")
            return None

        try:
            # Check IP header (20 bytes)
            ip_header = packet[:20]
            protocol = ip_header[9]
            
            if protocol != socket.IPPROTO_UDP:
                self.log(f"Not a UDP packet (protocol: {protocol})")
                return None
                
            # Verify source IP address
            src_ip = socket.inet_ntoa(ip_header[12:16])
            if src_ip != self.dns_server:
                self.log(f"Packet not from DNS server (from: {src_ip}, expected: {self.dns_server})")
                return None
                
            # Check UDP header (8 bytes)
            udp_header = packet[20:28]
            src_port = struct.unpack('!H', udp_header[0:2])[0]
            dest_port = struct.unpack('!H', udp_header[2:4])[0]
            
            if src_port != DNS_PORT:
                self.log(f"Not from DNS port (source port: {src_port})")
                return None
                
            dns_payload = packet[28:]
            
            if len(dns_payload) < 12:  # Min size for DNS header
                self.log("DNS payload too short")
                return None

            # Parse DNS header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', dns_payload[:12])
            header = DNSHeader(id, flags, qdcount, ancount, nscount, arcount)
            
            self.log(f"DNS Response ID: {header.id}, Flags: {header.flags:04x}, Answers: {header.ancount}")
            
            # Check if it's a response
            if (header.flags & DNS_RESPONSE) == 0:
                self.log("Not a DNS response")
                return None

            # Check for errors
            rcode = header.flags & 0x000F
            if rcode != 0:
                self.log(f"DNS error code: {rcode}")
                return None

            answers = []
            offset = 12  # Skip header

            # Skip question section
            for _ in range(header.qdcount):
                if offset >= len(dns_payload):
                    self.log("Packet too short for question section")
                    return None
                
                # Skip domain name
                while offset < len(dns_payload):
                    length = dns_payload[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:  # Compression pointer
                        offset += 2
                        break
                    offset += length + 1
                
                if offset + 4 > len(dns_payload):
                    self.log("Packet too short for question section")
                    return None
                offset += 4  # Skip QTYPE and QCLASS

            # Parsing answers
            for _ in range(header.ancount):
                if offset >= len(dns_payload):
                    self.log("Packet too short for answer section")
                    break

                try:
                    name, offset = self.parse_dns_name(dns_payload, offset)
                    if offset + 10 > len(dns_payload):
                        self.log("Packet too short for answer record")
                        break

                    atype, aclass, ttl, rdlength = struct.unpack(
                        '!HHIH', dns_payload[offset:offset + 10])
                    offset += 10

                    if offset + rdlength > len(dns_payload):
                        self.log("Packet too short for answer data")
                        break

                    rdata = dns_payload[offset:offset + rdlength]
                    offset += rdlength

                    if atype == DNS_A_RECORD and aclass == DNS_CLASS_IN:
                        ip = socket.inet_ntoa(rdata)
                        name_str = name.decode() if isinstance(name, bytes) else name
                        self.log(f"Found A record: {name_str} -> {ip}")
                        answers.append((name_str, ttl, ip))

                except Exception as e:
                    self.log(f"Error parsing answer: {e}")
                    break

            return answers

        except Exception as e:
            self.log(f"Error parsing DNS response: {e}")
            return None

    def parse_dns_name(self, packet, offset):
        name_parts = []
        original_offset = offset

        try:
            while True:
                if offset >= len(packet):
                    self.log("DNS name parsing: end of packet reached")
                    return b'.'.join(name_parts), offset

                length = packet[offset]

                if length == 0:
                    offset += 1
                    break

                if (length & 0xC0) == 0xC0:  # Compression pointer
                    if offset + 1 >= len(packet):
                        self.log("DNS name parsing: compression pointer out of bounds")
                        return b'.'.join(name_parts), offset

                    pointer = struct.unpack('!H', packet[offset:offset + 2])[0] & 0x3FFF

                    # Check for forward reference
                    if pointer >= original_offset:
                        self.log("DNS name parsing: forward reference detected")
                        return b'.'.join(name_parts), offset

                    # Follow the pointer
                    pointed_name, _ = self.parse_dns_name(packet, pointer)
                    if isinstance(pointed_name, bytes):
                        name_parts.append(pointed_name)
                    else:
                        name_parts.append(pointed_name.encode())
                    offset += 2
                    break
                else:
                    offset += 1
                    if offset + length > len(packet):
                        self.log("DNS name parsing: label length exceeds packet")
                        return b'.'.join(name_parts), offset
                    name_parts.append(packet[offset:offset + length])
                    offset += length

            return b'.'.join(name_parts), offset

        except Exception as e:
            self.log(f"Error parsing DNS name: {e}")
            return b'.'.join(name_parts), offset

    # Receiving the responses
    def receive_response(self, query_id):
        start_time = time.time()
        self.recv_sock.settimeout(self.timeout)
        self.log(f"Waiting for response to query ID: {query_id}")

        while time.time() - start_time < self.timeout:
            try:
                data, addr = self.recv_sock.recvfrom(4096)
                self.log(f"Received packet of length {len(data)}")
                
                # Skip Ethernet header (14 bytes) and IP header (20 bytes)
                if len(data) < 42:  # 14 (Eth) + 20 (IP) + 8 (UDP)
                    continue
                    
                # Extract IP header
                ip_part = data[14:34]  # IP header
                if len(ip_part) < 20:
                    continue
                    
                # Extract source IP
                src_ip = socket.inet_ntoa(ip_part[12:16])
                if src_ip != self.dns_server:
                    continue
                    
                # Check protocol (UDP = 17)
                if ip_part[9] != socket.IPPROTO_UDP:
                    continue
                    
                # Extract UDP header
                udp_part = data[34:42]  # UDP header
                if len(udp_part) < 8:
                    continue
                    
                # Check if source port is DNS (53)
                src_port = struct.unpack('!H', udp_part[0:2])[0]
                if src_port != DNS_PORT:
                    continue
                    
                # DNS payload starts at offset 42
                dns_payload = data[42:]
                if len(dns_payload) < 12:
                    continue
                    
                # Check DNS query ID
                received_id = struct.unpack('!H', dns_payload[0:2])[0]
                if received_id != query_id:
                    self.log(f"Ignoring DNS response with ID {received_id}, expected {query_id}")
                    continue
                
                self.log(f"Found matching DNS response with ID {received_id}")
                return self.parse_dns_response(data)
                
            except socket.timeout:
                self.log("Socket timeout while waiting for response")
                break
            except Exception as e:
                self.log(f"Error receiving response: {e}")
        
        return None

    # Main resolver method to be called by users
    def resolve(self, domain):
        self.log(f"Resolving domain: {domain}")
        
        # Check cache first
        if domain in self.cache:
            if self.cache[domain]['expires'] > time.time():
                self.log(f"Using cached result for {domain}")
                return self.cache[domain]['ips']
            else:
                self.log(f"Cache expired for {domain}")
        
        # Send query and get response
        response = self.send_query(domain)
        
        if response:
            # Cache the result using the shortest TTL
            min_ttl = min([ttl for _, ttl, _ in response])
            self.cache[domain] = {
                'ips': response,
                'expires': time.time() + min_ttl
            }
            self.log(f"Cached result for {domain} with TTL {min_ttl}")
            return response
        else:
            self.log(f"Failed to resolve {domain}")
            return None

    # Clean up resources
    def close(self):
        if self.sock:
            try:
                self.sock.close()
                self.log("Send socket closed")
            except Exception as e:
                self.log(f"Error closing send socket: {e}")
            self.sock = None
            
        if hasattr(self, 'recv_sock') and self.recv_sock:
            try:
                self.recv_sock.close()
                self.log("Receive socket closed")
            except Exception as e:
                self.log(f"Error closing receive socket: {e}")
            self.recv_sock = None


# Example usage
if __name__ == "__main__":
    # Note: This needs to be run as root/administrator to use AF_PACKET sockets
    resolver = DNSResolver()
    try:
        result = resolver.resolve("example.com")
        if result:
            print("\nResolution results:")
            for domain, ttl, ip in result:
                print(f"{domain} -> {ip} (TTL: {ttl}s)")
        else:
            print("\nFailed to resolve domain")
    finally:
        resolver.close()