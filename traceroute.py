import argparse
import time
import struct
import socket

def make_icmp_socket(ttl, timeout):
    # create raw socket for ICMP
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)
    return sock

def send_icmp_echo(sock, id, seq, destination):
    # construct ICMP header
    type_code = 8  # ICMP Echo Request
    code = 0
    checksum = 0
    header = struct.pack('!BBHHH', type_code, code, checksum, id, seq)
    payload = b'cs3640_traceroute'
    
    # calculate checksum
    checksum = calculate_checksum(header + payload)
    header = struct.pack('!BBHHH', type_code, code, checksum, id, seq)
    
    # send the packet
    sock.sendto(header + payload, (destination, 1))

# implement Internet Checksum algorithm! Takes in byte sequence, returns 16-bit checksum.
# Sums 16 bit words in source_string, handles odd-byte cases if needed, adds overflow back into lower 16 bits,
# compliments result to get checksum, and swap bytes for network byte order.
def calculate_checksum(source_string):
    sum = 0
    
    #  highest even index we can reach in source_string. Only process complete pairs of bytes.
    count_to = (len(source_string) // 2) * 2
    
    # Processes two bytes (16 bits) at a time.
    for count in range(0, count_to, 2):
        # Multiplying by 256 shifts 8 bits to the left to  be a 16 bit number with source_string[count] as lower 8 bits.
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        
        # Sum fits within 32 bit bounds for overflow reasons
        sum = sum & 0xffffffff
        
    # Handle off length strings.
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    # Handle overflow beyond 16 bits
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    
    # Invert sum to create checksum
    answer = ~sum
    answer = answer & 0xffff
    
    # Return Checksum in Network Byte Order.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def recv_icmp_response(sock, id, seq):
    start_time = time.time()
    while True:
        try:
            packet, addr = sock.recvfrom(1024)
            ip_header_len = (packet[0] & 0x0F) * 4
            icmp_header = packet[ip_header_len:ip_header_len + 8]
            _type, _code, _checksum, _id, _seq = struct.unpack('!BBHHH', icmp_header)

            if _type == 11 or (_type == 0 and _id == id and _seq == seq):  # ICMP Time Exceeded or Echo Reply
                rtt = (time.time() - start_time) * 1000
                return addr[0], rtt
        except socket.timeout:
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traceroute")
    parser.add_argument("-destination", required=True, help="Destination IP address or domain")
    parser.add_argument("-n_hops", type=int, default=30, help="Maximum number of hops")
    args = parser.parse_args()

    dest = args.destination
    n_hops = args.n_hops
    timeout = 2

    print(f"Executing traceroute to {dest} with max hops {n_hops}:")

    for i in range(1, n_hops + 1):
        sock = make_icmp_socket(i, timeout)
        try:
            send_icmp_echo(sock, i, i, dest)
            response = recv_icmp_response(sock, i, i)
            if response:
                responder_ip, rtt = response
                print(f"destination = {dest}; hop {i} = {responder_ip}; rtt = {rtt:.2f} ms")
                if responder_ip == dest:
                    print("Reached destination.")
                    break
            else:
                print(f"destination = {dest}; hop {i}: Request timed out")
        finally:
            sock.close()
