import socket
import dpkt
import time
import struct
import argparse

def make_icmp_socket(ttl, timeout):
    # create raw socket for ICMP
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)
    return sock

def send_icmp_echo(sock, payload, id, seq, destination):
    # create ICMP echo packet using dpkt
    icmp = dpkt.icmp.ICMP()
    icmp.type = dpkt.icmp.ICMP_ECHO
    icmp.code = 0
    icmp.data = struct.pack('!HH', id, seq) + payload
    icmp.sum = dpkt.in_cksum(bytes(icmp))

    # send packet to destination
    sock.sendto(bytes(icmp), (destination, 1))

def recv_icmp_response(sock, id, seq):
    # listen for ICMP response packets
    start_time = time.time()
    while True:
        try:
            packet, addr = sock.recvfrom(1024)
            # extract ICMP header from the packet (ICMP header starts after IP header, which is 20 bytes)
            ip_header_len = (packet[0] & 0x0F) * 4  # calculate IP header length
            icmp_header = packet[ip_header_len:ip_header_len + 8]
            _type, _code, _checksum, _id, _seq = struct.unpack('!BBHHH', icmp_header)

            # check if it’s an ICMP Echo Reply matching ID and sequence number
            if _type == dpkt.icmp.ICMP_ECHOREPLY and _id == id and _seq == seq:
                return time.time() - start_time
        except socket.timeout:
            return None

def main(destination, n, ttl):
    # run ping with n packets to destination
    id = 0
    success_count = 0
    total_rtt = 0
    payload = b'ping'

    for seq in range(n):
        # send ICMP Echo Request
        with make_icmp_socket(ttl, 1) as sock:
            send_icmp_echo(sock, payload, id, seq, destination)
            rtt = recv_icmp_response(sock, id, seq)
            if rtt:
                rtt_ms = rtt * 1000
                success_count += 1
                total_rtt += rtt_ms
                print(f"destination = {destination}; icmp_seq = {seq}; icmp_id = {id}; ttl = {ttl}; rtt = {rtt_ms:.1f} ms")
            else:
                print(f"destination = {destination}; icmp_seq = {seq}; icmp_id = {id}; ttl = {ttl}; request timed out")

    # print summary
    avg_rtt = total_rtt / success_count if success_count else 0
    print(f"Average rtt: {avg_rtt:.1f} ms; {success_count}/{n} successful pings.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-destination", required=True)
    parser.add_argument("-n", type=int, default=3)
    parser.add_argument("-ttl", type=int, default=64)
    args = parser.parse_args()

    main(args.destination, args.n, args.ttl)
