import argparse
#import system
#import dnspython
import socket

def send_request_to_server(addr, port, domain, service):

    sock = None
    try: 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        print("Error creating socket.")
        return None

    try: 
        sock.connect((addr, int(port)))
    except:
        print("Error connecting to server.")
        sock.close()
        return None

    message = f"{service}({domain})"

    try:
        sock.sendall(message.encode('utf-8'))
    except:
        print("Error sending data.")
        sock.close()
        return None

    try: 
        received = sock.recv(2048).decode('utf-8')
    except:
        print("Error receiving message.")
        sock.close()
        return None

    sock.close()

    return received

def main():
    # get arguments
    parser = argparse.ArgumentParser(description="Intelligence server/client.")
    parser.add_argument("-intel_server_addr", required=True)
    parser.add_argument("-intel_server_port", required=True)
    parser.add_argument("-domain", required=True)
    parser.add_argument("-service", required=True)
    args = parser.parse_args()

    # send request and print the server response
    print(send_request_to_server(args.intel_server_addr, args.intel_server_port, args.domain, args.service))

if __name__ == "__main__":
    main()
