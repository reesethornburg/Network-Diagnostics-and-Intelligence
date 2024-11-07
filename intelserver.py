import socket
import re
import dns.resolver as dns
import ssl
import ipwhois
from cryptography import x509

#server binding info
ip = "127.0.0.1"
port = 5555

#parse the commands we want to take and get output
def command_parse(message):
    v4_addr = re.compile(r'^IPV4_ADDR\(.*\)$')
    v6_addr = re.compile(r'^IPV6_ADDR\(.*\)$')
    tls_cert = re.compile(r'^TLS_CERT\(.*\)$')
    host_as = re.compile(r'^HOSTING_AS\(.*\)$')
    org = re.compile(r'^ORGANIZATION\(.*\)$')

    if v4_addr.match(message):
        try:
            parsed = message[message.index('(')+1:-1]
            #A = IPV4, tcp connection
            answers = dns.resolve(parsed, 'A', tcp=True)
            addrs = [d.address for d in answers]
            return addrs
        except dns.NXDOMAIN:
            return "Domain not found."
        except dns.NoAnswer:
            return "Could not find an IPV4 address associated with this domain."
        except:
            return "Error in finding the IPV4 address of the domain supplied."
    elif v6_addr.match(message):
        try:
            parsed = message[message.index('(')+1:-1]
            #AAAA = IPV6
            answers = dns.resolve(parsed, 'AAAA', tcp=True)
            addrs = [d.address for d in answers]
            return addrs
        except dns.NXDOMAIN:
            return "Domain not found."
        except dns.NoAnswer:
            return "Could not find an IPV6 address associated with this domain."
        except:
            return "Error in the address finding process."
    elif tls_cert.match(message):
        try:
            parse = message[message.index('(')+1:-1]
            #try for an http connection, if we don't get it, go for https
            try:
                cert = ssl.get_server_certificate((parse, 80))
                #we trust the recipient can decode the PEM-encoded certificate themself
                return cert
            except:
                cert = ssl.get_server_certificate((parse, 443))
                
                return cert
            
        except:
            return "Error when trying to get the TSL/SSL certificate of the domain."       
    elif host_as.match(message):
        try:
            #first, get ipv6 address
            #use v6 instead of v4 because ipv6 is a superset
            parsed = message[message.index('(')+1:-1]
            answers = dns.resolve(parsed, 'AAAA', tcp=True)
            addrs = [d.address for d in answers]

            #first address, then use ipwhois
            addr = addrs[0]
            obj = ipwhois.IPWhois(addr)
            return obj.lookup_rdap(depth=1)['asn']
        except dns.NXDOMAIN:
            return "Domain not found."
        except dns.NoAnswer:
            return "Could not find an address associated with this domain."
        except:
            return "Error in the address finding process."
    elif org.match(message):
        try:
            parse = message[message.index('(')+1:-1]
            try:
                cert = ssl.get_server_certificate((parse, 80))
                #use cryptography to decode the certificate
                cert = x509.load_pem_x509_certificate(cert.encode("utf-8"))

                #get the common name of the organization
                name = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION)[0].value
                return name
            except:
                cert = ssl.get_server_certificate((parse, 443))
                cert = x509.load_pem_x509_certificate(cert.encode("utf-8"))
            
                name = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION)[0].value
                return name
        except:
            return "Error when finding organization name of the domain." 
    else:
        return "No viable command"

def run_server():

    server = None
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        print("Error establishing server")
        exit(1)

    try:
        server.bind((ip, port))
    except:
        print("Error binding to port")
        exit(2)
    
    server.listen()
    print(f"Listening on {ip}:{port}")

    #just listen for connects, clients only want to send and receive one message, so no need for loop inside
    while True:
        c_sock, c_addr = server.accept()
        print(f"Accepted connection from {c_addr[0]}:{c_addr[1]}")

        mess = c_sock.recv(1024).decode("utf-8")
                
        response = str(command_parse(mess))

        c_sock.send(response.encode("utf-8"))
        c_sock.close()

if __name__ == "__main__":
    run_server()
