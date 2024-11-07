Work distribution:

Reese Thornburg, rethornburg: First half of Task 2 and Task 3 Client
Sam Riffel, riffel: Task 1
Ramona Tepe, tepe: Second half of Task 2
Marie Burer, pburer: Task 3 Server


To Run:
	Installations:
	sudo pip install dpkt --break-system-packages
	sudo pip install dnspython --break-system-packages
	sudo pip install ipwhois --break-system-packages

	Task 1 Example:
		sudo python3 cs3640-ping.py -destination 8.8.8.8 -n 3 -ttl 100
		(sends 3 packets to destination, sets time to live to 100)
	Task 2 Example:
		sudo python3 cs3640-traceroute.py -destination 8.8.8.8 -n_hops 3
		(max 3 hops to destination)
	Task 3 Examples:
		In server terminal, 
		sudo python3 cs3640-intelserver.py
		In client terminals, 
		sudo python3 cs3640-intelclient.py -intel_server_addr 127.0.0.1 -intel_server_port 5555 -domain python.org -service IPV4_ADDR
		sudo python3 cs3640-intelclient.py -intel_server_addr 127.0.0.1 -intel_server_port 5555 -domain python.org -service IPV6_ADDR
		sudo python3 cs3640-intelclient.py -intel_server_addr 127.0.0.1 -intel_server_port 5555 -domain python.org -service TLS_CERT
		sudo python3 cs3640-intelclient.py -intel_server_addr 127.0.0.1 -intel_server_port 5555 -domain python.org -service HOSTING_AS
		sudo python3 cs3640-intelclient.py -intel_server_addr 127.0.0.1 -intel_server_port 5555 -domain python.org -service ORGANIZATION


Resources Consulted:

https://www.w3computing.com/articles/analyzing-network-traffic-patterns-pythons-dpkt-library/
https://docs.python.org/3/library/socket.html
https://realpython.com/python-sockets/
https://dpkt.readthedocs.io/en/latest/print_icmp.html
https://dpkt.readthedocs.io/en/latest/installation.html
https://www.geeksforgeeks.org/implementing-checksum-using-python/
https://cryptography.io/en/latest/x509/reference/
https://github.com/secynic/ipwhois/tree/master/ipwhois/examples
https://docs.python.org/3/library/ssl.html
https://stackoverflow.com/questions/26851034/opening-a-ssl-socket-connection-in-python
https://dnspython.readthedocs.io/en/latest/
https://cryptography.io/en/latest/x509/tutorial/
https://ipwhois.readthedocs.io/en/latest/
https://docs.python.org/3/library/re.html
https://github.com/mdelatorre/checksum/blob/master/ichecksum.py

We used these resources to help create an understanding of how to build an implementation of a network intelligence and diagnostic service as a python program. We found it necessary to use a few libraries such as dpkt, dns, and ipwhois to implement the requirements.
