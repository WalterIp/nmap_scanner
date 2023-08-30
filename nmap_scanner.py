#!/usr/bin/python 3

import nmap

nm = nmap.PortScanner()
print("\nWclome, this is a simple nmap automation tool")
print("<--------------------------------------------------------->")

ip_add = input("Please enter the IP address you want to scan: ")
print("The IP address you entered is: ", ip_add)
type(ip_add)

while True:

    resp = input("""\nPlease enter they type of scan you want to run
                    1)SYN ACK Scan
                    2)UDP Scan
                    3)Comprehensive Scan\n""")
    print("\nYou have selected option: ", resp)

    if resp == "1":
        print ("Nmap Version:", nm.nmap_version())                   #print the nmap version used by nm
        nm.scan(ip_add, '1-1024', '-v -sS')                          #scan the entered IP address with verbose SYN ACK scan
        print("Scaning Information: ", nm.scaninfo())                #print the scanning information
        print("IP Status: ", nm[ip_add].state())                     #print the state of the entered IP address, up or down
        print("Protocols: ", nm[ip_add].all_protocols())             #print the identified protocols on the entered IP address, TCP or UDP
        print("Open Ports: ", nm[ip_add]['tcp'].keys())              #print the open TCP ports on the entered IP address
        break
    elif resp == "2":
        print ("Nmap Version:", nm.nmap_version())
        nm.scan(ip_add, '1-1024', '-v -sU')
        print("Scaning Information: ", nm.scaninfo())
        print("IP Status: ", nm[ip_add].state())
        print("Protocols: ", nm[ip_add].all_protocols())
        print("Open Ports: ", nm[ip_add]['udp'].keys())
        break
    elif resp == "3":
        print ("Nmap Version:", nm.nmap_version())
        nm.scan(ip_add, '1-1024', '-v -sS -sV -sC -A -O')
        print("Scaning Information: ", nm.scaninfo())
        print("IP Status: ", nm[ip_add].state())
        print("Protocols: ", nm[ip_add].all_protocols())
        print("Open Ports: ", nm[ip_add]['tcp'].keys())
        break
    else:
        print("Invalid option. Please enter a number between 1 and 3.")