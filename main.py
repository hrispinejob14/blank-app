import socket
import ssl
import threading
import struct
import select

# --- Configuration ---
LISTEN_PORT = 443
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
BUFFER_SIZE = 65535  # Max IP packet size

def parse_ip_packet(packet):
    """
    Parses the IP packet header to find the destination IP and protocol.
    """
    try:
        # IP header is the first 20 bytes
        ip_header = packet[0:20]
        # Unpack the header fields
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        protocol = iph[6]
        dest_ip = socket.inet_ntoa(iph[9])
        
        # TCP is protocol number 6
        if protocol == 6:
            # TCP header starts after the IP header
            tcp_header = packet[20:40]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            dest_port = tcph[1]
            return dest_ip, dest_port
        else:
            # Handle other protocols like UDP or ICMP if needed
            return None, None
            
    except struct.error:
        return None, None

def forward_traffic(client_conn, remote_sock):
    """
    Forwards traffic in both directions between the client and the remote destination
    using select() for efficient I/O multiplexing.
    """
    sockets = [client_conn, remote_sock]
    
    try:
        while True:
            # Wait for any of the sockets to be ready for reading
            readable, _, exceptional = select.select(sockets, [], sockets, 60)
            
            if exceptional:
                break # An error occurred
            
            if not readable:
                break # Timeout
                
            for sock in readable:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return # Connection closed
                
                if sock is client_conn:
                    # Data from the Android app, forward to the real destination
                    remote_sock.sendall(data)
                else:
                    # Data from the real destination, forward back to the Android app
                    client_conn.sendall(data)
    except Exception as e:
        print(f"[!] Forwarding error: {e}")
    finally:
        client_conn.close()
        remote_sock.close()


def handle_client(conn):
    """
    Handles a single client, establishes connection to the real destination,
    and starts the traffic forwarding.
    """
    print("[+] New client connected.")
    remote_sock = None
    try:
        # We need to read the first packet to know where to connect
        headers = b''
        while b'\r\n\r\n' not in headers:
            headers += conn.recv(1)
        
        headers_str = headers.decode('utf-8', errors='ignore')
        content_length_str = [line for line in headers_str.split('\r\n') if 'content-length' in line.lower()]
        
        if not content_length_str:
            return

        content_length = int(content_length_str[0].split(':')[1].strip())
        
        ip_packet = b''
        while len(ip_packet) < content_length:
            ip_packet += conn.recv(content_length - len(ip_packet))
        
        # Parse the packet to get the destination
        dest_ip, dest_port = parse_ip_packet(ip_packet)
        
        if not dest_ip:
            print("[-] Could not parse IP packet. Closing connection.")
            return

        print(f"[*] Client wants to connect to: {dest_ip}:{dest_port}")
        
        # Create a new socket to connect to the real destination
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((dest_ip, dest_port))
        
        # We've connected. Now, send the first packet that we already read.
        remote_sock.sendall(ip_packet)
        
        # Start forwarding all subsequent traffic
        forward_traffic(conn, remote_sock)

    except Exception as e:
        print(f"[!] Error in handle_client: {e}")
    finally:
        if remote_sock:
            remote_sock.close()
        conn.close()
        print("[-] Client disconnected.")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', LISTEN_PORT))
    sock.listen(10)
    print(f"[*] Secure Tunnel Server listening on 0.0.0.0:{LISTEN_PORT}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print("[!] SSL certificate files not found. Please generate cert.pem and key.pem.")
        return

    while True:
        client_socket, addr = sock.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        secure_conn = context.wrap_socket(client_socket, server_side=True)
        
        client_handler = threading.Thread(target=handle_client, args=(secure_conn,))
        client_handler.start()

if __name__ == '__main__':
    main()
