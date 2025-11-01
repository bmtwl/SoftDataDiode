import socket
import sys

def main():
    if len(sys.argv) != 3:
        print("SoftDataDiode UDP Packet Redirector")
        print("Usage: python udp_responder.py <listen_port> <response_port>")
        sys.exit(1)

    try:
        listen_port = int(sys.argv[1])
        response_port = int(sys.argv[2])
        if not (1 <= listen_port <= 65535 and 1 <= response_port <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
    except ValueError as e:
        print(f"Invalid port number: {e}")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind(('', listen_port))
        print(f"Listening on port {listen_port}, will respond on port {response_port}...")

        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received {len(data)} bytes from {addr}")

            # Send response to the same IP but different port
            response_addr = (addr[0], response_port)
            response = b"message received"
            sock.sendto(response, response_addr)
            print(f"Sent response to {response_addr}")

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
