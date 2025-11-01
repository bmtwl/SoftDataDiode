import socket
import sys

def main():
    if len(sys.argv) != 2:
        print("SoftDataDiode UDP Packet Reflector")
        print("Usage: python ddreflect.py <port>")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        print(f"Invalid port number: {e}")
        sys.exit(1)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Bind to the specified port on all interfaces
        sock.bind(('', port))
        print(f"Listening on port {port}...")

        while True:
            # Receive data and sender's address
            data, addr = sock.recvfrom(1024)
            print(f"Received {len(data)} bytes from {addr}")

            # Send response back to sender
            response = b"dd reflector"
            sock.sendto(response, addr)
            print(f"Sent response to {addr}")

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
