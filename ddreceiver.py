import socket
import threading
import argparse
import logging
import time
import struct
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import cv2
import numpy as np
from cryptography.fernet import Fernet

class DataDiodeReceiver:
    def __init__(self, udp_host, udp_port, http_host, http_port, key, buffer_size=100, debug=False):
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.http_host = http_host
        self.http_port = http_port
        self.buffer_size = buffer_size
        self.debug = debug

        self.logger = self.setup_logging(debug)

        try:
            self.cipher = Fernet(key.encode())
            self.logger.debug("Encryption key validated")
        except Exception as e:
            self.logger.error(f"Invalid encryption key: {e}")
            raise

        # Frame buffer (circular buffer)
        self.frame_buffer = deque(maxlen=buffer_size)
        self.buffer_lock = threading.Lock()

        # Fragment reassembly buffer
        self.fragment_buffer = defaultdict(dict)  # seq_num -> {frag_index: data}
        self.fragment_metadata = {}  # seq_num -> total_frags

        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_decrypted': 0,
            'frames_buffered': 0,
            'decryption_errors': 0,
            'fragments_received': 0,
            'frames_reassembled': 0
        }

        # UDP socket
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Increase receive buffer size
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)  # 8MB
        self.udp_sock.bind((udp_host, udp_port))
        self.logger.info(f"UDP socket bound to {udp_host}:{udp_port}")

        # HTTP server
        self.http_server = None

    def setup_logging(self, debug=False):
        """Setup logging configuration"""
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    def reassemble_frame(self, sequence_number):
        """Reassemble frame from fragments"""
        fragments = self.fragment_buffer.get(sequence_number, {})
        total_frags = self.fragment_metadata.get(sequence_number, 0)

        if len(fragments) == total_frags and total_frags > 0:
            # Reassemble in order
            frame_data = b''.join([fragments[i] for i in range(total_frags)])

            # Clean up
            del self.fragment_buffer[sequence_number]
            del self.fragment_metadata[sequence_number]

            return frame_data
        return None

    def udp_receiver(self):
        """Background thread to receive UDP packets"""
        self.logger.info(f"Listening for UDP packets on {self.udp_host}:{self.udp_port}")

        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.stats['packets_received'] += 1

                try:
                    decrypted_data = self.cipher.decrypt(data)
                    self.stats['packets_decrypted'] += 1
                except InvalidToken:
                    self.stats['decryption_errors'] += 1
                    self.logger.warning(f"Decryption failed for packet from {addr}")
                    continue
                except Exception as e:
                    self.stats['decryption_errors'] += 1
                    self.logger.error(f"Decryption error: {e}")
                    continue

                # Parse header: sequence_number(4) + frag_index(2) + total_frags(2)
                if len(decrypted_data) < 8:
                    self.logger.warning("Packet too short to contain header")
                    continue

                header = decrypted_data[:8]
                sequence_number, frag_index, total_frags = struct.unpack('>IHH', header)
                fragment_data = decrypted_data[8:]

                self.stats['fragments_received'] += 1

                # Store fragment
                self.fragment_buffer[sequence_number][frag_index] = fragment_data
                self.fragment_metadata[sequence_number] = total_frags

                # Try to reassemble frame
                frame_data = self.reassemble_frame(sequence_number)

                if frame_data:
                    # Convert to frame
                    nparr = np.frombuffer(frame_data, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

                    if frame is not None:
                        with self.buffer_lock:
                            self.frame_buffer.append((sequence_number, frame))
                            self.stats['frames_buffered'] += 1
                            self.stats['frames_reassembled'] += 1

                        if self.debug:
                            self.logger.debug(f"Reassembled frame {sequence_number}, buffer size: {len(self.frame_buffer)}")
                    else:
                        self.logger.warning(f"Failed to decode frame {sequence_number}")

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

    def start_udp_receiver(self):
        """Start UDP receiver in background thread"""
        udp_thread = threading.Thread(target=self.udp_receiver, daemon=True)
        udp_thread.start()
        self.logger.info("UDP receiver thread started")
        return udp_thread

    def start_http_server(self):
        """Start HTTP server"""
        class FrameHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                self.server.receiver.logger.info(f"{self.address_string()} - {format % args}")

            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()

                    html = """
                    <html>
                        <head>
                            <title>Data Diode Stream</title>
                        </head>
                        <body>
                            <h1>Data Diode PoC</h1>
                            <img src="/stream" width="1280" height="720" />
                        </body>
                    </html>
                    """
                    self.wfile.write(html.encode())

                elif self.path == '/stream':
                    self.send_response(200)
                    self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=frame')
                    self.end_headers()

                    last_seq = -1
                    while True:
                        frame = None
                        current_seq = -1

                        with self.server.receiver.buffer_lock:
                            if self.server.receiver.frame_buffer:
                                current_seq, frame = self.server.receiver.frame_buffer[-1]

                        if frame is not None and current_seq != last_seq:
                            # Resize for streaming
                            frame_resized = cv2.resize(frame, (800, 450))
                            _, buffer = cv2.imencode('.jpg', frame_resized)
                            frame_data = buffer.tobytes()

                            self.wfile.write(b'--frame\r\n')
                            self.send_header('Content-type', 'image/jpeg')
                            self.send_header('Content-length', str(len(frame_data)))
                            self.end_headers()
                            self.wfile.write(frame_data)
                            self.wfile.write(b'\r\n')

                            last_seq = current_seq
                            if self.server.receiver.debug:
                                self.server.receiver.logger.debug(f"Streamed frame {current_seq}")

                        time.sleep(0.03)

                elif self.path == '/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()

                    import json
                    stats_json = json.dumps(self.server.receiver.stats, indent=2)
                    self.wfile.write(stats_json.encode())

                else:
                    self.send_error(404)

        self.http_server = HTTPServer((self.http_host, self.http_port), FrameHandler)
        self.http_server.receiver = self

        self.logger.info(f"HTTP server starting on {self.http_host}:{self.http_port}")
        self.http_server.serve_forever()

    def run(self):
        """Main run method"""
        self.start_udp_receiver()

        try:
            self.start_http_server()
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
        finally:
            self.udp_sock.close()
            if self.http_server:
                self.http_server.shutdown()

def main():
    parser = argparse.ArgumentParser(description='Data Diode Receiver')
    parser.add_argument('--udp-host', default='0.0.0.0', help='UDP listen host (default: 0.0.0.0)')
    parser.add_argument('--udp-port', type=int, required=True, help='UDP listen port')
    parser.add_argument('--http-host', default='127.0.0.1', help='HTTP server host (default: 127.0.0.1)')
    parser.add_argument('--http-port', type=int, required=True, help='HTTP server port')
    parser.add_argument('--key', required=True, help='Base64 encoded encryption key')
    parser.add_argument('--buffer-size', type=int, default=100, help='Frame buffer size (default: 100)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    try:
        receiver = DataDiodeReceiver(
            udp_host=args.udp_host,
            udp_port=args.udp_port,
            http_host=args.http_host,
            http_port=args.http_port,
            key=args.key,
            buffer_size=args.buffer_size,
            debug=args.debug
        )

        receiver.run()
    except Exception as e:
        print(f"Failed to start receiver: {e}")

if __name__ == "__main__":
    main()
