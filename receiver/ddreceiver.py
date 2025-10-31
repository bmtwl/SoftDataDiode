import socket
import threading
import argparse
import logging
import time
import struct
import math
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import cv2
import numpy as np
from cryptography.fernet import Fernet

class ThreadingHTTPServer(HTTPServer):
    """Handle requests in separate threads"""
    def process_request(self, request, client_address):
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address)
        )
        thread.daemon = True
        thread.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

class StreamReceiver:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('StreamReceiver')

        # Initialize encryption
        self.cipher = Fernet(config['key'].encode())

        # Frame buffer (circular buffer)
        self.frame_buffer = deque(maxlen=config['buffer_size'])
        self.buffer_lock = threading.Lock()

        # Fragment reassembly buffer
        self.fragment_buffer = defaultdict(dict)
        self.fragment_metadata = {}
        self.fragment_timestamps = {}

        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_decrypted': 0,
            'frames_buffered': 0,
            'decryption_errors': 0,
            'fragments_received': 0,
            'frames_reassembled': 0,
            'incomplete_frames': 0
        }

        # UDP socket
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
        self.udp_sock.bind((config['udp_host'], config['udp_port']))

        # Cleanup thread for old fragments
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_fragments, daemon=True)
        self.cleanup_thread.start()

    def cleanup_old_fragments(self):
        """Background thread to clean up old incomplete fragments"""
        while True:
            time.sleep(30)
            current_time = time.time()

            old_seqs = []
            for seq_num, timestamp in self.fragment_timestamps.items():
                if current_time - timestamp > 10:
                    old_seqs.append(seq_num)

            for seq_num in old_seqs:
                if seq_num in self.fragment_buffer:
                    del self.fragment_buffer[seq_num]
                if seq_num in self.fragment_metadata:
                    del self.fragment_metadata[seq_num]
                del self.fragment_timestamps[seq_num]
                self.stats['incomplete_frames'] += 1

    def reassemble_frame(self, sequence_number):
        """Reassemble frame from fragments"""
        fragments = self.fragment_buffer.get(sequence_number, {})
        total_frags = self.fragment_metadata.get(sequence_number, 0)

        if len(fragments) == total_frags and total_frags > 0:
            try:
                frame_data = b''.join([fragments[i] for i in range(total_frags)])

                del self.fragment_buffer[sequence_number]
                del self.fragment_metadata[sequence_number]
                del self.fragment_timestamps[sequence_number]

                return frame_data
            except Exception as e:
                self.logger.error(f"Frame {sequence_number}: Error reassembling: {e}")
                return None
        return None

    def udp_receiver(self):
        """Background thread to receive UDP packets"""
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.stats['packets_received'] += 1

                try:
                    decrypted_data = self.cipher.decrypt(data)
                    self.stats['packets_decrypted'] += 1
                except Exception as e:
                    self.stats['decryption_errors'] += 1
                    continue

                if len(decrypted_data) < 8:
                    continue

                header = decrypted_data[:16]
                sequence_number, frag_index, total_frags = struct.unpack('>QII', header)
                fragment_data = decrypted_data[16:]

                self.stats['fragments_received'] += 1

                self.fragment_buffer[sequence_number][frag_index] = fragment_data
                self.fragment_metadata[sequence_number] = total_frags
                self.fragment_timestamps[sequence_number] = time.time()

                frame_data = self.reassemble_frame(sequence_number)

                if frame_data:
                    nparr = np.frombuffer(frame_data, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

                    if frame is not None:
                        with self.buffer_lock:
                            self.frame_buffer.append((sequence_number, frame))
                            self.stats['frames_buffered'] += 1
                            self.stats['frames_reassembled'] += 1

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

    def start(self):
        """Start the receiver"""
        udp_thread = threading.Thread(target=self.udp_receiver, daemon=True)
        udp_thread.start()
        return udp_thread

class StreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Disable default logging

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.serve_index()
        elif self.path == '/stream':
            self.serve_stream()
        elif self.path == '/stats':
            self.serve_stats()
        else:
            self.send_error(404)

    def serve_index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        html = """
        <html>
            <head>
                <title>Data Diode Stream</title>
            </head>
            <body>
                <h1>Data Diode Stream</h1>
                <img src="/stream" width="800" height="450" />
                <p><a href="/stats">Statistics</a></p>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

    def serve_stream(self):
        self.send_response(200)
        self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=frame')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        last_seq = -1
        while not self.wfile.closed:
            frame = None
            current_seq = -1

            with self.server.receiver.buffer_lock:
                if self.server.receiver.frame_buffer:
                    current_seq, frame = self.server.receiver.frame_buffer[-1]

            if frame is not None and current_seq != last_seq:
                frame_resized = cv2.resize(frame, (800, 450))
                _, buffer = cv2.imencode('.jpg', frame_resized, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
                frame_data = buffer.tobytes()

                try:
                    self.wfile.write(b'--frame\r\n')
                    self.send_header('Content-type', 'image/jpeg')
                    self.send_header('Content-length', str(len(frame_data)))
                    self.end_headers()
                    self.wfile.write(frame_data)
                    self.wfile.write(b'\r\n')
                    self.wfile.flush()
                except:
                    break

                last_seq = current_seq

            time.sleep(0.05)

    def serve_stats(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        import json
        stats_json = json.dumps(self.server.receiver.stats, indent=2)
        self.wfile.write(stats_json.encode())

def main():
    parser = argparse.ArgumentParser(description='Data Diode Receiver')
    parser.add_argument('--udp-host', default='0.0.0.0', help='UDP host to listen on')
    parser.add_argument('--udp-port', type=int, required=True, help='UDP port to listen on')
    parser.add_argument('--http-host', default='127.0.0.1', help='HTTP host to serve on')
    parser.add_argument('--http-port', type=int, required=True, help='HTTP port to serve on')
    parser.add_argument('--key', required=True, help='Base64 encoded encryption key')
    parser.add_argument('--buffer-size', type=int, default=100, help='Frame buffer size')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Configuration
    config = {
        'udp_host': args.udp_host,
        'udp_port': args.udp_port,
        'key': args.key,
        'buffer_size': args.buffer_size
    }

    # Initialize receiver
    receiver = StreamReceiver(config)

    # Start UDP receiver
    receiver.start()

    # Start HTTP server with threading
    http_server = ThreadingHTTPServer((args.http_host, args.http_port), StreamHandler)
    http_server.receiver = receiver

    print(f"HTTP server starting on {args.http_host}:{args.http_port}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        receiver.udp_sock.close()

if __name__ == "__main__":
    main()
