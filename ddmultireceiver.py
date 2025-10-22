import socket
import threading
import argparse
import logging
import time
import struct
import json
import os
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import cv2
import numpy as np
from cryptography.fernet import Fernet

class StreamReceiver:
    def __init__(self, name, config, debug=False):
        self.name = name
        self.config = config
        self.debug = debug
        self.logger = self.setup_logging(debug)

        # Initialize encryption
        try:
            self.cipher = Fernet(config['key'].encode())
            self.logger.debug("Encryption key validated")
        except Exception as e:
            self.logger.error(f"Invalid encryption key: {e}")
            raise

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
        self.logger.info(f"Stream '{name}' listening on {config['udp_host']}:{config['udp_port']}")

        # Cleanup thread for old fragments
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_fragments, daemon=True)
        self.cleanup_thread.start()

    def setup_logging(self, debug=False):
        """Setup logging configuration"""
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format=f'%(asctime)s - {self.name} - %(levelname)s - %(message)s'
        )
        return logging.getLogger(self.name)

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
                if self.debug:
                    self.logger.debug(f"Cleaned up incomplete frame {seq_num}")

    def reassemble_frame(self, sequence_number):
        """Reassemble frame from fragments"""
        fragments = self.fragment_buffer.get(sequence_number, {})
        total_frags = self.fragment_metadata.get(sequence_number, 0)

        if self.debug:
            self.logger.debug(f"Frame {sequence_number}: {len(fragments)}/{total_frags} fragments received")

        if len(fragments) == total_frags and total_frags > 0:
            missing_frags = [i for i in range(total_frags) if i not in fragments]
            if missing_frags:
                self.logger.warning(f"Frame {sequence_number}: Missing fragments {missing_frags}")
                return None

            try:
                frame_data = b''.join([fragments[i] for i in range(total_frags)])

                del self.fragment_buffer[sequence_number]
                del self.fragment_metadata[sequence_number]
                del self.fragment_timestamps[sequence_number]

                self.logger.debug(f"Frame {sequence_number}: Successfully reassembled {len(frame_data)} bytes")
                return frame_data
            except Exception as e:
                self.logger.error(f"Frame {sequence_number}: Error reassembling: {e}")
                return None
        elif total_frags > 0:
            if self.debug:
                self.logger.debug(f"Frame {sequence_number}: Incomplete ({len(fragments)}/{total_frags})")

        return None

    def udp_receiver(self):
        """Background thread to receive UDP packets"""
        self.logger.info(f"Listening for UDP packets on {self.config['udp_host']}:{self.config['udp_port']}")

        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.stats['packets_received'] += 1

                if self.debug and self.stats['packets_received'] % 100 == 0:
                    self.logger.debug(f"Received packet {self.stats['packets_received']}: {len(data)} bytes from {addr}")

                try:
                    decrypted_data = self.cipher.decrypt(data)
                    self.stats['packets_decrypted'] += 1
                except Exception as e:
                    self.stats['decryption_errors'] += 1
                    self.logger.warning(f"Decryption failed for packet from {addr}: {e}")
                    continue

                if len(decrypted_data) < 8:
                    self.logger.warning("Packet too short to contain header")
                    continue

                header = decrypted_data[:8]
                sequence_number, frag_index, total_frags = struct.unpack('>IHH', header)
                fragment_data = decrypted_data[8:]

                self.stats['fragments_received'] += 1

                if self.debug:
                    self.logger.debug(f"Fragment: frame={sequence_number}, frag={frag_index}/{total_frags}, size={len(fragment_data)}")

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

                        self.logger.debug(f"Frame {sequence_number}: Successfully reassembled and buffered")
                    else:
                        self.logger.warning(f"Failed to decode frame {sequence_number}")

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

    def start(self):
        """Start the receiver"""
        udp_thread = threading.Thread(target=self.udp_receiver, daemon=True)
        udp_thread.start()
        self.logger.info("UDP receiver thread started")
        return udp_thread

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

class StreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        self.server.receiver.logger.info(f"{self.address_string()} - {format % args}")

    def do_GET(self):
        # Landing page
        if self.path == '/' or self.path == '':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            html = """
            <html>
                <head>
                    <title>Data Diode Streams</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; }
                        .stream { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                        .stream h3 { margin-top: 0; color: #333; }
                        .stream a { display: inline-block; margin: 5px; padding: 8px 15px; background: #007cba; color: white; text-decoration: none; border-radius: 3px; }
                        .stream a:hover { background: #005a87; }
                    </style>
                </head>
                <body>
                    <h1>Available Data Diode Streams</h1>
            """

            for stream_name, stream in self.server.receiver.streams.items():
                stream_config = self.server.receiver.config['streams'][stream_name]
                html += f"""
                    <div class="stream">
                        <h3>{stream_config['name']}</h3>
                        <p>{stream_config['description']}</p>
                        <p><strong>Path:</strong> /{stream_name}</p>
                        <a href="/{stream_name}">View Stream</a>
                    </div>
                """

            html += """
                </body>
            </html>
            """
            self.wfile.write(html.encode())

        # Individual stream pages - video streaming
        elif self.path.endswith('/stream'):
            stream_name = self.path[1:-7]  # Remove leading / and trailing /stream
            if stream_name in self.server.receiver.streams:
                self.stream_video(stream_name)
            else:
                self.send_error(404)

        elif self.path.endswith('/stats'):
            stream_name = self.path[1:-6]  # Remove leading / and trailing /stats
            if stream_name in self.server.receiver.streams:
                stream = self.server.receiver.streams[stream_name]
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                stats_json = json.dumps(stream.stats, indent=2)
                self.wfile.write(stats_json.encode())
            else:
                self.send_error(404)

        # Stream landing pages
        elif self.path[1:] in self.server.receiver.streams:  # Remove leading /
            stream_name = self.path[1:]
            stream_config = self.server.receiver.config['streams'][stream_name]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            html = f"""
            <html>
                <head>
                    <title>{stream_config['name']} - Data Diode Stream</title>
                </head>
                <body>
                    <h1>{stream_config['name']}</h1>
                    <p>{stream_config['description']}</p>
                    <img src="/{stream_name}/stream" width="800" height="450" />
                    <p><a href="/">Back to Streams</a></p>
                </body>
            </html>
            """
            self.wfile.write(html.encode())

        else:
            self.send_error(404)

    def stream_video(self, stream_name):
        """Stream video directly in the request handler (blocking but in separate thread)"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=frame')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()

            last_seq = -1
            while not self.wfile.closed:
                stream = self.server.receiver.streams[stream_name]
                frame = None
                current_seq = -1

                with stream.buffer_lock:
                    if stream.frame_buffer:
                        current_seq, frame = stream.frame_buffer[-1]

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
                    except Exception as e:
                        # Client disconnected
                        break

                    last_seq = current_seq
                    if stream.debug:
                        stream.logger.debug(f"Streamed frame {current_seq}")

                time.sleep(0.05)  # ~20 FPS
        except Exception as e:
            self.server.receiver.logger.error(f"Error streaming {stream_name}: {e}")
        finally:
            try:
                self.wfile.close()
            except:
                pass

class MultiStreamReceiver:
    def __init__(self, config_file):
        self.config_file = config_file
        self.logger = logging.getLogger('MultiStream')
        self.config = self.load_config()
        self.debug = self.config['server'].get('debug', False)

        # Create stream receivers
        self.streams = {}
        for stream_name, stream_config in self.config['streams'].items():
            try:
                self.streams[stream_name] = StreamReceiver(stream_name, stream_config, self.debug)
                self.logger.info(f"Initialized stream: {stream_name}")
            except Exception as e:
                self.logger.error(f"Failed to initialize stream {stream_name}: {e}")

        # HTTP server
        self.http_server = None

    def load_config(self):
        """Load configuration from JSON file"""
        if not os.path.exists(self.config_file):
            self.logger.error(f"Configuration file not found: {self.config_file}")
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            self.logger.info(f"Configuration loaded from {self.config_file}")
            return config
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise

    def setup_logging(self, debug=False):
        """Setup logging configuration"""
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - MultiStream - %(levelname)s - %(message)s'
        )
        return logging.getLogger('MultiStream')

    def start_all_streams(self):
        """Start all stream receivers"""
        threads = []
        for stream_name, stream in self.streams.items():
            try:
                thread = stream.start()
                threads.append((stream_name, thread))
                self.logger.info(f"Started stream receiver: {stream_name}")
            except Exception as e:
                self.logger.error(f"Failed to start stream {stream_name}: {e}")
        return threads

    def start_http_server(self):
        """Start HTTP server with threading support"""
        http_config = self.config['server']
        self.http_server = ThreadingHTTPServer((http_config['http_host'], http_config['http_port']), StreamHandler)
        self.http_server.receiver = self

        self.logger.info(f"HTTP server starting on {http_config['http_host']}:{http_config['http_port']}")
        self.http_server.serve_forever()

    def run(self):
        """Main run method"""
        # Start all stream receivers
        threads = self.start_all_streams()

        # Start HTTP server
        try:
            self.start_http_server()
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
        finally:
            # Close all UDP sockets
            for stream_name, stream in self.streams.items():
                stream.udp_sock.close()
            if self.http_server:
                self.http_server.shutdown()

def main():
    parser = argparse.ArgumentParser(description='Multi-Stream Data Diode Receiver')
    parser.add_argument('--config', default='config.json', help='Configuration file path (default: config.json)')

    args = parser.parse_args()

    try:
        receiver = MultiStreamReceiver(args.config)
        receiver.run()
    except Exception as e:
        print(f"Failed to start receiver: {e}")

if __name__ == "__main__":
    main()
