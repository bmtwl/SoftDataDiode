import socket
import threading
import argparse
import logging
import time
import struct
import json
import os
import base64
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.fernet import Fernet

# Embedded favicon (BASE64 encoded 16x16 ICO file)
FAVICON_ICO = """
AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAACMuAAAjLgAAAAAAAAAAAAD/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////9vb2/+Dg4P/9/f3//////////////////v7+//7+/v///////////////////////////////////////////+Dg4P89PT3/goKC/+bm5v///////v7+/5KSkv+SkpL//v7+/////////////////////////////v7+///////f39//Hh4e/wAAAP8yMjL/oqKi//Hx8f9WVlb/VlZW//39/f/+/v7//v7+//7+/v///////v7+/5OTk/9UVFT/TExM/woKCv8AAAD/AAAA/wcHB/88PDz/Hh4e/x0dHf9WVlb/VlZW/1NTU/+Tk5P//v7+//7+/v+Tk5P/VFRU/0xMTP8KCgr/AAAA/wAAAP8HBwf/PDw8/x4eHv8dHR3/VlZW/1ZWVv9TU1P/k5OT//7+/v///////v7+///////f39//Hh4e/wAAAP8yMjL/oqKi//Hx8f9WVlb/VlZW//39/f/+/v7//v7+//7+/v//////////////////////4ODg/z09Pf+CgoL/5ubm///////+/v7/kpKS/5KSkv/+/v7///////////////////////////////////////b29v/g4OD//f39//////////////////7+/v/+/v7/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
"""

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
    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug
        self.logger = self.setup_logging(debug)

        # Parse resolution if present
        self.display_resolution = None
        if 'display_resolution' in config:
            self.display_resolution = self.parse_resolution(config['display_resolution'])
            # Only import Pillow if we need resizing
            from PIL import Image
            import io

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

        # Freshness tracking
        self.last_frame_timestamp = 0
        self.freshness_lock = threading.Lock()

        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_decrypted': 0,
            'frames_buffered': 0,
            'decryption_errors': 0,
            'fragments_received': 0,
            'frames_reassembled': 0,
            'incomplete_frames': 0,
            'bytes_received': 0
        }

        # UDP socket
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
        self.udp_sock.bind((config['udp_host'], config['udp_port']))
        self.logger.info(f"Listening on {config['udp_host']}:{config['udp_port']}")

        # Cleanup thread for old fragments
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_fragments, daemon=True)
        self.cleanup_thread.start()

    def parse_resolution(self, resolution_str):
        """Parse resolution string like '1280x720' into (width, height) tuple"""
        try:
            width, height = map(int, resolution_str.lower().split('x'))
            return (width, height)
        except Exception as e:
            self.logger.warning(f"Invalid resolution '{resolution_str}', using original size: {e}")
            return None

    def setup_logging(self, debug=False):
        """Setup logging configuration"""
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - StreamReceiver - %(levelname)s - %(message)s'
        )
        return logging.getLogger('StreamReceiver')

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

    def resize_jpeg(self, jpeg_bytes, target_size):
        """Resize JPEG bytes using Pillow"""
        try:
            img = Image.open(io.BytesIO(jpeg_bytes))
            img = img.resize(target_size, Image.Resampling.LANCZOS)
            output = io.BytesIO()
            img.save(output, format='JPEG', quality=80)
            return output.getvalue()
        except Exception as e:
            self.logger.error(f"Error resizing JPEG: {e}")
            return jpeg_bytes  # Return original on error

    def udp_receiver(self):
        """Background thread to receive UDP packets"""
        self.logger.info(f"Listening for UDP packets on {self.config['udp_host']}:{self.config['udp_port']}")

        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.stats['packets_received'] += 1
                self.stats['bytes_received'] += len(data)

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

                header = decrypted_data[:16]
                sequence_number, frag_index, total_frags = struct.unpack('>QII', header)
                fragment_data = decrypted_data[16:]

                self.stats['fragments_received'] += 1

                if self.debug:
                    self.logger.debug(f"Fragment: frame={sequence_number}, frag={frag_index}/{total_frags}, size={len(fragment_data)}")

                self.fragment_buffer[sequence_number][frag_index] = fragment_data
                self.fragment_metadata[sequence_number] = total_frags
                self.fragment_timestamps[sequence_number] = time.time()

                frame_data = self.reassemble_frame(sequence_number)

                if frame_data:
                    # Store JPEG bytes directly, no decoding
                    with self.buffer_lock:
                        self.frame_buffer.append((sequence_number, frame_data))
                        self.stats['frames_buffered'] += 1
                        self.stats['frames_reassembled'] += 1

                    # Update freshness timestamp
                    with self.freshness_lock:
                        self.last_frame_timestamp = time.time()

                    self.logger.debug(f"Frame {sequence_number}: Successfully reassembled and buffered")

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

    def get_freshness_status(self):
        """Get current freshness status"""
        with self.freshness_lock:
            if self.last_frame_timestamp == 0:
                return {"status": "red", "seconds": 999999}

            elapsed = time.time() - self.last_frame_timestamp
            if elapsed < 30:
                return {"status": "green", "seconds": elapsed}
            elif elapsed < 300:  # 5 minutes
                return {"status": "yellow", "seconds": elapsed}
            else:
                return {"status": "red", "seconds": elapsed}

    def start(self):
        """Start the receiver"""
        udp_thread = threading.Thread(target=self.udp_receiver, daemon=True)
        udp_thread.start()
        self.logger.info("UDP receiver thread started")
        return udp_thread

class StreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        self.server.receiver.logger.debug(f"{self.address_string()} - {format % args}")

    def handle(self):
        """Override handle to gracefully handle client disconnections"""
        try:
            super().handle()
        except (BrokenPipeError, ValueError, OSError) as e:
            # Client disconnected normally during streaming
            if hasattr(self.server, 'receiver') and self.server.receiver.debug:
                self.server.receiver.logger.debug(f"Client disconnected: {e}")
        except Exception as e:
            # Log other unexpected errors
            if hasattr(self.server, 'receiver'):
                self.server.receiver.logger.error(f"HTTP handler error: {e}")
        finally:
            try:
                self.wfile.close()
            except:
                pass

    def do_GET(self):
        # Favicon
        if self.path == '/favicon.ico':
            self.send_response(200)
            self.send_header('Content-type', 'image/x-icon')
            self.end_headers()

            # Decode and serve the embedded favicon
            try:
                favicon_data = base64.b64decode(FAVICON_ICO)
                self.wfile.write(favicon_data)
            except:
                # If base64 decode fails, serve as raw data
                self.wfile.write(FAVICON_ICO.encode())
            return

        if self.path == '/' or self.path == '/index.html':
            self.serve_index()
        elif self.path == '/stream':
            self.serve_stream()
        elif self.path == '/freshness':
            self.serve_freshness()
        elif self.path == '/stats':
            self.serve_stats()
        else:
            self.send_error(404)

    def serve_index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Get display resolution for img tag
        width = height = ""
        if self.server.receiver.display_resolution:
            width = f'width="{self.server.receiver.display_resolution[0]}"'
            height = f'height="{self.server.receiver.display_resolution[1]}"'

        html = f"""
        <html>
            <head>
                <title>Data Diode Stream</title>
                <link rel="icon" type="image/x-icon" href="/favicon.ico">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
                    .header {{ background: #007cba; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; }}
                    .freshness-indicator {{ display: flex; align-items: center; }}
                    .status-circle {{ width: 15px; height: 15px; border-radius: 50%; margin-right: 8px; }}
                    .green {{ background-color: #4CAF50; }}
                    .yellow {{ background-color: #FFC107; }}
                    .red {{ background-color: #F44336; }}
                    .freshness-text {{ color: white; font-size: 0.9em; min-width: 120px; }}
                    img {{ border: 1px solid #ddd; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    .stats-link {{ display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 3px; }}
                    .stats-link:hover {{ background: #005a87; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <div>
                        <h1>Data Diode Stream</h1>
                    </div>
                    <div class="freshness-indicator">
                        <div class="status-circle red" id="circle-status"></div>
                        <div class="freshness-text" id="text-status">No data</div>
                    </div>
                </div>
                <img id="mjpeg-stream" src="/stream" {width} {height} style="display: none;" />

                <script>
                    // Self-invoking function to manage stream
                    (function() {{
                        const mjpegImg = document.getElementById('mjpeg-stream');
                        const streamUrl = '/stream';
                        let abortController = null;

                        // Function to pause the stream - actually closes HTTP connection
                        function pauseStream() {{
                            if (abortController) {{
                                abortController.abort();  // This actually closes the connection
                                abortController = null;
                                mjpegImg.style.display = 'none';
                                console.log('Stream paused - connection closed.');
                            }}
                        }}

                        // Function to resume the stream
                        function resumeStream() {{
                            if (!abortController) {{
                                abortController = new AbortController();
                                mjpegImg.style.display = 'block';
                                mjpegImg.src = streamUrl;
                                console.log('Stream resumed.');
                            }}
                        }}

                        // Listen for visibility changes
                        document.addEventListener('visibilitychange', function() {{
                            if (document.hidden) {{
                                pauseStream();
                            }} else {{
                                resumeStream();
                            }}
                        }});

                        // Start stream on page load
                        resumeStream();
                    }})();

                    // Freshness updates
                    function updateFreshness() {{
                        fetch('/freshness')
                            .then(response => response.json())
                            .then(data => {{
                                const circle = document.getElementById('circle-status');
                                const text = document.getElementById('text-status');

                                circle.className = `status-circle ${{data.status}}`;

                                if (data.status === 'green') {{
                                    text.textContent = 'Live';
                                }} else if (data.status === 'yellow') {{
                                    const minutes = Math.floor(data.seconds / 60);
                                    const seconds = Math.floor(data.seconds % 60);
                                    if (minutes > 0) {{
                                        text.textContent = `${{minutes}}m ${{seconds}}s ago`;
                                    }} else {{
                                        text.textContent = `${{seconds}}s ago`;
                                    }}
                                }} else {{
                                    text.textContent = 'Stale';
                                }}
                            }})
                            .catch(error => {{
                                console.error('Error updating freshness:', error);
                            }});
                    }}

                    // Update every 2 seconds
                    setInterval(updateFreshness, 2000);
                    updateFreshness();
                </script>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

    def serve_freshness(self):
        """Serve freshness status as JSON"""
        freshness = self.server.receiver.get_freshness_status()

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(freshness).encode())

    def serve_stats(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        stats_json = json.dumps(self.server.receiver.stats, indent=2)
        self.wfile.write(stats_json.encode())

    def _write_frame(self, frame_data):
        """Helper method to write a frame with proper error handling"""
        try:
            if self.wfile.closed:
                raise ValueError("I/O operation on closed file")

            self.wfile.write(b'--frame\r\n')
            self.wfile.write(b'Content-Type: image/jpeg\r\n')
            self.wfile.write(f'Content-Length: {len(frame_data)}\r\n\r\n'.encode())
            self.wfile.write(frame_data)
            self.wfile.write(b'\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ValueError, OSError):
            raise  # Re-raise to be caught by caller

    def serve_stream(self):
        """Stream video directly in the request handler (blocking but in separate thread)"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=frame')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()

            # Initialize with -1 to ensure first frame is sent immediately
            last_seq = -1

            # Send the most recent frame immediately if available
            with self.server.receiver.buffer_lock:
                if self.server.receiver.frame_buffer:
                    current_seq, frame_data = self.server.receiver.frame_buffer[-1]
                    if frame_data:
                        # Resize if needed
                        if self.server.receiver.display_resolution:
                            frame_data = self.server.receiver.resize_jpeg(frame_data, self.server.receiver.display_resolution)

                        try:
                            # Send as first frame in multipart stream (twice to satisfy Chrome/Edge/Webkit)
                            frames_to_send = 2
                            for i in range(frames_to_send):
                                self._write_frame(frame_data)
                            last_seq = current_seq
                        except (BrokenPipeError, ValueError, OSError):
                            # Client disconnected during initial send
                            return

            while True:  # More reliable than checking wfile.closed
                frame_data = None
                current_seq = -1

                with self.server.receiver.buffer_lock:
                    if self.server.receiver.frame_buffer:
                        current_seq, frame_data = self.server.receiver.frame_buffer[-1]

                if frame_data and current_seq != last_seq:
                    # Resize if needed
                    if self.server.receiver.display_resolution:
                        frame_data = self.server.receiver.resize_jpeg(frame_data, self.server.receiver.display_resolution)

                    try:
                        self._write_frame(frame_data)
                    except (BrokenPipeError, ValueError, OSError) as e:
                        # Client disconnected or connection closed
                        if self.server.receiver.debug:
                            self.server.receiver.logger.debug(f"Client disconnected: {e}")
                        break

                    last_seq = current_seq
                    if self.server.receiver.debug:
                        self.server.receiver.logger.debug(f"Streamed frame {current_seq}")

                time.sleep(0.05)  # Limit to ~20 FPS
        except Exception as e:
            self.server.receiver.logger.error(f"Error streaming: {e}")
        finally:
            # Mark connection as handled to prevent double-flush
            self.close_connection = True
            try:
                if hasattr(self, 'wfile') and not self.wfile.closed:
                    self.wfile.close()
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description='Data Diode Receiver')
    parser.add_argument('--udp-host', default='0.0.0.0', help='UDP host to listen on')
    parser.add_argument('--udp-port', type=int, required=True, help='UDP port to listen on')
    parser.add_argument('--http-host', default='127.0.0.1', help='HTTP host to serve on')
    parser.add_argument('--http-port', type=int, required=True, help='HTTP port to serve on')
    parser.add_argument('--key', required=True, help='Base64 encoded encryption key')
    parser.add_argument('--buffer-size', type=int, default=2, help='Frame buffer size')
    parser.add_argument('--display-resolution', help='Display resolution (e.g., 1280x720)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Configuration
    config = {
        'udp_host': args.udp_host,
        'udp_port': args.udp_port,
        'key': args.key,
        'buffer_size': args.buffer_size
    }

    if args.display_resolution:
        config['display_resolution'] = args.display_resolution

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Initialize receiver
    receiver = StreamReceiver(config, debug=args.debug)

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
        http_server.shutdown()

if __name__ == "__main__":
    main()
