import socket
import threading
import argparse
import logging
import time
import struct
import json
import os
import hashlib
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler

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

class FileSyncReceiver:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('FileSyncReceiver')
        self.debug = config.get('debug', False)
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        # Initialize encryption
        self.cipher = Fernet(config['key'].encode())

        # Fragment reassembly buffer
        self.fragment_buffer = defaultdict(dict)
        self.fragment_metadata = {}
        self.fragment_timestamps = {}

        # File state tracking (to avoid rewriting unchanged files)
        self.file_state = {}  # path -> {mtime, checksum}

        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_decrypted': 0,
            'decryption_errors': 0,
            'fragments_received': 0,
            'files_received': 0,
            'files_written': 0,
            'files_skipped': 0,
            'incomplete_files': 0
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
                if current_time - timestamp > 60:  # Increased timeout for files
                    old_seqs.append(seq_num)

            for seq_num in old_seqs:
                if seq_num in self.fragment_buffer:
                    del self.fragment_buffer[seq_num]
                if seq_num in self.fragment_metadata:
                    del self.fragment_metadata[seq_num]
                del self.fragment_timestamps[seq_num]
                self.stats['incomplete_files'] += 1
                if self.debug:
                    self.logger.debug(f"Cleaned up incomplete file sequence {seq_num}")

    def calculate_file_checksum(self, filepath):
        """Calculate SHA256 checksum of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating checksum for {filepath}: {e}")
            return None

    def should_write_file(self, file_info, file_data):
        """Check if file should be written (not same as existing)"""
        target_path = os.path.join(self.config['output_dir'], file_info['path'])

        # Check if file exists
        if not os.path.exists(target_path):
            return True

        # Check modification time
        existing_mtime = os.path.getmtime(target_path)
        if existing_mtime != file_info['mtime']:
            return True

        # Check checksum
        existing_checksum = self.calculate_file_checksum(target_path)
        if existing_checksum != file_info['checksum']:
            return True

        return False

    def write_file(self, file_info, file_data):
        """Write file to disk"""
        try:
            target_path = os.path.join(self.config['output_dir'], file_info['path'])

            # Create directory structure if needed
            target_dir = os.path.dirname(target_path)
            if target_dir and not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)
                if self.debug:
                    self.logger.debug(f"Created directory: {target_dir}")

            # Check if we should write the file
            if not self.should_write_file(file_info, file_data):
                self.stats['files_skipped'] += 1
                if self.debug:
                    self.logger.debug(f"Skipped unchanged file: {file_info['path']}")
                return True

            # Write file
            with open(target_path, 'wb') as f:
                f.write(file_data)

            # Set modification time to match source
            os.utime(target_path, (file_info['mtime'], file_info['mtime']))

            # Update file state tracking
            self.file_state[file_info['path']] = {
                'mtime': file_info['mtime'],
                'checksum': file_info['checksum']
            }

            self.stats['files_written'] += 1
            self.logger.info(f"Wrote file: {file_info['path']} ({len(file_data)} bytes)")
            return True

        except Exception as e:
            self.logger.error(f"Error writing file {file_info['path']}: {e}")
            return False

    def reassemble_data(self, sequence_number):
        """Reassemble data from fragments"""
        fragments = self.fragment_buffer.get(sequence_number, {})
        total_frags = self.fragment_metadata.get(sequence_number, 0)

        if len(fragments) == total_frags and total_frags > 0:
            try:
                data = b''.join([fragments[i] for i in range(total_frags)])

                del self.fragment_buffer[sequence_number]
                del self.fragment_metadata[sequence_number]
                del self.fragment_timestamps[sequence_number]

                return data
            except Exception as e:
                self.logger.error(f"Sequence {sequence_number}: Error reassembling: {e}")
                return None
        return None

    def process_filesync_metadata(self, data):
        """Process filesync metadata packet"""
        try:
            # Remove packet type identifier
            json_data = data[len(b'FILESYNC_METADATA'):].decode('utf-8')
            sync_data = json.loads(json_data)

            self.logger.info(f"Received sync metadata with {len(sync_data.get('files', []))} files")
            if self.debug:
                self.logger.debug(f"Sync data: {sync_data}")

        except Exception as e:
            self.logger.error(f"Error processing filesync metadata: {e}")

    def process_file_content(self, data):
        """Process file content packet"""
        try:
            # Remove packet type identifier
            content_data = data[len(b'FILE_CONTENT'):]

            # Split header and file data at null terminator
            null_pos = content_data.find(b'\x00')
            if null_pos == -1:
                self.logger.error("Invalid file content packet: missing null terminator")
                return

            header_data = content_data[:null_pos]
            file_data = content_data[null_pos+1:]

            # Parse file info
            file_info = json.loads(header_data.decode('utf-8'))

            # Write file
            if self.write_file(file_info, file_data):
                self.stats['files_received'] += 1
            else:
                self.logger.error(f"Failed to write file: {file_info['path']}")

        except Exception as e:
            self.logger.error(f"Error processing file content: {e}")

    def udp_receiver(self):
        """Background thread to receive UDP packets"""
        self.logger.info(f"UDP receiver listening on {self.config['udp_host']}:{self.config['udp_port']}")

        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self.stats['packets_received'] += 1

                try:
                    decrypted_data = self.cipher.decrypt(data)
                    self.stats['packets_decrypted'] += 1
                except Exception as e:
                    self.stats['decryption_errors'] += 1
                    if self.debug:
                        self.logger.debug(f"Decryption error: {e}")
                    continue

                if len(decrypted_data) < 16:
                    continue

                header = decrypted_data[:16]
                sequence_number, frag_index, total_frags = struct.unpack('>QII', header)
                fragment_data = decrypted_data[16:]

                self.stats['fragments_received'] += 1

                self.fragment_buffer[sequence_number][frag_index] = fragment_data
                self.fragment_metadata[sequence_number] = total_frags
                self.fragment_timestamps[sequence_number] = time.time()

                # Try to reassemble data
                reassembled_data = self.reassemble_data(sequence_number)

                if reassembled_data:
                    # Check packet type
                    if reassembled_data.startswith(b'FILESYNC_METADATA'):
                        self.process_filesync_metadata(reassembled_data)
                    elif reassembled_data.startswith(b'FILE_CONTENT'):
                        self.process_file_content(reassembled_data)
                    else:
                        self.logger.warning(f"Unknown packet type in sequence {sequence_number}")

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

    def start(self):
        """Start the receiver"""
        udp_thread = threading.Thread(target=self.udp_receiver, daemon=True)
        udp_thread.start()
        return udp_thread

class StatsHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Disable default logging

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.serve_index()
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
                <title>Data Diode File Sync Receiver</title>
            </head>
            <body>
                <h1>Data Diode File Sync Receiver</h1>
                <p>File synchronization receiver is running.</p>
                <p><a href="/stats">Statistics</a></p>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

    def serve_stats(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        import json
        stats_json = json.dumps(self.server.receiver.stats, indent=2)
        self.wfile.write(stats_json.encode())

def main():
    parser = argparse.ArgumentParser(description='Data Diode File Sync Receiver')
    parser.add_argument('--udp-host', default='0.0.0.0', help='UDP host to listen on')
    parser.add_argument('--udp-port', type=int, required=True, help='UDP port to listen on')
    parser.add_argument('--http-host', default='127.0.0.1', help='HTTP host to serve on')
    parser.add_argument('--http-port', type=int, required=True, help='HTTP port to serve on')
    parser.add_argument('--key', required=True, help='Base64 encoded encryption key')
    parser.add_argument('--output-dir', required=True, help='Output directory for synchronized files')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    # Validate output directory
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir, exist_ok=True)
        print(f"Created output directory: {args.output_dir}")
    elif not os.path.isdir(args.output_dir):
        print(f"Error: Output path exists but is not a directory: {args.output_dir}")
        return

    # Configuration
    config = {
        'udp_host': args.udp_host,
        'udp_port': args.udp_port,
        'key': args.key,
        'output_dir': args.output_dir,
        'debug': args.debug
    }

    # Initialize receiver
    receiver = FileSyncReceiver(config)

    # Start UDP receiver
    receiver.start()

    # Start HTTP server with threading
    http_server = ThreadingHTTPServer((args.http_host, args.http_port), StatsHandler)
    http_server.receiver = receiver

    print(f"File Sync Receiver starting...")
    print(f"UDP listening on {args.udp_host}:{args.udp_port}")
    print(f"HTTP server on {args.http_host}:{args.http_port}")
    print(f"Output directory: {args.output_dir}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        receiver.udp_sock.close()

if __name__ == "__main__":
    main()
