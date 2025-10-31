import cv2
import numpy as np
import socket
import time
import argparse
import struct
import math
import shutil
import os
import hashlib
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

def setup_logging(debug=False):
    """Setup logging configuration"""
    import logging
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('DataDiodeSender')

def create_webdriver():
    """Create headless Chrome webdriver for screenshots"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1280,720")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--disable-features=VizDisplayCompositor")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])  # Suppress logging
    chrome_options.add_experimental_option('useAutomationExtension', False)

    driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(30)
    return driver

def parse_resolution(resolution_str):
    """Parse resolution string like '1280x720' into (width, height) tuple"""
    try:
        width, height = map(int, resolution_str.lower().split('x'))
        return (width, height)
    except Exception as e:
        print(f"Invalid resolution '{resolution_str}', using default 1280x720: {e}")
        return (1280, 720)

def capture_webpage(url, driver, username=None, password=None, timeout=30, element_selector="body", capture_resolution=(1280, 720)):
    """Capture screenshot of webpage with optional authentication and element selection"""
    logger = setup_logging(False)  # Create logger for this function

    try:
        # Handle authentication if provided
        if username and password:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            if not parsed.username:
                netloc = f"{username}:{password}@{parsed.netloc}"
                auth_url = urlunparse((
                    parsed.scheme, netloc, parsed.path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                logger.debug(f"Using authenticated URL: {auth_url}")
                driver.get(auth_url)
            else:
                driver.get(url)
        else:
            driver.get(url)

        # Wait for page to load
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        # Wait a bit more for dynamic content
        time.sleep(2)

        # Set window size to capture resolution
        driver.set_window_size(capture_resolution[0], capture_resolution[1])

        # Find and capture specific element or full page
        if element_selector and element_selector != "body":
            try:
                element = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, element_selector))
                )
                screenshot = element.screenshot_as_png
                logger.debug(f"Captured element '{element_selector}': {len(screenshot)} bytes")
            except Exception as e:
                logger.warning(f"Element '{element_selector}' not found, capturing full page: {e}")
                screenshot = driver.get_screenshot_as_png()
        else:
            screenshot = driver.get_screenshot_as_png()
            logger.debug(f"Captured full page: {len(screenshot)} bytes")

        # Convert to OpenCV image
        nparr = np.frombuffer(screenshot, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is not None:
            logger.debug(f"Captured webpage screenshot: {img.shape}")
        else:
            logger.error("Failed to decode screenshot")

        return img

    except TimeoutException:
        logger.error(f"Timeout waiting for page to load: {url}")
        return None
    except Exception as e:
        logger.error(f"Error capturing webpage: {e}")
        return None

def capture_rtsp_stream(rtsp_url, username=None, password=None, capture_resolution=(1280, 720)):
    """Capture frame from RTSP stream with optional authentication"""
    logger = setup_logging(False)  # Create logger for this function

    try:
        if username and password:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(rtsp_url)
            if not parsed.username:
                netloc = f"{username}:{password}@{parsed.netloc}"
                auth_url = urlunparse((
                    parsed.scheme, netloc, parsed.path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                logger.debug(f"Using authenticated RTSP URL: {auth_url}")
                cap = cv2.VideoCapture(auth_url)
            else:
                cap = cv2.VideoCapture(rtsp_url)
        else:
            cap = cv2.VideoCapture(rtsp_url)

        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, capture_resolution[0])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, capture_resolution[1])

        ret, frame = cap.read()
        cap.release()

        if ret:
            frame = cv2.resize(frame, capture_resolution)
            logger.debug(f"Captured RTSP frame: {frame.shape}")
            return frame
        else:
            logger.error("Failed to capture RTSP frame")
            return None

    except Exception as e:
        logger.error(f"Error capturing RTSP stream: {e}")
        return None

def capture_vnc_display(vnc_host, vnc_password=None, vnc_display=0, capture_resolution=(1280, 720)):
    """Capture frame from VNC display"""
    logger = setup_logging(False)  # Create logger for this function

    try:
        # For now, we'll use a simple approach with subprocess to capture VNC with vncsnapshot
        import subprocess
        import tempfile
        import os

        # Create temporary file for screenshot
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp_file:
            tmp_filename = tmp_file.name

        try:
            # Build VNC connection string
            vnc_url = f"{vnc_host}:{vnc_display}"

            # Use vncsnapshot capture tool
            commands = [
                ['vncsnapshot', '-passwd', vnc_password, vnc_url, tmp_filename],
            ]

            success = False
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                    if result.returncode == 0:
                        success = True
                        break
                except subprocess.TimeoutExpired:
                    logger.warning(f"VNC capture command timed out: {' '.join(cmd)}")
                except Exception as e:
                    logger.debug(f"VNC capture command failed: {' '.join(cmd)} - {e}")

            if success and os.path.exists(tmp_filename) and os.path.getsize(tmp_filename) > 0:
                # Read the captured image
                img = cv2.imread(tmp_filename)
                if img is not None:
                    img = cv2.resize(img, capture_resolution)
                    logger.debug(f"Captured VNC frame: {img.shape}")
                    return img
                else:
                    logger.error("Failed to read VNC screenshot")
            else:
                logger.error("VNC capture failed or produced empty file")

        except Exception as e:
            logger.error(f"Error capturing VNC display: {e}")
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_filename):
                os.unlink(tmp_filename)

        return None

    except Exception as e:
        logger.error(f"Error capturing VNC display: {e}")
        return None

def calculate_file_checksum(filepath):
    """Calculate SHA256 checksum of a file"""
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_file_info(filepath, base_path, preserve_path):
    """Get file information for transmission"""
    stat = os.stat(filepath)

    # Calculate relative path
    if os.path.isfile(base_path):
        # Special case: single file sync
        relative_path = os.path.basename(filepath)
    else:
        # Directory sync
        relative_path = os.path.relpath(filepath, base_path)

    # Handle path preservation
    if preserve_path:
        # Send full path from root
        send_path = filepath[1:] if filepath.startswith('/') else filepath
    else:
        # Send relative path (residual structure)
        send_path = relative_path

    return {
        'path': send_path,
        'size': stat.st_size,
        'mtime': int(stat.st_mtime),
        'checksum': calculate_file_checksum(filepath)
    }

def scan_files_for_sync(sync_path, max_file_age_hours, include_dot_files):
    """Scan files for synchronization based on criteria"""
    logger = setup_logging(False)
    files_to_sync = []

    # Check if path starts at root
    if not sync_path.startswith('/'):
        logger.error(f"Path must start at root: {sync_path}")
        return files_to_sync

    # Convert max age to timestamp
    if max_file_age_hours > 0:
        cutoff_time = time.time() - (max_file_age_hours * 3600)
    else:
        cutoff_time = 0

    if os.path.isfile(sync_path):
        # Single file case
        stat = os.stat(sync_path)
        if max_file_age_hours <= 0 or stat.st_mtime > cutoff_time:
            if include_dot_files or not os.path.basename(sync_path).startswith('.'):
                files_to_sync.append(sync_path)
    elif os.path.isdir(sync_path):
        # Directory case
        for root, dirs, files in os.walk(sync_path):
            # Filter directories (remove dot directories if needed)
            if not include_dot_files:
                dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if not include_dot_files and file.startswith('.'):
                    continue

                filepath = os.path.join(root, file)
                stat = os.stat(filepath)

                # Check age filter
                if max_file_age_hours > 0 and stat.st_mtime < cutoff_time:
                    continue

                files_to_sync.append(filepath)
    else:
        logger.error(f"Path does not exist: {sync_path}")

    return files_to_sync

def capture_filesync(sync_path, max_file_age_hours=0, include_dot_files=False, preserve_path=False):
    """Capture files for synchronization"""
    logger = setup_logging(False)

    # Validate path starts at root
    if not sync_path.startswith('/'):
        logger.error(f"Path must start at root: {sync_path}")
        return None

    # Determine base path
    if os.path.isfile(sync_path):
        base_path = os.path.dirname(sync_path)
    else:
        base_path = sync_path

    # Scan for files
    files = scan_files_for_sync(sync_path, max_file_age_hours, include_dot_files)

    if not files:
        logger.debug("No files found for sync")
        return None

    # Create sync data structure
    sync_data = {
        'base_path': base_path,
        'preserve_path': preserve_path,
        'files': []
    }

    for filepath in files:
        try:
            file_info = get_file_info(filepath, base_path, preserve_path)
            sync_data['files'].append(file_info)
            logger.debug(f"Added file for sync: {file_info['path']} ({file_info['size']} bytes)")
        except Exception as e:
            logger.error(f"Error processing file {filepath}: {e}")

    return sync_data

def send_frame_fragmented(frame, cipher, sock, cloud_ip, cloud_port, sequence_number, max_packet_size=1400, jpeg_quality=60):
    """Encrypt and send frame via UDP with fragmentation"""
    logger = setup_logging(False)  # Create logger for this function

    if frame is None:
        logger.debug("Skipping null frame")
        return

    try:
        # Encode frame to JPEG with quality control
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality]  # Configurable Quality
        _, buffer = cv2.imencode('.jpg', frame, encode_param)
        data = buffer.tobytes()

        # Calculate safe payload size accounting for encryption overhead
        header_size = 16  # 8 bytes seq + 4 bytes frag_index + 4 bytes total_frags
        fernet_overhead = 450  # Approximate Fernet overhead
        safe_payload_size = max_packet_size - header_size - fernet_overhead

        if safe_payload_size <= 0:
            logger.error(f"Packet size too small: max={max_packet_size}, header={header_size}, overhead={fernet_overhead}")
            return

        total_frags = math.ceil(len(data) / safe_payload_size)

        logger.debug(f"Frame {sequence_number}: {len(data)} bytes total, {total_frags} fragments needed, {safe_payload_size} safe payload bytes per fragment")

        # Fragment and send data
        fragments_sent = 0
        for frag_index in range(total_frags):
            start_pos = frag_index * safe_payload_size
            end_pos = min((frag_index + 1) * safe_payload_size, len(data))
            fragment_data = data[start_pos:end_pos]

            # Create header: sequence_number(8) + frag_index(4) + total_frags(4)
            header = struct.pack('>QII', sequence_number, frag_index, total_frags)
            packet_data = header + fragment_data

            # Encrypt packet
            encrypted_packet = cipher.encrypt(packet_data)

            # Send via UDP
            try:
                sock.sendto(encrypted_packet, (cloud_ip, cloud_port))
                fragments_sent += 1
                if logger.isEnabledFor(10):  # DEBUG level
                    logger.debug(f"Sent fragment {frag_index+1}/{total_frags} for frame {sequence_number}, size: {len(encrypted_packet)} bytes")
            except Exception as e:
                logger.error(f"Failed to send fragment {frag_index} for frame {sequence_number}: {e}")
                break

        logger.debug(f"Frame {sequence_number}: Sent {fragments_sent}/{total_frags} fragments, total size: {len(data)} bytes")

    except Exception as e:
        logger.error(f"Error processing frame {sequence_number}: {e}")

def send_filesync_fragmented(sync_data, cipher, sock, cloud_ip, cloud_port, sequence_number, max_packet_size=1400):
    """Encrypt and send filesync data via UDP with fragmentation"""
    logger = setup_logging(False)

    if sync_data is None:
        logger.debug("Skipping null sync data")
        return

    try:
        # Convert sync data to JSON and encode
        json_data = json.dumps(sync_data, separators=(',', ':'))
        data = json_data.encode('utf-8')

        # Add packet type identifier
        packet_type = b'FILESYNC_METADATA'
        data = packet_type + data

        # Calculate safe payload size accounting for encryption overhead
        header_size = 16  # 8 bytes seq + 4 bytes frag_index + 4 bytes total_frags
        fernet_overhead = 450  # Approximate Fernet overhead
        safe_payload_size = max_packet_size - header_size - fernet_overhead

        if safe_payload_size <= 0:
            logger.error(f"Packet size too small: max={max_packet_size}, header={header_size}, overhead={fernet_overhead}")
            return

        total_frags = math.ceil(len(data) / safe_payload_size)

        logger.debug(f"Filesync {sequence_number}: {len(data)} bytes total, {total_frags} fragments needed")

        # Fragment and send data
        fragments_sent = 0
        for frag_index in range(total_frags):
            start_pos = frag_index * safe_payload_size
            end_pos = min((frag_index + 1) * safe_payload_size, len(data))
            fragment_data = data[start_pos:end_pos]

            # Create header: sequence_number(8) + frag_index(4) + total_frags(4)
            header = struct.pack('>QII', sequence_number, frag_index, total_frags)
            packet_data = header + fragment_data

            # Encrypt packet
            encrypted_packet = cipher.encrypt(packet_data)

            # Send via UDP
            try:
                sock.sendto(encrypted_packet, (cloud_ip, cloud_port))
                fragments_sent += 1
                if logger.isEnabledFor(10):  # DEBUG level
                    logger.debug(f"Sent fragment {frag_index+1}/{total_frags} for filesync {sequence_number}, size: {len(encrypted_packet)} bytes")
            except Exception as e:
                logger.error(f"Failed to send fragment {frag_index} for filesync {sequence_number}: {e}")
                break

        logger.debug(f"Filesync {sequence_number}: Sent {fragments_sent}/{total_frags} fragments, total size: {len(data)} bytes")

    except Exception as e:
        logger.error(f"Error processing filesync {sequence_number}: {e}")

def send_file_content_fragmented(filepath, file_info, cipher, sock, cloud_ip, cloud_port, sequence_number, max_packet_size=1400):
    """Send individual file content via UDP with fragmentation"""
    logger = setup_logging(False)

    try:
        # Read file content
        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Add packet type identifier and file info
        packet_type = b'FILE_CONTENT'
        file_info_json = json.dumps(file_info, separators=(',', ':'))
        header_data = packet_type + file_info_json.encode('utf-8') + b'\x00'  # Null terminator
        data = header_data + file_data

        # Calculate safe payload size accounting for encryption overhead
        header_size = 16  # 8 bytes seq + 4 bytes frag_index + 4 bytes total_frags
        fernet_overhead = 450  # Approximate Fernet overhead
        safe_payload_size = max_packet_size - header_size - fernet_overhead

        if safe_payload_size <= 0:
            logger.error(f"Packet size too small: max={max_packet_size}, header={header_size}, overhead={fernet_overhead}")
            return

        total_frags = math.ceil(len(data) / safe_payload_size)

        logger.debug(f"File {sequence_number}: {file_info['path']} ({len(data)} bytes total, {total_frags} fragments needed)")

        # Fragment and send data
        fragments_sent = 0
        for frag_index in range(total_frags):
            start_pos = frag_index * safe_payload_size
            end_pos = min((frag_index + 1) * safe_payload_size, len(data))
            fragment_data = data[start_pos:end_pos]

            # Create header: sequence_number(8) + frag_index(4) + total_frags(4)
            header = struct.pack('>QII', sequence_number, frag_index, total_frags)
            packet_data = header + fragment_data

            # Encrypt packet
            encrypted_packet = cipher.encrypt(packet_data)

            # Send via UDP
            try:
                sock.sendto(encrypted_packet, (cloud_ip, cloud_port))
                fragments_sent += 1
                if logger.isEnabledFor(10):  # DEBUG level
                    logger.debug(f"Sent fragment {frag_index+1}/{total_frags} for file {sequence_number}, size: {len(encrypted_packet)} bytes")
            except Exception as e:
                logger.error(f"Failed to send fragment {frag_index} for file {sequence_number}: {e}")
                break

        logger.debug(f"File {sequence_number}: Sent {fragments_sent}/{total_frags} fragments, total size: {len(data)} bytes")

    except Exception as e:
        logger.error(f"Error processing file {sequence_number} ({filepath}): {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Data Diode Sender',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""description:
Data diode sender for one-way transmission of data streams and files.

modes:
  web     - Capture webpage screenshots
  rtsp    - Capture RTSP video streams
  vnc     - Capture VNC desktop displays
  filesync - Synchronize directory contents
"""
    )

    # Global options
    global_group = parser.add_argument_group('global options')
    global_group.add_argument('--mode', choices=['web', 'rtsp', 'vnc', 'filesync'], required=True, help='Capture mode')
    global_group.add_argument('--cloud-ip', required=True, help='Cloud server IP')
    global_group.add_argument('--cloud-port', type=int, required=True, help='Cloud server UDP port')
    global_group.add_argument('--key', required=True, help='Base64 encoded encryption key')
    global_group.add_argument('--debug', action='store_true', help='Enable debug logging')
    global_group.add_argument('--max-packet-size', type=int, default=1400, help='Maximum UDP packet size (default: 1400)')

    # Web mode options
    web_group = parser.add_argument_group('web mode options')
    web_group.add_argument('--source', help='URL for web capture')
    web_group.add_argument('--username', help='Username for authentication')
    web_group.add_argument('--password', help='Password for authentication')
    web_group.add_argument('--timeout', type=int, default=30, help='Timeout for web page loading (seconds)')
    web_group.add_argument('--web-capture-element', default='body', help='CSS selector for web capture element (default: body)')

    # RTSP mode options
    rtsp_group = parser.add_argument_group('rtsp mode options')
    rtsp_group.add_argument('--rtsp-url', help='RTSP stream URL')

    # VNC mode options
    vnc_group = parser.add_argument_group('vnc mode options')
    vnc_group.add_argument('--vnc-host', help='VNC host')
    vnc_group.add_argument('--vnc-password', help='Password for VNC authentication')
    vnc_group.add_argument('--vnc-display', type=int, default=0, help='The VNC Display Number (default: 0)')

    # Filesync mode options
    filesync_group = parser.add_argument_group('filesync mode options')
    filesync_group.add_argument('--sync-path', help='Directory or file path to sync')
    filesync_group.add_argument('--preserve-path', action='store_true', help='Preserve full directory structure')
    filesync_group.add_argument('--include-dot-files', action='store_true', help='Include hidden dot files')
    filesync_group.add_argument('--max-file-age', type=float, default=0, help='Maximum file age in hours (0 = no limit)')
    filesync_group.add_argument('--sync-interval', type=float, default=60, help='Sync interval in seconds (default: 60)')

    # Common capture options
    capture_group = parser.add_argument_group('capture options')
    capture_group.add_argument('--capture-resolution', default='1280x720', help='Capture resolution (default: 1280x720)')
    capture_group.add_argument('--jpeg-quality', type=int, default=60, help='JPEG encoding quality 0-100 (default: 60)')
    capture_group.add_argument('--interval', type=float, default=0.1, help='Capture interval in seconds (web/rtsp/vnc)')

    args = parser.parse_args()

    logger = setup_logging(args.debug)
    logger.info(f"Starting Data Diode Sender in {args.mode} mode")

    try:
        cipher = Fernet(args.key.encode())
        logger.debug("Encryption key validated")
    except Exception as e:
        logger.error(f"Invalid encryption key: {e}")
        return

    # Parse capture resolution
    if args.mode in ['web', 'rtsp', 'vnc']:
        capture_resolution = parse_resolution(args.capture_resolution)
        logger.info(f"Capture resolution set to: {capture_resolution[0]}x{capture_resolution[1]}")

    # Validate JPEG encoding quality value
    if args.mode in ['web', 'rtsp', 'vnc'] and not (0 <= args.jpeg_quality <= 100):
        logger.error(f"Quality must be between 0 and 100, inclusive.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger.debug(f"UDP socket created for {args.cloud_ip}:{args.cloud_port}")

    sequence_number = 0

    try:
        if args.mode == 'web':
            if not args.source:
                logger.error("Web mode requires --source URL")
                return
            driver = create_webdriver()
            capture_func = lambda: capture_webpage(
                args.source, driver, args.username, args.password, args.timeout,
                args.web_capture_element, capture_resolution
            )
            logger.info(f"Web capture initialized for {args.source}")
            logger.info(f"Capturing element: {args.web_capture_element}")

            while True:
                frame = capture_func()
                if frame is not None:
                    logger.debug(f"Captured frame {sequence_number} with shape {frame.shape}")
                send_frame_fragmented(
                    frame, cipher, sock, args.cloud_ip, args.cloud_port,
                    sequence_number, args.max_packet_size, args.jpeg_quality
                )
                sequence_number += 1
                time.sleep(args.interval)

        elif args.mode == 'rtsp':
            if not args.rtsp_url:
                logger.error("RTSP mode requires --rtsp-url")
                return
            capture_func = lambda: capture_rtsp_stream(
                args.rtsp_url, args.username, args.password, capture_resolution
            )
            logger.info(f"RTSP capture initialized for {args.rtsp_url}")

            while True:
                frame = capture_func()
                if frame is not None:
                    logger.debug(f"Captured frame {sequence_number} with shape {frame.shape}")
                send_frame_fragmented(
                    frame, cipher, sock, args.cloud_ip, args.cloud_port,
                    sequence_number, args.max_packet_size, args.jpeg_quality
                )
                sequence_number += 1
                time.sleep(args.interval)

        elif args.mode == 'vnc':
            if not args.vnc_host:
                logger.error("VNC mode requires --vnc-host")
                return
            if shutil.which('vncsnapshot'):
                logger.debug(f"VNC Capture tool found") 
            else:
                logger.info(f"VNC Capture Tool vncsnapshot not found in path. Aborting!")
                return
            capture_func = lambda: capture_vnc_display(
                args.vnc_host, args.vnc_password, args.vnc_display, capture_resolution
            )
            logger.info(f"VNC capture initialized for {args.vnc_host}")

            while True:
                frame = capture_func()
                if frame is not None:
                    logger.debug(f"Captured frame {sequence_number} with shape {frame.shape}")
                send_frame_fragmented(
                    frame, cipher, sock, args.cloud_ip, args.cloud_port,
                    sequence_number, args.max_packet_size, args.jpeg_quality
                )
                sequence_number += 1
                time.sleep(args.interval)

        elif args.mode == 'filesync':
            if not args.sync_path:
                logger.error("Filesync mode requires --sync-path")
                return

            # Validate path starts at root
            if not args.sync_path.startswith('/'):
                logger.error(f"Sync path must start at root: {args.sync_path}")
                return

            logger.info(f"Filesync initialized for {args.sync_path}")
            logger.info(f"Preserve path: {args.preserve_path}")
            logger.info(f"Include dot files: {args.include_dot_files}")
            logger.info(f"Max file age: {args.max_file_age} hours")

            while True:
                # Capture sync metadata
                sync_data = capture_filesync(
                    args.sync_path, 
                    args.max_file_age, 
                    args.include_dot_files, 
                    args.preserve_path
                )

                if sync_data is not None:
                    logger.debug(f"Captured sync data with {len(sync_data['files'])} files")

                    # Send sync metadata
                    send_filesync_fragmented(
                        sync_data, cipher, sock, args.cloud_ip, args.cloud_port,
                        sequence_number, args.max_packet_size
                    )
                    sequence_number += 1

                    # Send individual file contents
                    base_path = sync_data['base_path']
                    for file_info in sync_data['files']:
                        # Reconstruct full file path
                        if os.path.isfile(args.sync_path):
                            filepath = args.sync_path
                        else:
                            # For directory sync, reconstruct path
                            if args.preserve_path:
                                # Path is from root
                                filepath = '/' + file_info['path']
                            else:
                                # Path is relative to base
                                filepath = os.path.join(base_path, file_info['path'])

                        if os.path.exists(filepath):
                            send_file_content_fragmented(
                                filepath, file_info, cipher, sock, args.cloud_ip, args.cloud_port,
                                sequence_number, args.max_packet_size
                            )
                            sequence_number += 1
                        else:
                            logger.warning(f"File not found, skipping: {filepath}")

                time.sleep(args.sync_interval)

    except KeyboardInterrupt:
        logger.info("Stopping sender...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if args.mode == 'web':
            driver.quit()
        sock.close()
        logger.info("Sender shutdown complete")

if __name__ == "__main__":
    main()
