import cv2
import numpy as np
import socket
import time
import argparse
import struct
import math
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

    # Suppress logging
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
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

def send_frame_fragmented(frame, cipher, sock, cloud_ip, cloud_port, sequence_number, max_packet_size=1400):
    """Encrypt and send frame via UDP with fragmentation"""
    logger = setup_logging(False)  # Create logger for this function

    if frame is None:
        logger.debug("Skipping null frame")
        return

    try:
        # Encode frame to JPEG with quality control
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 60]  # Reduced quality further
        _, buffer = cv2.imencode('.jpg', frame, encode_param)
        data = buffer.tobytes()

        # Calculate safe payload size accounting for encryption overhead
        header_size = 8  # 4 bytes seq + 2 bytes frag_index + 2 bytes total_frags
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

            # Create header: sequence_number(4) + frag_index(2) + total_frags(2)
            header = struct.pack('>IHH', sequence_number, frag_index, total_frags)
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

def main():
    parser = argparse.ArgumentParser(description='Data Diode Sender')
    parser.add_argument('--mode', choices=['web', 'rtsp'], required=True, help='Capture mode')
    parser.add_argument('--source', required=True, help='URL for web or RTSP stream URL')
    parser.add_argument('--cloud-ip', required=True, help='Cloud server IP')
    parser.add_argument('--cloud-port', type=int, required=True, help='Cloud server UDP port')
    parser.add_argument('--key', required=True, help='Base64 encoded encryption key')
    parser.add_argument('--interval', type=float, default=0.1, help='Capture interval in seconds')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for web page loading (seconds)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--max-packet-size', type=int, default=1400, help='Maximum UDP packet size (default: 1400)')
    parser.add_argument('--capture-resolution', default='1280x720', help='Capture resolution (default: 1280x720)')
    parser.add_argument('--web-capture-element', default='body', help='CSS selector for web capture element (default: body)')

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
    capture_resolution = parse_resolution(args.capture_resolution)
    logger.info(f"Capture resolution set to: {capture_resolution[0]}x{capture_resolution[1]}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger.debug(f"UDP socket created for {args.cloud_ip}:{args.cloud_port}")

    if args.mode == 'web':
        driver = create_webdriver()
        capture_func = lambda: capture_webpage(
            args.source, driver, args.username, args.password, args.timeout,
            args.web_capture_element, capture_resolution
        )
        logger.info(f"Web capture initialized for {args.source}")
        logger.info(f"Capturing element: {args.web_capture_element}")
    else:  # rtsp
        capture_func = lambda: capture_rtsp_stream(
            args.source, args.username, args.password, capture_resolution
        )
        logger.info(f"RTSP capture initialized for {args.source}")

    sequence_number = 0

    try:
        while True:
            frame = capture_func()
            if frame is not None:
                logger.debug(f"Captured frame {sequence_number} with shape {frame.shape}")
            send_frame_fragmented(
                frame, cipher, sock, args.cloud_ip, args.cloud_port,
                sequence_number, args.max_packet_size
            )
            sequence_number += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Stopping sender...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        if args.mode == 'web':
            driver.quit()
        sock.close()
        logger.info("Sender shutdown complete")

if __name__ == "__main__":
    main()
