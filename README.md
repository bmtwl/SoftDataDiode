<p align="center">
<img src="https://github.com/user-attachments/assets/5cb569c6-34cc-4ee4-b7a4-c961714234ce" width="500">
</p>

## Soft Data Diode Image Streaming System 

A secure, one-way video streaming solution that implements a software-based data diode for transmitting web content and RTSP streams to a cloud server without exposing any return path.

This protects the secure service in two ways: it acts as a data diode, never establishing a 2-way communication link, and it also acts as an opto-isolator, transforming any web content into an image to prevent HTML inspection or other unintentional information leakage.

Even if the receiver cloud server is compromised, there should be no way to move laterally back into the sender's network if the receiver software is all that is installed.

The data itself is encrypted with AES-256-GCM prior to being transmitted with a simple pre-shared key.

## Architecture

```mermaid
graph TD
    subgraph "Secure Environment"
        SOURCE[Source System<BR>Web, RTSP or VNC] --> SENDER[Data Diode Sender]
        SENDER --> SENDERPROCESSING[UDP Packets<br/>Encrypted & Fragmented]
    end
    
    SENDERPROCESSING -.->|Fire-and-Forget<br/>One-Way UDP| CLOUDIP[Cloud Server<br/>Public IP:Port]
    
    subgraph "Cloud Environment"
        CLOUDIP --> RECEIVER[Data Diode Receiver]
        RECEIVER --> RECEIVERPROCESSING[Frame Reassembly<br/>& Decryption]
        RECEIVERPROCESSING --> BUFFER[Frame Buffer]
        BUFFER --> HTTPSERVER[HTTP Stream Server]
    end

    subgraph "Internet"
        HTTPSERVER --> INTERNETCLIENT[Web Browser/Client]
    end

    
    
    classDef secure fill:#e1f5fe,stroke:#01579b;
    classDef cloud fill:#ffebee,stroke:#b71c1c;
    classDef client fill:#fff3e0,stroke:#e65100;
    
    class SOURCE,SENDER,SENDERPROCESSING secure
    class CLOUDIP,RECEIVER,RECEIVERPROCESSING,BUFFER,HTTPSERVER cloud
    class INTERNETCLIENT client
```

## Features

- **True One-Way Communication**: No return path possible (software data diode)
- **Opto-Isolation**: Resource is encoded as a simple image to prevent information leakage
- **Multiple Stream Support**: Multi-receiver version handles multiple independent streams
- **Secure Encryption**: AES-256-GCM encryption with pre-shared keys
- **Web, RTSP and VNC Sources**: Capture web pages (with Selenium), RTSP video streams or VNC clients (with vncsnapshot)
- **Freshness Monitoring**: Streams visually and programatically show whether updates are:
    - Live - Green dot (Updated within the last 30 seconds)
    - Stalled - Yellow dot and time since last frame (Last update was more than 30 seconds ago)
    - Stale - Red dot (Not updated in more than 5 minutes)
    - Freshness JSON endpoint per stream with the state and seconds since last frame (`https://host/stream/freshness`)

## Installation

1. **Clone the repository:**
```bash
cd /opt
git clone https://github.com/bmtwl/SoftDataDiode.git
cd SoftDataDiode
```
2. **Create a virtual environment (optional):**

   _A `venv` is recommended for the sender side especially, as selenium can be famously hard to get to work using OS packages._

   _If you use a `venv` then you must activate it before starting any senders or receivers. To exit a `venv`, use the `deactivate` command._

```bash
python -m venv venv
source venv/bin/activate
```

3. **Install Packages:**

   **Sender Side:**
   ```bash
   pip install opencv-python-headless cryptography selenium numpy
   ```

   **Receiver Side:**
   ```bash
   pip install opencv-python-headless cryptography numpy
   ```

4. **Generate encryption key (must be same key on both sender and receiver sides) :**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Configuration

### 1. Multi-receiver Configuration (`config.json`)

```json
{
  "server": {
    "http_host": "127.0.0.1",
    "http_port": 8000,
    "debug": false
  },
  "streams": {
    "dashboard": {
      "name": "Main Dashboard",
      "description": "Primary monitoring dashboard",
      "udp_host": "0.0.0.0",
      "udp_port": 5005,
      "key": "your-generated-key-here",
      "buffer_size": 50
    },
    "camera1": {
      "name": "Security Camera 1",
      "description": "Front entrance camera",
      "udp_host": "0.0.0.0",
      "udp_port": 5006,
      "key": "your-generated-key-here",
      "buffer_size": 100,
      "display_resolution": "1280x720"
    },
    "desktop1": {
      "name": "Desktop 1",
      "description": "Information Kiosk desktop",
      "udp_host": "0.0.0.0",
      "udp_port": 5007,
      "key": "your-generated-key-here",
      "buffer_size": 100
    }
  }
}
```

### 2. Example Web Frontend Configuration (Caddy)

While of course you can use any web front end you want (Apache, Nginx, Traefik, etc), or even expose the builtin web service directly, Caddy is shown here for simplicity.

#### Add an HTTP basic auth gate by adding a username and hashed password:
```bash
caddy hash-password --plaintext "mysecret"
```

#### Edit Caddy Config eg `/etc/caddy/Caddyfile`
```caddyfile
yourserverfqdn {
    tls internal
    basic_auth {
        user output-of-caddy-hash-password
    }
    handle {
        reverse_proxy 127.0.0.1:8000
    }
}
```

_Remove the `tls internal` line if your domain is public and you want to have an [automatic LetsEncrypt certificate](https://caddyserver.com/docs/automatic-https#overview) generated for this host._

_Remove the `basic_auth` (`basicauth` prior to v2.8) section if you want to allow access without any authentication._


## Usage

### Running Senders

#### Web Page Capture
```bash
python ddsender.py \
  --mode web \
  --source "https://webpage.example.com" \
  --cloud-ip YOUR_CLOUD_IP \
  --cloud-port 5005 \
  --key "your-base64-key-here" \
  --interval 5
```

#### RTSP Stream Capture
```bash
python ddsender.py \
  --mode rtsp \
  --source "rtsp://camera.example.com/stream" \
  --cloud-ip YOUR_CLOUD_IP \
  --cloud-port 5006 \
  --key "your-base64-key-here" \
  --interval 0.1
```

#### VNC Capture
```bash
python ddsender.py \
  --mode vnc \
  --source "vnc.example.com" \
  --cloud-ip YOUR_CLOUD_IP \
  --cloud-port 5006 \
  --password ~/.vnc/passwd \
  --key "your-base64-key-here" \
  --interval 10
```

### Running the Receiver

```bash
# Single receiver usage
python ddreceiver.py \
  -udp-host 1.2.3.4 \
  --udp-port 5005 \
  --http-host 127.0.0.1 \
  --http-port 8000 \
  --key "your-base64-key-here"

# Multi-receiver usage
python ddmultireceiver.py --config /path/to/config.json
```

## Troubleshooting

### Selenium crashes because it can't find a chrome/chromium driver
There are broken OS packages on Debian, at least. The recommended way to run the sender is with a `venv`.

### Resource usage is too high
There are a few strategies to reduce resource usage:
1. Reduce the capture resolution of the image that is being sent/received.
2. Increase the interval between captures
3. Reduce the jpeg quality (This may make text hard to read. The default of `60` is already a good balance of quality vs size)
4. Switch from Python to Pypy (hard)

### Traffic isn't getting through to the receiver
Check for the presence of UDP packets using something like Wireshark or `tcpdump udp and port 5005`. You should see a constant stream from the sender to the receiver on both hosts.
Any firewalls in the path between the sender and receiver are highly likely to block this traffic, so make sure they are set up with appropriate allow rules.

### Things aren't working and I'm not sure what's happening
You can start the sender or receiver with the `--debug` flag, or turn on debugging in the `config.json` file. This should make the output very verbose.
If this still doesn't help, please create an issue in the repo.

## Known issues

### My logs have lots of `I/O operation on closed file` events in them
This is due to the way the Python http server flushes out connections and there is no simple workaround.
I may do some custom exception handling in the future to clean these up, but for now they can be safely ignored.
