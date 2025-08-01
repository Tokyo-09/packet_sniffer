# Rust Packet Sniffer

A Rust-based network packet sniffer that captures and analyzes network packets with advanced filtering and statistics. This tool is designed to monitor network traffic on a specified interface, filter packets by protocol (IP, TCP, UDP, ICMP, or all), and provide detailed packet statistics.

## Features

- **Packet Capture**: Captures Ethernet packets on a specified network interface using the `pnet` library.
- **Protocol Filtering**: Supports filtering packets by protocol (`ip`, `tcp`, `udp`, `icmp`, or `all`).
- **Verbose Output**: Optionally displays detailed packet information, including TCP flags, sequence numbers, and payload sizes.
- **Packet Statistics**: Tracks and displays the total number of packets, as well as counts for IPv4, TCP, UDP, and ICMP packets using thread-safe atomic counters.
- **Graceful Shutdown**: Handles `Ctrl+C` to display final statistics and exit cleanly.
- **Customizable Packet Count**: Allows specifying the number of packets to capture before exiting.
- **Colorized Output**: Uses the `colored` crate to provide a visually appealing console output with color-coded protocol information.

## Prerequisites

To build and run this project, you need the following:

- **Rust**: Install the latest stable version of Rust using [rustup](https://rustup.rs/).
- **Root Privileges**: The sniffer requires root privileges to capture packets
- **libpcap**: The `pnet` library requires `libpcap` for packet capturing. Install it on your system:
  - **Ubuntu/Debian**: `sudo apt-get install libpcap-dev`
  - **Fedora**: `sudo dnf install libpcap-devel`
  - **macOS**: `brew install libpcap`
- **Network Interface**: A network interface that is up and has an IP address assigned (non-loopback).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://gitlab.com/Tokyo-04/packet_sniffer.git
   cd packet_sniffer
   ```

2. **Build the Project**:
   ```bash
   cargo build --release
   ```

3. **Run the Sniffer**:
   Since the program requires root privileges, use `sudo` to run it:
   ```bash
   sudo ./target/release/packet_sniffer
   ```

## Usage

The program can be run with various command-line arguments to customize its behavior. Below is the help output:

```bash
Rust Packet Sniffer 0.2.0
A network packet sniffer with advanced filtering and statistics

USAGE:
    rust-packet-sniffer [OPTIONS]

OPTIONS:
    -i, --interface <INTERFACE>    Network interface to capture packets from
    -f, --filter <FILTER>         Filter packets (e.g., 'tcp', 'udp', 'ip', 'icmp', 'all') [default: all]
    -c, --count <COUNT>           Number of packets to capture before exiting
    -v, --verbose                 Enable verbose output
    -h, --help                    Print help information
    -V, --version                 Print version information
```

### Examples

1. **Capture All Packets on Default Interface**:
   ```bash
   sudo ./target/release/packet_sniffer
   ```

2. **Capture TCP Packets on a Specific Interface**:
   ```bash
   sudo ./target/release/packet_sniffer -i eth0 -f tcp
   ```

3. **Capture 100 Packets with Verbose Output**:
   ```bash
   sudo ./target/release/packet_sniffer -i eth0 -c 100 -v
   ```

4. **Capture ICMP Packets Only**:
   ```bash
   sudo ./target/release/packet_sniffer -f icmp
   ```

### Output

The sniffer displays real-time packet information with color-coded output. For example:

```
Capturing on interface: eth0
[2025-08-01T10:57:00Z] IPv4 192.168.1.100 -> 8.8.8.8 (TTL: 64)
  TCP 12345 -> 80
[2025-08-01T10:57:01Z] IPv4 192.168.1.100 -> 8.8.8.8 (TTL: 64)
  UDP 12345 -> 53 (Length: 45)
```

When exiting (via `Ctrl+C` or reaching the packet count), it shows statistics:

```
Packet Statistics:
Total Packets: 150
IPv4 Packets: 150
TCP Packets: 100
UDP Packets: 40
ICMP Packets: 10
```

## Limitations

- **Ethernet Only**: The sniffer currently supports only Ethernet channels.
- **IPv4 Only**: Only IPv4 packets are processed; IPv6 support is not implemented.
- **Root Privileges**: Requires root access due to low-level network operations.
- **Platform-Specific**: Some features may behave differently depending on the operating system and network interface.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please ensure your code follows the Rust style guidelines and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
