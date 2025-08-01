use clap::{Arg, Command};
use colored::*;
use nix::unistd::Uid;
use pnet::datalink::{self, Channel, Config};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Packet statistics structure
#[derive(Default)]
struct PacketStats {
    total_packets: AtomicUsize,
    ipv4_packets: AtomicUsize,
    tcp_packets: AtomicUsize,
    udp_packets: AtomicUsize,
    icmp_packets: AtomicUsize,
}

impl Clone for PacketStats {
    fn clone(&self) -> Self {
        PacketStats {
            total_packets: AtomicUsize::new(self.total_packets.load(Ordering::Relaxed)),
            ipv4_packets: AtomicUsize::new(self.ipv4_packets.load(Ordering::Relaxed)),
            tcp_packets: AtomicUsize::new(self.tcp_packets.load(Ordering::Relaxed)),
            udp_packets: AtomicUsize::new(self.udp_packets.load(Ordering::Relaxed)),
            icmp_packets: AtomicUsize::new(self.icmp_packets.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ProtocolFilter {
    All,
    Ip,
    Tcp,
    Udp,
    Icmp,
}

impl From<&str> for ProtocolFilter {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ip" => ProtocolFilter::Ip,
            "tcp" => ProtocolFilter::Tcp,
            "udp" => ProtocolFilter::Udp,
            "icmp" => ProtocolFilter::Icmp,
            _ => ProtocolFilter::All,
        }
    }
}

fn main() {
    let matches = Command::new("Rust Packet Sniffer")
        .version("0.2.0")
        .about("A network packet sniffer with advanced filtering and statistics")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to capture packets from"),
        )
        .arg(
            Arg::new("filter")
                .short('f')
                .long("filter")
                .value_name("FILTER")
                .help("Filter packets (e.g., 'tcp', 'udp', 'ip', 'icmp', 'all')")
                .default_value("all"),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .long("count")
                .value_name("COUNT")
                .help("Number of packets to capture before exiting")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Enable verbose output"),
        )
        .get_matches();

    if !Uid::effective().is_root() {
        eprintln!("{}", "Error: This program requires root privileges".red());
        process::exit(1);
    }

    let interface_name = matches.get_one::<String>("interface");
    let interfaces = datalink::interfaces();
    let interface = interface_name
        .and_then(|name| {
            interfaces
                .clone()
                .into_iter()
                .find(|iface| iface.name == *name)
        })
        .or_else(|| {
            interfaces
                .into_iter()
                .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        })
        .expect("No suitable interface found");

    println!(
        "{}",
        format!("Capturing on interface: {}", interface.name).green()
    );

    let stats = Arc::new(PacketStats::default());
    let config = Config {
        read_timeout: Some(std::time::Duration::from_millis(500)),
        promiscuous: true,
        ..Default::default()
    };

    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("{}", "Error: Only Ethernet channels are supported".red());
            process::exit(1);
        }
        Err(e) => {
            eprintln!("{}", format!("Error creating channel: {e}").red());
            process::exit(1);
        }
    };

    let stats_clone = Arc::clone(&stats);
    ctrlc::set_handler(move || {
        print_stats(&stats_clone);
        println!("\n{}", "Shutting down...".yellow());
        process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    let filter: ProtocolFilter = matches.get_one::<String>("filter").unwrap().as_str().into();
    let max_packets = matches.get_one::<usize>("count").copied();
    let verbose = matches.get_flag("verbose");

    let mut packet_count = 0;
    loop {
        if let Some(max) = max_packets {
            if packet_count >= max {
                print_stats(&stats);
                break;
            }
        }

        match rx.next() {
            Ok(packet) => {
                stats.total_packets.fetch_add(1, Ordering::Relaxed);
                packet_count += 1;
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    handle_packet(&ethernet, &filter, &stats, verbose);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                eprintln!("{}", format!("Error reading packet: {e}").red());
                continue;
            }
        }
    }

    print_stats(&stats);
}

fn handle_packet(
    ethernet: &EthernetPacket,
    filter: &ProtocolFilter,
    stats: &PacketStats,
    verbose: bool,
) {
    if ethernet.get_ethertype() != EtherTypes::Ipv4 || !matches_filter(filter, &ProtocolFilter::Ip)
    {
        return;
    }

    stats.ipv4_packets.fetch_add(1, Ordering::Relaxed);
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());

        if verbose || matches_filter(filter, &ProtocolFilter::Ip) {
            println!(
                "{} {} {} -> {} (TTL: {})",
                format!("[{timestamp}]").dimmed(),
                "IPv4".blue(),
                ipv4.get_source().to_string().cyan(),
                ipv4.get_destination().to_string().cyan(),
                ipv4.get_ttl()
            );
        }

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp if matches_filter(filter, &ProtocolFilter::Tcp) => {
                stats.tcp_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    if verbose {
                        println!(
                            "  {} {} -> {} (Flags: {}{}, Seq: {}, Ack: {})",
                            "TCP".green(),
                            tcp.get_source().to_string().yellow(),
                            tcp.get_destination().to_string().yellow(),
                            format!("{:?}", tcp.get_flags()).purple(),
                            if !tcp.payload().is_empty() {
                                format!(" Payload: {} bytes", tcp.payload().len())
                            } else {
                                String::new()
                            },
                            tcp.get_sequence(),
                            tcp.get_acknowledgement()
                        );
                    } else {
                        println!(
                            "  {} {} -> {}",
                            "TCP".green(),
                            tcp.get_source().to_string().yellow(),
                            tcp.get_destination().to_string().yellow()
                        );
                    }
                }
            }
            IpNextHeaderProtocols::Udp if matches_filter(filter, &ProtocolFilter::Udp) => {
                stats.udp_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    println!(
                        "  {} {} -> {} (Length: {})",
                        "UDP".magenta(),
                        udp.get_source().to_string().yellow(),
                        udp.get_destination().to_string().yellow(),
                        udp.get_length()
                    );
                }
            }
            IpNextHeaderProtocols::Icmp if matches_filter(filter, &ProtocolFilter::Icmp) => {
                stats.icmp_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                    println!(
                        "  {} Type: {} Code: {}",
                        "ICMP".red(),
                        icmp.get_icmp_type().0,
                        icmp.get_icmp_code().0
                    );
                }
            }
            _ => {}
        }
    }
}

fn matches_filter(filter: &ProtocolFilter, protocol: &ProtocolFilter) -> bool {
    matches!(filter, ProtocolFilter::All) || filter == protocol
}

fn print_stats(stats: &PacketStats) {
    println!("\n{}", "Packet Statistics:".bold().underline());
    println!(
        "Total Packets: {}",
        stats.total_packets.load(Ordering::Relaxed)
    );
    println!(
        "IPv4 Packets: {}",
        stats.ipv4_packets.load(Ordering::Relaxed)
    );
    println!("TCP Packets: {}", stats.tcp_packets.load(Ordering::Relaxed));
    println!("UDP Packets: {}", stats.udp_packets.load(Ordering::Relaxed));
    println!(
        "ICMP Packets: {}",
        stats.icmp_packets.load(Ordering::Relaxed)
    );
}
