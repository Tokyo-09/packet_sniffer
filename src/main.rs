use clap::{Arg, Command};
use nix::unistd::Uid;
use pnet::datalink::{self, Channel};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use std::process;

fn main() {
    // CLI argument parsing for interface selection
    let matches = Command::new("Rust Packet Sniffer")
        .version("0.1.0")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to capture packets from")
                .required(false),
        )
        .get_matches();

    if !Uid::effective().is_root() {
        panic!("You must run this executable with root permissions");
    }
    let interface_name = matches.get_one::<String>("interface");
    let interfaces = datalink::interfaces();
    let interface = match interface_name {
        Some(name) => interfaces
            .into_iter()
            .find(|iface| iface.name == *name)
            .expect("Specified interface not found"),
        None => interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .expect("No suitable interface found"),
    };

    println!("Capturing on interface: {}", interface.name);

    // Create a datalink channel for packet capture
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Error: Only Ethernet channels are supported");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Error creating channel: {e}");
            process::exit(1);
        }
    };

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    // Main loop
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    handle_packet(&ethernet);
                }
            }
            Err(e) => {
                eprintln!("Error reading packet: {e}");
                continue;
            }
        }
    }
}

fn handle_packet(ethernet: &EthernetPacket) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            println!("IPv4: {} -> {}", ipv4.get_source(), ipv4.get_destination());

            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    println!("TCP: {} -> {}", tcp.get_source(), tcp.get_destination());
                }
            }
        }
    }
}
