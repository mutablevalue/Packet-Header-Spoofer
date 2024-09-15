use socket2::{Domain, Protocol, Socket, Type};
use std::fmt::Error;
use std::net::SocketAddr;
use std::time::Instant;
use tokio;
use rand::Rng;

async fn ip_spoof(
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    destination_port: u16,
    source_port: u16,
    payload: &[u8],
) -> std::io::Result<()> {
    let start_time = Instant::now(); // Start time

    // Create a raw IP socket (not UDP)
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    // Create destination address
    let dest_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(destination_ip)),
        destination_port,
    );

    // Build and send the IP + UDP packet
    let full_packet = build_packet(source_ip, destination_ip, source_port, destination_port, payload);
    println!("Packet to be sent: {:?}", full_packet);

    socket.send_to(&full_packet, &dest_addr.into())?;

    println!("Spoofing packet took: {:?}", start_time.elapsed());
    Ok(())
}

fn build_packet(
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::with_capacity(20 + 8 + payload.len()); // Pre-allocate for IP + UDP + payload

    // Build IP header
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, (20 + 8 + payload.len()) as u8, 0x00, 0x00, 0x40, 0x00,
        64, 17, 0x00, 0x00, // Protocol UDP (17), TTL, Placeholder for checksum
    ]);
    packet.extend_from_slice(&source_ip);
    packet.extend_from_slice(&destination_ip);

    // Build UDP header
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes()); // UDP length
    packet.extend_from_slice(&[0x00, 0x00]); // UDP checksum placeholder

    // Append payload
    packet.extend_from_slice(payload);
    packet
}

#[tokio::main]
async fn main() {
    let mut rng = rand::thread_rng();
    let source_ip: [u8; 4] = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
    let destination_ip: [u8; 4] = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
    let destination_port: u16 = rng.gen();
    let source_port: u16 = rng.gen();
    let payload: &[u8; 12] = b"Hello, world";

    let tasks = futures::future::join_all(
        (0..1000).map(|_| ip_spoof(source_ip, destination_ip, destination_port, source_port, payload))
    );

    tasks.await.into_iter().for_each(|result| {
        if let Err(e) = result {
            eprintln!("Error: {}", e);
        }
    });
}
