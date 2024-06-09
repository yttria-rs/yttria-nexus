mod network;

use std::net::Ipv4Addr;

use network::NetworkTun;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tun = NetworkTun::builder()
        .name("rust-tun")
        .ip_address(Ipv4Addr::new(10, 10, 1, 1))
        .subnet_mask(24)
        .build()?;

    tun.set_up(true)?;

    loop {
        match tun.recv() {
            Ok(v) => println!("{v}"),
            Err(e) => println!("{e:?}"),
        };
    }
}
