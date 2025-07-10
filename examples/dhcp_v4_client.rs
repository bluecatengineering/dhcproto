use anyhow::{Result, anyhow};
use dhcproto::Decodable;
use dhcproto::Encodable;
use dhcproto::v4::DhcpOption;
use dhcproto::v4::Message;
use dhcproto::v4::MessageType;
use dhcproto::v4::OptionCode;
use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use rand::RngCore;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    let interface_name = find_default_interface()?;
    println!("Using network interface: {}", interface_name);
    let interface = find_interface_by_name(&interface_name)?;

    let req = build_dhcp_discover(interface.mac.unwrap())?;
    let res = send_dhcp(req).await?;

    println!(
        "ServerIdentifier: {:?}",
        res.opts().get(OptionCode::ServerIdentifier).unwrap()
    );
    println!("IP: {:?}", res.yiaddr());
    println!("GateWay: {:?}", res.opts().get(OptionCode::Router).unwrap());
    println!(
        "SubnetMask: {:?}",
        res.opts().get(OptionCode::SubnetMask).unwrap()
    );
    println!(
        "DomainNameServer: {:?}",
        res.opts().get(OptionCode::DomainNameServer).unwrap()
    );
    println!(
        "LeaseTime: {:?}",
        res.opts().get(OptionCode::AddressLeaseTime).unwrap()
    );

    Ok(())
}

async fn send_dhcp(mut message: Message) -> Result<Message> {
    let bind_addr = "0.0.0.0:0";
    let server_addr = "255.255.255.255:67";

    let xid: u32 = rand::rng().next_u32();

    message.set_xid(xid);

    let socket = UdpSocket::bind(bind_addr).await?;
    socket.set_broadcast(true)?;
    socket.send_to(&message.to_vec()?, server_addr).await?;
    let mut buf = vec![0; 1024];

    let (n, _) = socket.recv_from(&mut buf[..]).await?;

    let res = Message::from_bytes(&buf[..n]).unwrap();

    Ok(res)
}

fn build_dhcp_discover(mac_addr: MacAddr) -> Result<Message> {
    let mut msg = Message::default();
    msg.set_chaddr(&mac_addr.octets());

    msg.set_opts(
        vec![
            DhcpOption::MessageType(MessageType::Discover),
            DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::BroadcastAddr,
                OptionCode::TimeOffset,
                OptionCode::Router,
                OptionCode::DomainName,
                OptionCode::DomainNameServer,
                OptionCode::Hostname,
            ]),
            DhcpOption::End,
        ]
        .into_iter()
        .collect(),
    );

    Ok(msg)
}

// Find the default network interface
fn find_default_interface() -> Result<String> {
    datalink::interfaces()
        .iter()
        .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .map(|i| i.name.clone())
        .ok_or(anyhow!("No available network interface found"))
}

// Find a network interface by its name
fn find_interface_by_name(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or(anyhow!("Interface {} not found", name))
}
