#[cfg(feature = "with-serde")]
use serde::{Deserialize, Deserializer};
use socket2::{Domain, Socket, Type};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct MacAddress([u8; 6]);

#[cfg(feature = "with-serde")]
impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<MacAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = MacAddress;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("String or array of mac bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<MacAddress, E>
            where
                E: serde::de::Error,
            {
                MacAddress::from_str(value)
                    .map_err(|()| serde::de::Error::custom("not a valid mac string".to_string()))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<MacAddress, E>
            where
                E: serde::de::Error,
            {
                if value.len() == 6 {
                    let mut bytes = [0u8; 6];
                    bytes.copy_from_slice(&value[0..6]);
                    Ok(MacAddress::with_bytes(bytes))
                } else {
                    Err(serde::de::Error::custom("expected 6 bytes".to_string()))
                }
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl MacAddress {
    pub fn with_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }

    fn do_fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (idx, v) in self.0.iter().enumerate() {
            if idx > 0 {
                write!(fmt, ":")?;
            }
            write!(fmt, "{:02x}", v)?;
        }
        Ok(())
    }
}

impl FromStr for MacAddress {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let mut bytes = [0u8; 6];
        let mut n = 0;

        for v in s.split(':') {
            if n >= bytes.len() {
                return Err(());
            }
            let v = u8::from_str_radix(v, 16).map_err(|_| ())?;
            bytes[n] = v;
            n += 1;
        }
        if n != bytes.len() {
            return Err(());
        }

        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.do_fmt(fmt)
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.do_fmt(fmt)
    }
}

/// Populate the ARP table by sending an empty UDP packet to a high port
fn populate_arp_table_for_addr(ip: IpAddr) -> std::io::Result<()> {
    let socket = Socket::new(
        if ip.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;

    let dest: SocketAddr = (ip, 55555).into();
    let dest = dest.into();
    socket.send_to(b"", &dest)?;
    Ok(())
}

fn parse_arp_command_output(data: &str) -> BTreeMap<IpAddr, MacAddress> {
    let mut table = BTreeMap::new();

    for line in data.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        fn strip_enclosing_parens(s: &str) -> &str {
            let s = s.strip_prefix('(').unwrap_or(s);
            s.strip_suffix(')').unwrap_or(s)
        }

        let ip = strip_enclosing_parens(&fields[1]);

        if let Ok(addr) = IpAddr::from_str(ip) {
            if let Ok(mac) = MacAddress::from_str(&fields[3]) {
                table.insert(addr, mac);
            }
        }
    }

    table
}

fn parse_proc_net_arp(data: &str) -> BTreeMap<IpAddr, MacAddress> {
    let mut table = BTreeMap::new();

    for line in data.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if let Ok(addr) = IpAddr::from_str(&fields[0]) {
            if let Ok(mac) = MacAddress::from_str(&fields[3]) {
                table.insert(addr, mac);
            }
        }
    }

    table
}

#[cfg(test)]
#[test]
fn mac_parse() {
    k9::snapshot!(
        MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        "00:11:22:33:44:55"
    );
}

#[cfg(test)]
#[test]
fn test_parse_proc_net_arp() {
    let data = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.199    0x1         0x2         ff:ff:ff:00:00:00     *        enp3s0
192.168.1.129    0x1         0x2         ee:ee:ee:aa:aa:aa     *        enp3s0"#;

    k9::snapshot!(
        parse_proc_net_arp(data),
        "
{
    192.168.1.129: ee:ee:ee:aa:aa:aa,
    192.168.1.199: ff:ff:ff:00:00:00,
}
"
    );
}

#[cfg(test)]
#[test]
fn test_parse_arp_command_output() {
    let data = r#"? (192.168.1.199) at ff:ff:ff:00:00:00 [ether] on enp3s0
? (192.168.1.129) at ee:ee:ee:aa:aa:aa [ether] on enp3s0"#;

    k9::snapshot!(
        parse_arp_command_output(data),
        "
{
    192.168.1.129: ee:ee:ee:aa:aa:aa,
    192.168.1.199: ff:ff:ff:00:00:00,
}
"
    );
}

/// Attempt to resolve the MAC address for a given IP.
/// Does not require root privs.
/// Not guaranteed to succeed.
pub fn mac_address_for_ip(ip: IpAddr) -> Option<MacAddress> {
    let _ = populate_arp_table_for_addr(ip);

    // Attempt to read linux-specific ARP data from the kernel
    if let Ok(data) = std::fs::read_to_string("/proc/net/arp") {
        let mut table = parse_proc_net_arp(&data);
        return table.remove(&ip);
    }

    // Try parsing the output from `arp -a` on other systems.
    // Take a look at <https://github.com/GhostofGoes/getmac/blob/master/getmac/getmac.py>
    // for inspiration if you are considering porting this.
    if let Ok(output) = std::process::Command::new("arp")
        .args(["-a", "-n"])
        .output()
    {
        let data = String::from_utf8_lossy(&output.stdout);
        let mut table = parse_arp_command_output(&data);
        return table.remove(&ip);
    }

    None
}
