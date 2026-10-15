//! Server side of the SOCKS handshake for dynamic port forwarding (`ssh -D`).
//!
//! Only CONNECT is supported: SOCKS5 without authentication (RFC 1928) and
//! SOCKS4 / SOCKS4a. Host names are passed through unresolved, so DNS is done
//! by the SSH server — the same behavior as OpenSSH's `-D` (what clients call
//! "socks5h").

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SOCKS4: u8 = 4;
const SOCKS5: u8 = 5;
const CMD_CONNECT: u8 = 1;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
/// SOCKS4 user id / SOCKS4a host name length limit (bytes, without NUL).
const MAX_CSTRING: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4,
    V5,
}

/// A CONNECT request: where the client wants to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub version: SocksVersion,
    pub host: String,
    pub port: u16,
}

/// Why the tunnel could not reach the requested target (what sshd reports
/// for a refused direct-tcpip channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    General,
    /// The server's forwarding policy forbids it.
    NotAllowed,
    /// The server could not connect (unresolvable, unreachable or refused).
    Refused,
}

#[derive(Debug)]
pub enum SocksError {
    Io(std::io::Error),
    UnsupportedVersion(u8),
    NoAcceptableAuth,
    UnsupportedCommand(u8),
    UnsupportedAddressType(u8),
    InvalidHostname,
    FieldTooLong,
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocksError::Io(e) => write!(f, "I/O error: {e}"),
            SocksError::UnsupportedVersion(v) => write!(f, "unsupported SOCKS version {v}"),
            SocksError::NoAcceptableAuth => {
                write!(f, "client requires SOCKS authentication, but only 'no authentication' is offered")
            }
            SocksError::UnsupportedCommand(c) => write!(f, "unsupported SOCKS command {c} (only CONNECT)"),
            SocksError::UnsupportedAddressType(a) => write!(f, "unsupported SOCKS address type {a}"),
            SocksError::InvalidHostname => write!(f, "invalid host name"),
            SocksError::FieldTooLong => write!(f, "SOCKS4 field too long"),
        }
    }
}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        SocksError::Io(e)
    }
}

/// Run the handshake up to and including the CONNECT request. The caller
/// must answer with [`send_success`] or [`send_failure`].
pub async fn read_request<S>(stream: &mut S) -> Result<SocksRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match stream.read_u8().await? {
        SOCKS5 => read_v5(stream).await,
        SOCKS4 => read_v4(stream).await,
        other => Err(SocksError::UnsupportedVersion(other)),
    }
}

async fn read_v5<S>(stream: &mut S) -> Result<SocksRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method_count = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS5, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(SocksError::NoAcceptableAuth);
    }
    stream.write_all(&[SOCKS5, METHOD_NO_AUTH]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let [version, command, _reserved, address_type] = header;
    if version != SOCKS5 {
        return Err(SocksError::UnsupportedVersion(version));
    }
    if command != CMD_CONNECT {
        write_v5_reply(stream, 0x07).await?;
        return Err(SocksError::UnsupportedCommand(command));
    }

    let host = match address_type {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            hostname(name)?
        }
        other => {
            write_v5_reply(stream, 0x08).await?;
            return Err(SocksError::UnsupportedAddressType(other));
        }
    };
    let port = stream.read_u16().await?;

    Ok(SocksRequest {
        version: SocksVersion::V5,
        host,
        port,
    })
}

async fn read_v4<S>(stream: &mut S) -> Result<SocksRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let mut ip = [0u8; 4];
    stream.read_exact(&mut ip).await?;
    let _user_id = read_cstring(stream).await?;

    // SOCKS4a: an address of 0.0.0.x (x != 0) means "host name follows".
    let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
        hostname(read_cstring(stream).await?)?
    } else {
        Ipv4Addr::from(ip).to_string()
    };

    if command != CMD_CONNECT {
        write_v4_reply(stream, false).await?;
        return Err(SocksError::UnsupportedCommand(command));
    }

    Ok(SocksRequest {
        version: SocksVersion::V4,
        host,
        port,
    })
}

async fn read_cstring<S>(stream: &mut S) -> Result<Vec<u8>, SocksError>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        match stream.read_u8().await? {
            0 => return Ok(bytes),
            b if bytes.len() < MAX_CSTRING => bytes.push(b),
            _ => return Err(SocksError::FieldTooLong),
        }
    }
}

fn hostname(bytes: Vec<u8>) -> Result<String, SocksError> {
    let name = String::from_utf8(bytes).map_err(|_| SocksError::InvalidHostname)?;
    if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(SocksError::InvalidHostname);
    }
    Ok(name)
}

/// The target is connected; data can flow after this.
pub async fn send_success<S>(stream: &mut S, version: SocksVersion) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match version {
        SocksVersion::V5 => write_v5_reply(stream, 0x00).await,
        SocksVersion::V4 => write_v4_reply(stream, true).await,
    }
}

pub async fn send_failure<S>(stream: &mut S, version: SocksVersion, failure: ConnectFailure) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match version {
        SocksVersion::V5 => {
            let code = match failure {
                ConnectFailure::General => 0x01,
                ConnectFailure::NotAllowed => 0x02,
                ConnectFailure::Refused => 0x05,
            };
            write_v5_reply(stream, code).await
        }
        // SOCKS4 has a single "rejected or failed" code.
        SocksVersion::V4 => write_v4_reply(stream, false).await,
    }
}

/// The bound address isn't known (the connection is made by the SSH server),
/// so replies carry 0.0.0.0:0, which clients ignore for CONNECT.
async fn write_v5_reply<S>(stream: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[SOCKS5, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await
}

async fn write_v4_reply<S>(stream: &mut S, granted: bool) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let code = if granted { 0x5A } else { 0x5B };
    stream.write_all(&[0, code, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Feed `input` to the server side and return (result, everything the
    /// server wrote back).
    async fn handshake(input: &[u8]) -> (Result<SocksRequest, SocksError>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        client.write_all(input).await.unwrap();
        let result = read_request(&mut server).await;
        drop(server);
        let mut replies = Vec::new();
        client.read_to_end(&mut replies).await.unwrap();
        (result, replies)
    }

    #[tokio::test]
    async fn v5_domain_connect() {
        let mut input = vec![5, 1, 0, 5, 1, 0, 3, 11];
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(&443u16.to_be_bytes());
        let (result, replies) = handshake(&input).await;
        assert_eq!(
            result.unwrap(),
            SocksRequest { version: SocksVersion::V5, host: "example.com".into(), port: 443 }
        );
        assert_eq!(replies, [5, 0]);
    }

    #[tokio::test]
    async fn v5_ipv4_and_ipv6_connect() {
        let (result, _) = handshake(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 5, 0x1f, 0x90]).await;
        let request = result.unwrap();
        assert_eq!((request.host.as_str(), request.port), ("10.0.0.5", 8080));

        let mut input = vec![5, 1, 0, 5, 1, 0, 4];
        input.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        input.extend_from_slice(&22u16.to_be_bytes());
        let (result, _) = handshake(&input).await;
        assert_eq!(result.unwrap().host, "::1");
    }

    #[tokio::test]
    async fn v5_requires_no_auth_method() {
        // Client only offers username/password (0x02).
        let (result, replies) = handshake(&[5, 1, 2]).await;
        assert!(matches!(result, Err(SocksError::NoAcceptableAuth)));
        assert_eq!(replies, [5, 0xff]);
    }

    #[tokio::test]
    async fn v5_rejects_bind_and_udp() {
        let (result, replies) = handshake(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        assert!(matches!(result, Err(SocksError::UnsupportedCommand(2))));
        assert_eq!(replies, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn v4_and_v4a_connect() {
        let (result, replies) = handshake(&[4, 1, 0, 80, 192, 168, 1, 2, b'u', 0]).await;
        assert_eq!(
            result.unwrap(),
            SocksRequest { version: SocksVersion::V4, host: "192.168.1.2".into(), port: 80 }
        );
        assert!(replies.is_empty());

        let mut input = vec![4, 1, 0x15, 0x38, 0, 0, 0, 1, 0];
        input.extend_from_slice(b"db.internal\0");
        let (result, _) = handshake(&input).await;
        let request = result.unwrap();
        assert_eq!((request.host.as_str(), request.port), ("db.internal", 5432));
    }

    #[tokio::test]
    async fn rejects_bad_hostnames_and_versions() {
        let mut input = vec![5, 1, 0, 5, 1, 0, 3, 4];
        input.extend_from_slice(b"a\nb ");
        input.extend_from_slice(&80u16.to_be_bytes());
        assert!(matches!(handshake(&input).await.0, Err(SocksError::InvalidHostname)));
        assert!(matches!(handshake(&[0x16, 3, 1]).await.0, Err(SocksError::UnsupportedVersion(0x16))));
    }

    #[tokio::test]
    async fn reply_encoding() {
        let mut out = Vec::new();
        send_failure(&mut out, SocksVersion::V5, ConnectFailure::Refused).await.unwrap();
        assert_eq!(out, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut out = Vec::new();
        send_success(&mut out, SocksVersion::V4).await.unwrap();
        assert_eq!(out, [0, 0x5a, 0, 0, 0, 0, 0, 0]);
    }
}
