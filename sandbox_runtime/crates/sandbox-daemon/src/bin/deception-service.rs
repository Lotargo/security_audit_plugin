use std::io::{Error as IoError, ErrorKind};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PORT_MIN: u16 = 18_000;
const PORT_MAX: u16 = 18_999;

#[derive(Clone)]
struct ServiceConfig {
    bind: IpAddr,
    port: u16,
    protocol: String,
    service: String,
    profile: String,
    session: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;
    if !config.bind.is_loopback() {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "deception-service may bind only to loopback",
        )
        .into());
    }
    if !(PORT_MIN..=PORT_MAX).contains(&config.port) || matches!(config.port, 9050 | 9051 | 9999) {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "deception-service port is outside the synthetic range",
        )
        .into());
    }

    let listener = TcpListener::bind((config.bind, config.port)).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, config).await;
        });
    }
}

fn parse_args() -> Result<ServiceConfig, Box<dyn std::error::Error>> {
    let mut bind = None;
    let mut port = None;
    let mut protocol = None;
    let mut service = None;
    let mut profile = None;
    let mut session = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| {
            IoError::new(ErrorKind::InvalidInput, format!("missing value for {arg}"))
        })?;
        match arg.as_str() {
            "--bind" => bind = Some(value.parse::<IpAddr>()?),
            "--port" => port = Some(value.parse::<u16>()?),
            "--protocol" => protocol = Some(value),
            "--service" => service = Some(value),
            "--profile" => profile = Some(value),
            "--session" => session = Some(value),
            _ => {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}"),
                )
                .into())
            }
        }
    }

    Ok(ServiceConfig {
        bind: bind.ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --bind"))?,
        port: port.ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --port"))?,
        protocol: protocol
            .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --protocol"))?,
        service: service
            .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --service"))?,
        profile: profile
            .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --profile"))?,
        session: session
            .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "missing --session"))?,
    })
}

async fn handle_connection(
    mut stream: TcpStream,
    config: ServiceConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match config.protocol.as_str() {
        "ssh" => handle_ssh(&mut stream).await?,
        "postgres" => handle_postgres(&mut stream).await?,
        "http" => handle_http(&mut stream, &config).await?,
        _ => {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "unsupported synthetic service protocol",
            )
            .into())
        }
    }
    Ok(())
}

async fn handle_http(
    stream: &mut TcpStream,
    config: &ServiceConfig,
) -> Result<(), std::io::Error> {
    let mut request = [0_u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut request)).await;

    let payload = serde_json::json!({
        "status": "ok",
        "environment": "production",
        "service": config.service,
        "profile": config.profile,
        "node": format!("{}.shadow.internal", config.service),
        "session_marker": config.session,
        "synthetic": true
    });
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"status\":\"ok\"}".to_vec());
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nServer: envoy\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

async fn handle_ssh(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream
        .write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14\r\n")
        .await?;
    let mut client_banner = [0_u8; 512];
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        stream.read(&mut client_banner),
    )
    .await;
    stream.shutdown().await
}

async fn handle_postgres(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    let mut startup = [0_u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut startup))
        .await
        .ok()
        .transpose()?
        .unwrap_or(0);

    if read >= 8 {
        let code = u32::from_be_bytes([startup[4], startup[5], startup[6], startup[7]]);
        if code == 80_877_103 {
            stream.write_all(b"N").await?;
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut startup)).await;
        }
    }

    // PostgreSQL AuthenticationCleartextPassword.
    stream.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]).await?;
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut startup)).await;

    let fields = b"SERROR\0C28P01\0Mpassword authentication failed\0\0";
    let len = (4 + fields.len()) as u32;
    let mut response = Vec::with_capacity(1 + 4 + fields.len());
    response.push(b'E');
    response.extend_from_slice(&len.to_be_bytes());
    response.extend_from_slice(fields);
    stream.write_all(&response).await?;
    stream.shutdown().await
}
