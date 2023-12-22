use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::server::{AllowAnyAuthenticatedClient, ClientCertVerified};
use tokio_rustls::rustls::{Certificate, DistinguishedName, Error, PrivateKey, RootCertStore};

pub type Versions = &'static [&'static rustls::SupportedProtocolVersion];
static V12_ONLY: Versions = &[&rustls::version::TLS12];
static V13_ONLY: Versions = &[&rustls::version::TLS13];

const CA_CRT: &str = include_str!("../certs/ca.crt");
const CLIENT_CRT: &str = include_str!("../certs/client.crt");
const CLIENT_KEY: &str = include_str!("../certs/client.key");
const SERVER_CRT: &str = include_str!("../certs/server.crt");
const SERVER_KEY: &str = include_str!("../certs/server.key");

#[tokio::main]
async fn main() {
    println!("TLS 1.2 - Without client rejection");
    run_test(V12_ONLY, false).await;
    println!("TLS 1.2 - With client rejection");
    run_test(V12_ONLY, true).await;
    println!("TLS 1.3 - Without client rejection");
    run_test(V13_ONLY, false).await;
    println!("TLS 1.3 - With client rejection");
    run_test(V13_ONLY, true).await;
}

async fn run_test(versions: Versions, reject_client: bool) {
    let connector = configure_client(versions);
    let acceptor = configure_server(versions, reject_client);

    let (client, server) = connect().await;

    let acceptor_task = tokio::spawn(acceptor.accept(server));
    let client_result = connector
        .connect("server42".try_into().unwrap(), client)
        .await;
    let server_result = acceptor_task.await.unwrap();

    println!("client: {client_result:?}");
    println!("server: {server_result:?}");
}

async fn connect() -> (TcpStream, TcpStream) {
    fn local_host(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    let listener = tokio::net::TcpListener::bind(local_host(0)).await.unwrap();
    let assigned_port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(local_host(assigned_port)).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    (client, server)
}

fn root_cert_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(&read_cert(CA_CRT)).unwrap();
    roots
}

fn configure_server(versions: Versions, reject_client: bool) -> tokio_rustls::TlsAcceptor {
    let verifier = {
        let verifier = AllowAnyAuthenticatedClient::new(root_cert_store());
        Arc::new(CustomClientVerifier {
            reject_client,
            inner: verifier,
        })
    };

    let server_cert = read_cert(SERVER_CRT);
    let server_key = read_key(SERVER_KEY);

    let config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key)
        .unwrap();

    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn configure_client(versions: Versions) -> tokio_rustls::TlsConnector {
    let client_cert = read_cert(CLIENT_CRT);
    let client_key = read_key(CLIENT_KEY);

    let config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(root_cert_store())
        .with_client_auth_cert(vec![client_cert], client_key)
        .unwrap();

    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn read_pem(data: &str) -> Vec<u8> {
    let pem = pem::parse(data).unwrap();
    pem.contents().to_vec()
}

fn read_cert(data: &str) -> Certificate {
    Certificate(read_pem(data))
}

fn read_key(data: &str) -> PrivateKey {
    PrivateKey(read_pem(data))
}

struct CustomClientVerifier {
    reject_client: bool,
    inner: AllowAnyAuthenticatedClient,
}

impl rustls::server::ClientCertVerifier for CustomClientVerifier {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        if self.reject_client {
            return Err(Error::General(
                "Client rejected for custom reason".to_string(),
            ));
        }

        Ok(ClientCertVerified::assertion())
    }
}
