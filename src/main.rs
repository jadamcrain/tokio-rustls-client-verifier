use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
use tokio_rustls::rustls::server::danger::ClientCertVerified;
use tokio_rustls::rustls::server::WebPkiClientVerifier;


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
    let client_result = connector.connect("server42".try_into().unwrap(), client).await;
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

fn root_cert_store() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(read_pem(CA_CRT).into()).unwrap();
    roots.into()
}

fn configure_server(versions: Versions, reject_client: bool) -> tokio_rustls::TlsAcceptor {

    let verifier = {
        let verifier = WebPkiClientVerifier::builder(root_cert_store()).build().unwrap();
        Arc::new(CustomClientVerifier {
            reject_client,
            inner: verifier
        })
    };

    let server_cert = read_cert(SERVER_CRT);
    let server_key = read_key(SERVER_KEY);

    let config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key.into())
        .unwrap();

    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn configure_client(versions: Versions) -> tokio_rustls::TlsConnector {

    let client_cert = read_cert(CLIENT_CRT);
    let client_key = read_key(CLIENT_KEY);

    let config = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(root_cert_store())
        .with_client_auth_cert(vec![client_cert], client_key.into())
        .unwrap();

    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn read_pem(data: &str) -> Vec<u8> {
    let pem = pem::parse(data).unwrap();
    pem.contents().to_vec()
}

fn read_cert(data: &str) -> CertificateDer<'static> {
    read_pem(data).to_vec().into()
}

fn read_key(data: &str) -> PrivatePkcs8KeyDer<'static> {
    read_pem(data).to_vec().into()
}

#[derive(Debug)]
struct CustomClientVerifier {
    reject_client: bool,
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
}

impl rustls::server::danger::ClientCertVerifier for CustomClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<ClientCertVerified, Error> {
        self.inner.verify_client_cert(end_entity, intermediates, now)?;

        if self.reject_client {
            return Err(Error::General("Client rejected for custom reason".to_string()));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

