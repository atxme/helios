//! A disposable, mutually pinned private channel shared by lifecycle tests.

use std::{path::Path, sync::Arc, time::Duration};

use aether::certificates::encoding::DerCertificate;
use astra_channel::{AstraChannelHandler, ChannelIdentity};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

pub(crate) struct ServerTask(tokio::task::JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Uses the shipped TLS configuration and HTTP routes, with an isolated peer.
pub(crate) async fn channel(
    state_dir: &Path,
    handler: Arc<dyn AstraChannelHandler>,
) -> (crate::gateway::GatewayChannel, ServerTask) {
    let astra_certificate = crate::gateway::initialize(state_dir, false).expect("Astra identity");
    let mut params = CertificateParams::new(vec![astra_channel::INTERNAL_SERVER_NAME.into()])
        .expect("gateway parameters");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
    let key = KeyPair::generate().expect("gateway TLS key");
    let certificate = params.self_signed(&key).expect("gateway certificate");
    let gateway_certificate = DerCertificate::new(certificate.der().to_vec()).expect("DER");
    let identity = ChannelIdentity {
        certificate_der: gateway_certificate.as_bytes().to_vec(),
        private_key_der: key.serialize_der(),
    };
    let config =
        astra_channel::server_config(&identity, &astra_certificate).expect("pinned server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback port");
    let address = listener.local_addr().expect("listener address");
    drop(listener);
    let router = astra_channel::router(handler);
    let task = ServerTask(tokio::spawn(async move {
        astra_channel::serve(address, config, router, astra_channel::INTERNAL_PREFIX)
            .await
            .expect("private listener");
    }));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("private listener ready");
    let channel = crate::gateway::GatewayChannel::open(state_dir, address, &gateway_certificate)
        .expect("mutually pinned client");
    (channel, task)
}
