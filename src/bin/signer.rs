#[cfg(target_os = "hermit")]
use hermit as _;
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    bathysign::initialize_crypto()?;
    tracing_subscriber::fmt()
        .with_env_filter("bathysign=info")
        .init();
    tracing::info!("Bathysign: strict entropy profile v1");
    let path = std::env::var_os("BATHYSIGN_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/root/config.json".into());
    if !path.try_exists()? && std::path::Path::new("/root/bootstrap.json").try_exists()? {
        return bathysign::server::provisioning(std::path::Path::new("/root/bootstrap.json")).await;
    }
    let loaded = bathysign::config::Loaded::read(&path)?;
    bathysign::server::run(loaded).await
}
