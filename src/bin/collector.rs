fn main() -> anyhow::Result<()> {
    bathysign::initialize_crypto()?;
    let path = std::env::var_os("BATHYSIGN_COLLECTOR_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "collector.json".into());
    let config: bathysign::collector::CollectorConfig =
        serde_json::from_slice(&std::fs::read(path)?)?;
    let token = bathysign::config::read_secret(&config.token_file)?;
    let store = bathysign::collector::Store::open(
        &config.database,
        std::str::from_utf8(&token)?.trim().as_bytes(),
    )?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !args.is_empty() {
        anyhow::ensure!(
            args.len() == 2 && args[0] == "initialize-trust",
            "usage: collector [initialize-trust CHECKPOINT]"
        );
        let checkpoint = serde_json::from_slice(&std::fs::read(&args[1])?)?;
        println!("{}", store.trust_initialize(&checkpoint)?);
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(bathysign::server::serve_tls(
        bathysign::collector::router(store),
        &config.listen,
        &config.tls_certificate,
        &config.tls_private_key,
    ))
}
