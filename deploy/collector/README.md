# External audit collector

Build `bathysign-collector` with Cargo's `collector` feature and package it with this Dockerfile. Mount `collector.json`, a TLS certificate/key, a private bearer token and persistent SQLite storage. Set `BATHYSIGN_COLLECTOR_CONFIG` to the configuration path. Run one replica with a Recreate update strategy.

The collector owns policy revisions, durable jobs, audit event hash chains and TUF checkpoint history. Keep its API and metrics private, require bearer authentication and verify TLS. Use transactionally consistent SQLite backups and retained audit anchors. Android private signing keys belong only in the signer's read-only export.
