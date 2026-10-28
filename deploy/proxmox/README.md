# Proxmox installation

Use a dedicated stopped VM with host CPU/RDSEED, one core, 2 GiB fixed RAM, ballooning disabled, SeaBIOS, i440fx, VirtIO networking and serial diagnostics. Hermit boots directly from the loader and Bathysign image; no guest Linux disk or SSH service is required.

Provision a protected host directory, then run `provision-host.py --base /var/lib/bathysign --server-name bathysign.internal` on the authorized host. This creates provisioning TLS and a read-only virtiofs service; it does not import Android keys or GitHub credentials. CA private keys remain outside the guest export. Install reviewed configuration and secrets separately.

The host requires virtiofsd 1.13 or later with `--readonly` support. Check the installed daemon's `--help` output before provisioning.

Copy boot artifacts to `BASE/hermit-loader` and `BASE/bathysign`. Run `configure-vm.py --vmid YOUR_ID --name bathysign --bridge YOUR_BRIDGE --mac YOUR_MAC` with optional `--vlan`, `--mtu`, `--base`, and `--socket`. The script checks the existing VM name and stopped state before mutation. MTU defaults to 1500; only increase it after verifying the complete network path. `qm showcmd` should show direct boot, shared memfd RAM, the read-only root filesystem socket and VirtIO networking.

Choose DHCP/DNS/firewall/ingress settings for your installation. Expose only exact `POST /webhooks/github` publicly. Keep health/readiness/metrics private, verify backend TLS, and allow the signer outbound HTTPS to GitHub/artifact storage, authenticated trust metadata, and its collector. Never migrate/snapshot the VM without a key-handling and durable-ledger recovery procedure.

The generated leaf certificate lasts 90 days. Renew it with the same CA/server name before expiry, preserve the CA pin, and coordinate a guest restart. `provision-host.py` initializes certificates only; it is not a renewal service.
