#!/usr/bin/env python3
"""Disposable Hermit/TLS/ledger/webhook smoke test. Never contacts GitHub."""
import argparse, base64, hashlib, hmac, json, os, pathlib, signal, ssl, subprocess, tempfile, time, urllib.request, urllib.error
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--loader", required=True, type=pathlib.Path)
p.add_argument("--admin", type=pathlib.Path, default=ROOT/"target/debug/bathysign-admin")
p.add_argument("--collector", type=pathlib.Path, default=ROOT/"target/debug/bathysign-collector")
p.add_argument("--tcg", action="store_true")
p.add_argument("--trust-checkpoint", type=pathlib.Path, help="Explicit prepared checkpoint for dynamic public TUF trust")
p.add_argument("--image", type=pathlib.Path, default=ROOT/"target/x86_64-unknown-hermit/release/bathysign")
p.add_argument("--gdb-port", type=int)
p.add_argument("--idle-close-check", action="store_true", help="Verify idle TCP close reaches peers without extra traffic")
a = p.parse_args()
request_timeout=600 if a.gdb_port else 45
def run(args):
    subprocess.run([str(x) for x in args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix="bathysign-smoke-") as temporary:
    d=pathlib.Path(temporary); secret=d/"secrets";secret.mkdir(mode=0o700)
    for name in ["app", "apk", "upload", "transparency", "receipt", "ca", "tls"]:
        run(["openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",secret/(name+".key.pem")])
        args=["openssl","req","-new","-x509","-key",secret/(name+".key.pem"),"-out",secret/(name+".pem"),"-days","2","-subj","/CN=Local-test-"+name]
        if name=="ca": args += ["-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"]
        if name=="tls":
            run(["openssl","req","-new","-key",secret/"tls.key.pem","-out",secret/"tls.csr","-subj","/CN=localhost"])
            extensions=secret/"tls.ext"
            extensions.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.2.2\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
            run(["openssl","x509","-req","-in",secret/"tls.csr","-CA",secret/"ca.pem","-CAkey",secret/"ca.key.pem","-CAcreateserial","-out",secret/"tls.pem","-days","2","-extfile",extensions])
        else: run(args)
    subprocess.run(["openssl","verify","-x509_strict","-purpose","sslserver","-CAfile",secret/"ca.pem",secret/"tls.pem"],check=True)
    (secret/"audit-token").write_text("test-audit-"+os.urandom(32).hex())
    webhook=os.urandom(32);(secret/"webhook-secret").write_bytes(webhook)
    run([a.admin,"init","--key",secret/"apk.key.pem","--cert",secret/"apk.pem","--out",secret/"lineage.bin"])
    root=ROOT/"tests/fixtures/public-trusted-root.json";(secret/"public-root.json").write_bytes(root.read_bytes())
    keys={}
    for name in ["apk","upload","transparency","receipt"]:
        der=ssl.PEM_cert_to_DER_cert((secret/(name+".pem")).read_text())
        keys[name]={"private_key":"/root/"+name+".key.pem","certificate":"/root/"+name+".pem","fingerprint":hashlib.sha256(der).hexdigest()}
    config={"listen":"0.0.0.0:8443","tls_certificate":"/root/tls.pem","tls_private_key":"/root/tls.key.pem","github_app_id":1,"github_app_private_key":"/root/app.key.pem","webhook_secret":"/root/webhook-secret","audit_url":"https://10.0.2.2:18443","audit_token":"/root/audit-token","audit_ca_certificate":"/root/ca.pem","keys":keys,"trust_roots":{"public":{"file":"/root/public-root.json","sha256":sha(root),"valid_until":int(time.time())+3600}},"repositories":[{"id":1,"name":"example/test","workflow":".github/workflows/build.yml","refs":["refs/heads/main"],"events":["push"],"runners":["github-hosted"],"visibility":"public","package":"test.example","apk_artifact":"unsigned-apk","aab_artifact":"unsigned-aab","apk_file":"app.apk","aab_file":"app.aab","revision":1,"archive_resource":None,"signing":{"original_key":"apk","current_key":"apk","upload_key":"upload","transparency_key":"transparency","lineage":"/root/lineage.bin","lineage_sha256":sha(secret/"lineage.bin"),"hybrid":None}}]}
    repo=config["repositories"][0]
    workflow=repo.pop("workflow")
    repo["callers"]=[workflow]
    repo["builder"]={"repository":"kruton/bathysign","repository_id":2,"workflow":".github/workflows/bathysign-attest.yml","refs":["refs/heads/bathysign-v1"]}
    repo["finalizer"]={**repo["builder"],"workflow":".github/workflows/bathysign-finalize.yml"}
    repo["receipt_namespace"]="bathysign"
    repo["receipt_key"]="receipt"
    repo["profiles"]={"default":{field:repo.pop(field) for field in ["package","apk_artifact","aab_artifact","apk_file","aab_file","signing","archive_resource"]}}
    config["version"]=3
    if a.trust_checkpoint:
        config["version"]=4
        config["trust_roots"]={}
        config["trust_authority"]=json.loads(a.trust_checkpoint.read_bytes())["authority"]
    (secret/"config.json").write_text(json.dumps(config))
    collector={"listen":"0.0.0.0:18443","tls_certificate":str(secret/"tls.pem"),"tls_private_key":str(secret/"tls.key.pem"),"token_file":str(secret/"audit-token"),"database":str(d/"audit.sqlite")}
    collector_file=d/"collector.json";collector_file.write_text(json.dumps(collector))
    context=ssl.create_default_context(cafile=str(secret/"ca.pem"))
    initial_secret_files={path.name:sha(path) for path in secret.iterdir() if path.is_file()}
    processes=[]
    try:
        with (d/"collector.log").open("w") as log:
            processes.append(subprocess.Popen([a.collector],env={**os.environ,"BATHYSIGN_COLLECTOR_CONFIG":str(collector_file)},stdout=log,stderr=log,start_new_session=True))
        guest_log=d/"guest.log"
        with guest_log.open("w") as log:
            args=["python3",ROOT/"scripts/run-qemu.py","--secrets",secret,"--loader",a.loader,"--image",a.image,"--port","18444","--memory","1G","--test-unsandboxed-fs"]
            if a.tcg: args.append("--tcg")
            if a.gdb_port: args += ["--gdb-port",str(a.gdb_port)]
            processes.append(subprocess.Popen([str(x) for x in args],stdout=log,stderr=log,start_new_session=True))
        if a.trust_checkpoint:
            for _ in range(120):
                try:
                    with urllib.request.urlopen("https://localhost:18444/healthz",context=context,timeout=2) as response:
                        if response.status==200: break
                except Exception: pass
                time.sleep(.5)
            else: raise AssertionError("Health unavailable while trust is uninitialized")
            try:
                urllib.request.urlopen("https://localhost:18444/readyz",context=context,timeout=5)
                raise AssertionError("Uninitialized trust must not be ready")
            except urllib.error.HTTPError as error: assert error.code==503
            import sqlite3
            with sqlite3.connect(d/"audit.sqlite") as db:
                assert db.execute("SELECT count(*) FROM trust_heads").fetchone()[0]==0
            print("PASS: health remains available and trust cannot initialize itself",flush=True)
            subprocess.run([str(a.collector),"initialize-trust",str(a.trust_checkpoint.resolve())],env={**os.environ,"BATHYSIGN_COLLECTOR_CONFIG":str(collector_file)},check=True)
        readiness_error=None
        for _ in range(720 if a.trust_checkpoint else 120):
            try:
                with urllib.request.urlopen("https://localhost:18444/readyz",context=context,timeout=2) as r:
                    if r.status==200: break
            except Exception as error: readiness_error=error
            if processes[0].poll() is not None: raise RuntimeError("Collector stopped with status "+str(processes[0].returncode))
            if processes[-1].poll() is not None: raise RuntimeError("Guest stopped: "+guest_log.read_text()[-8000:])
            time.sleep(.5)
        else: raise RuntimeError("Guest did not become ready ("+str(readiness_error)+"): "+guest_log.read_text()[-8000:])
        body=b"{}"
        def post(signature, data=body, event="ping"):
            result=subprocess.run(["curl","--silent","--show-error","--max-time",str(request_timeout),"--cacert",str(secret/"ca.pem"),"--output","/dev/null","--write-out","%{http_code}","--header","Content-Type: application/json","--header","X-GitHub-Event: "+event,"--header","X-Hub-Signature-256: sha256="+signature,"--data-binary","@-","https://localhost:18444/webhooks/github"],input=data,capture_output=True,check=True)
            return int(result.stdout)
        assert post("00"*32)==401
        assert post(hmac.new(webhook,body,hashlib.sha256).hexdigest())==200
        if a.idle_close_check:
            import http.client, select
            idle = http.client.HTTPSConnection("localhost", 18444, context=context, timeout=5)
            idle.request("GET", "/healthz")
            response = idle.getresponse()
            assert response.status == 200
            response.read()
            assert select.select([idle.sock], [], [], 70)[0], "Idle close did not reach peer; next proxied request would use a stale connection"
            idle.close()
        import sqlite3
        with sqlite3.connect(d/"audit.sqlite") as db:
            assert db.execute("SELECT count(*) FROM policies").fetchone()[0]==1
            assert db.execute("SELECT count(*) FROM jobs").fetchone()[0]==0
        if a.trust_checkpoint:
            with urllib.request.urlopen("https://localhost:18444/metrics",context=context,timeout=10) as response:
                assert 'bathysign_trust_ready{authority="sigstore-public"} 1' in response.read().decode()
            with sqlite3.connect(d/"audit.sqlite") as db:
                assert db.execute("SELECT count(*) FROM trust_checkpoints").fetchone()[0] >= 1
        # Stop the collector before any eligible event is submitted. The
        # webhook must refuse it rather than enqueue or contact GitHub.
        os.killpg(processes[0].pid,signal.SIGTERM); processes[0].wait(timeout=5)
        event=json.dumps({"action":"completed","repository":{"id":1,"full_name":"example/test"},"workflow":{"path":".github/workflows/build.yml"},"workflow_run":{"id":2,"run_attempt":1,"head_sha":"c"*40,"conclusion":"success"}}).encode()
        assert post(hmac.new(webhook,event,hashlib.sha256).hexdigest(), event, "workflow_run")==503
        try:
            if a.gdb_port: print("Inspecting readiness during collector outage",flush=True)
            urllib.request.urlopen("https://localhost:18444/readyz",context=context,timeout=request_timeout)
            raise AssertionError("Readiness must fail during ledger outage")
        except urllib.error.HTTPError as error: assert error.code==503
        assert initial_secret_files=={path.name:sha(path) for path in secret.iterdir() if path.is_file()}
        print("PASS: Hermit read-only secrets, VirtIO networking, TLS, durable policy activation, HMAC, fail-closed ledger outage" + (", idle TCP close" if a.idle_close_check else ""))
    except Exception:
        print("Guest log:", guest_log.read_text()[-5000:])
        print("Collector log:", (d/"collector.log").read_text()[-2000:])
        raise
    finally:
        for process in reversed(processes):
            try: os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
