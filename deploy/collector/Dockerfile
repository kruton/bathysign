FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
COPY --chmod=0555 bathysign-collector /usr/local/bin/bathysign-collector
USER 65532:65532
ENV BATHYSIGN_COLLECTOR_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/bathysign-collector"]
