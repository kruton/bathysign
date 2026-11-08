FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab
COPY --chmod=0555 bathysign-collector /usr/local/bin/bathysign-collector
USER 65532:65532
ENV BATHYSIGN_COLLECTOR_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/bathysign-collector"]
