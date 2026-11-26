FROM gcr.io/distroless/cc-debian13:nonroot@sha256:29ee70762214fe8190cea04ef1c0a84a8365879e047ce8f911ae5a5ab2355fa2
COPY --chmod=0555 bathysign-collector /usr/local/bin/bathysign-collector
USER 65532:65532
ENV BATHYSIGN_COLLECTOR_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/bathysign-collector"]
