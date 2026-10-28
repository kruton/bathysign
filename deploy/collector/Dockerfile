FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
COPY --chmod=0555 bathysign-collector /usr/local/bin/bathysign-collector
USER 65532:65532
ENV BATHYSIGN_COLLECTOR_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/bathysign-collector"]
