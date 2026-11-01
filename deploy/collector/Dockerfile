FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --chmod=0555 bathysign-collector /usr/local/bin/bathysign-collector
USER 65532:65532
ENV BATHYSIGN_COLLECTOR_CONFIG=/config/collector.json
ENTRYPOINT ["/usr/local/bin/bathysign-collector"]
