FROM pquic/pquic:latest AS pquic_build
FROM martenseemann/quic-network-simulator-endpoint:latest

ENV TZ=Europe/Brussels
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y openssl libarchive-dev google-perftools && \
    rm -rf /var/lib/apt/lists/*

COPY --from=pquic_build /src/pquic/picoquicdemo .
COPY --from=pquic_build /src/pquic/plugins plugins
COPY --from=pquic_build /src/pquic/certs/cert.pem certs/cert.pem
COPY --from=pquic_build /src/pquic/certs/key.pem certs/priv.key

# copy run script and run it
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
