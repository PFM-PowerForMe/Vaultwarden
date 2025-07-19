# syntax=docker/dockerfile:1

FROM alpine:edge AS git
ARG TAG
ENV TAG=${TAG:-main}
RUN apk update && apk add --no-cache \
	git
WORKDIR /tmp/
RUN git -c advice.detachedHead=false clone  --branch $TAG --depth=1 --recurse-submodules https://github.com/pfm-powerforme/vaultwarden.git vaultwarden
WORKDIR /tmp/vaultwarden/
RUN echo "$(git rev-parse HEAD)" > VW_VERSION


FROM ghcr.io/pfm-powerforme/vaultwarden-web:latest AS frontend


FROM docker.io/tonistiigi/xx AS xx


FROM docker.io/library/rust:slim AS backend
COPY --from=xx / /
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=UTC \
    TERM=xterm-256color \
    CARGO_HOME="/root/.cargo" \
    USER="root"
RUN apt-get update && \
    apt-get install -y \
        --no-install-recommends \
        clang \
        pkg-config \
        git \
        "libc6-$(xx-info debian-arch)-cross" \
        "libc6-dev-$(xx-info debian-arch)-cross" \
        "linux-libc-dev-$(xx-info debian-arch)-cross" && \
    xx-apt-get install -y \
        --no-install-recommends \
        gcc \
        libmariadb3 \
        libpq-dev \
        libpq5 \
        libssl-dev \
        zlib1g-dev && \
    apt-get download "libmariadb-dev-compat:$(xx-info debian-arch)" "libmariadb-dev:$(xx-info debian-arch)" && \
    dpkg --force-all -i ./libmariadb-dev*.deb && \
    echo "export CARGO_TARGET=$(xx-cargo --print-target-triple)" >> /env-cargo
RUN mkdir -pv "${CARGO_HOME}" && \
    rustup set profile minimal
RUN USER=root cargo new --bin /app
WORKDIR /app
RUN source /env-cargo && \
    if xx-info is-cross ; then \
        echo "export CC_$(echo "${CARGO_TARGET}" | tr '[:upper:]' '[:lower:]' | tr - _)=/usr/bin/$(xx-info)-gcc" >> /env-cargo && \
        echo "export CARGO_TARGET_$(echo "${CARGO_TARGET}" | tr '[:lower:]' '[:upper:]' | tr - _)_LINKER=/usr/bin/$(xx-info)-gcc" >> /env-cargo && \
        echo "export CROSS_COMPILE=1" >> /env-cargo && \
        echo "export PKG_CONFIG_ALLOW_CROSS=1" >> /env-cargo && \
        echo "export PKG_CONFIG_PATH=/usr/lib/$(xx-info)/pkgconfig" >> /env-cargo && \
        echo "# End of env-cargo" >> /env-cargo ; \
    fi && \
    cat /env-cargo
RUN source /env-cargo && \
    rustup target add "${CARGO_TARGET}"
COPY --from=git /tmp/vaultwarden/Cargo.* .
COPY --from=git /tmp/vaultwarden/rust-toolchain.toml rust-toolchain.toml
COPY --from=git /tmp/vaultwarden/build.rs build.rs
COPY --from=git /tmp/vaultwarden/macros/ macros/
COPY --from=git /tmp/vaultwarden/.git .git
COPY --from=git /tmp/vaultwarden/migrations/ migrations/
COPY --from=git /tmp/vaultwarden/src/ src/
COPY --from=git /tmp/vaultwarden/rustfmt.toml rustfmt.toml
COPY --from=git /tmp/vaultwarden/VW_VERSION VW_VERSION
RUN export VW_VERSION=$(cat VW_VERSION)
ARG CARGO_PROFILE=release
ARG DB=sqlite,mysql,postgresql
RUN source /env-cargo && \
    cargo build --features ${DB} --profile "${CARGO_PROFILE}" --target "${CARGO_TARGET}" && \
    if [[ "${CARGO_PROFILE}" == "dev" ]] ; then \
        ln -vfsr "/app/target/${CARGO_TARGET}/debug" /app/target/final ; \
    else \
        ln -vfsr "/app/target/${CARGO_TARGET}/${CARGO_PROFILE}" /app/target/final ; \
    fi


FROM docker.io/library/debian:stable
ENV ROCKET_PROFILE="release" \
    ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=80 \
    DEBIAN_FRONTEND=noninteractive
RUN mkdir /data && \
    apt-get update && apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb-dev-compat \
        libpq5 \
        openssl \
        tzdata \
        bash \
        tar \
        7zip \
        unzip \
        gnupg \
        expect \
        coreutils \
        cron && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai > /etc/timezone
RUN curl https://gosspublic.alicdn.com/ossutil/install.sh | bash
RUN mkdir -p /etc/default
COPY backup.sh /etc/cron.daily/backup
COPY gpg.sh gpg.sh
COPY start-debian.sh start-debian.sh
VOLUME /data
EXPOSE 80
WORKDIR /
COPY --from=git /tmp/vaultwarden/docker/healthcheck.sh healthcheck.sh
COPY --from=git /tmp/vaultwarden/docker/start.sh start.sh
COPY --from=frontend /web-vault web-vault/
COPY --from=backend /app/target/final/vaultwarden vaultwarden
RUN chmod +x /gpg.sh \
  && chmod +x /etc/cron.daily/backup \
  && chmod +x /start-debian.sh \
  && chmod +x /start.sh \
  && chmod +x /healthcheck.sh
HEALTHCHECK --interval=60s --timeout=10s CMD ["/healthcheck.sh"]
CMD ["/start-debian.sh"]
