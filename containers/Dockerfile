FROM docker.io/library/alpine:edge AS git
ARG TAG
ENV TAG=${TAG:-main}
RUN apk update && apk add --no-cache \
	git
WORKDIR /
RUN git -c advice.detachedHead=false clone --branch $TAG --depth=1 --recurse-submodules https://github.com/pfm-powerforme/vaultwarden.git source
WORKDIR /source/
RUN echo "$(git rev-parse HEAD)" > VW_VERSION


FROM ghcr.io/pfm-powerforme/vaultwarden-frontend:latest AS frontend


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
        libmariadb-dev \
        libpq-dev \
        libpq5 \
        libssl-dev \
        zlib1g-dev && \
    apt-get download "libmariadb-dev-compat:$(xx-info debian-arch)" "libmariadb-dev:$(xx-info debian-arch)" && \
    dpkg --force-all -i ./libmariadb-dev*.deb && \
    echo "export CARGO_TARGET=$(xx-cargo --print-target-triple)" >> /env-cargo
RUN mkdir -pv "${CARGO_HOME}" && \
    rustup set profile minimal
RUN USER=root cargo new --bin /backend
WORKDIR /backend/
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
COPY --from=git /source/Cargo.* .
COPY --from=git /source/rust-toolchain.toml rust-toolchain.toml
COPY --from=git /source/build.rs build.rs
COPY --from=git /source/macros/ macros/
COPY --from=git /source/.git .git
COPY --from=git /source/migrations/ migrations/
COPY --from=git /source/src/ src/
COPY --from=git /source/rustfmt.toml rustfmt.toml
COPY --from=git /source/VW_VERSION VW_VERSION
RUN export VW_VERSION=$(cat VW_VERSION)
ARG CARGO_PROFILE=release-micro
ARG DB=sqlite,mysql,postgresql
RUN source /env-cargo && \
    cargo build --features ${DB} --profile "${CARGO_PROFILE}" --target "${CARGO_TARGET}" && \
    if [[ "${CARGO_PROFILE}" == "dev" ]] ; then \
        ln -vfsr "/backend/target/${CARGO_TARGET}/debug" /backend/target/final ; \
    else \
        ln -vfsr "/backend/target/${CARGO_TARGET}/${CARGO_PROFILE}" /backend/target/final ; \
    fi


FROM docker.io/library/debian:stable AS scripts-builder
RUN apt-get update && apt-get install -y \
        --no-install-recommends \
        binutils \
        python3-dev \
        python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY backup.py /PY/backup.py
WORKDIR /PY
RUN pip3 install alibabacloud-oss-v2 --break-system-packages
RUN pip3 install pyinstaller --break-system-packages
RUN pyinstaller --noconfirm --name backup -F backup.py

FROM ghcr.io/pfm-powerforme/s6-base:latest AS runtime
ENV ROCKET_PROFILE="production" \
     ROCKET_ADDRESS=127.0.0.1 \
     ROCKET_PORT=8000
COPY rootfs/ /
RUN chmod +x /usr/local/sbin/setup && setup
COPY --from=scripts-builder /PY/dist/backup /usr/local/sbin/backup
COPY --from=frontend /frontend/ /vw/web-vault/
COPY --from=backend /backend/target/final/vaultwarden /vw/vaultwarden
RUN chmod +x /usr/local/sbin/backup && \
     chmod +x /vw/vaultwarden

WORKDIR /vw/
VOLUME /vw/data
EXPOSE 8080
HEALTHCHECK --timeout=60s CMD netstat -tulnp | grep -q ':8080\b' && exit 0 || exit 1
