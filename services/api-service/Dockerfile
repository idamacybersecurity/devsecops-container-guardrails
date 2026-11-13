FROM debian:trixie-slim AS python-builder

ARG CPYTHON_BASE_COMMIT=7d9da9208fc3dc126bebca6844dfe312afc43c34
ARG CPYTHON_EXPECTED_TREE=a1a3f69e297862f35e0ae8ebbb526ba3057a0d94


ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       git \
       build-essential \
       pkg-config \
       libssl-dev \
       zlib1g-dev \
       libbz2-dev \
       libreadline-dev \
       libsqlite3-dev \
       libffi-dev \
       liblzma-dev \
       libncurses-dev \
       libgdbm-dev \
       libexpat1-dev \
       uuid-dev \
    && rm -rf /var/lib/apt/lists/*

COPY build/cpython-patches/ /tmp/cpython-patches/

RUN git clone https://github.com/python/cpython.git /src/cpython \
    && cd /src/cpython \
    && git checkout --detach "$CPYTHON_BASE_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$CPYTHON_BASE_COMMIT" \
    && git -c user.name="CPython Patch Builder" -c user.email="builder@localhost" am /tmp/cpython-patches/*.patch \
    && test "$(git rev-list --count "$CPYTHON_BASE_COMMIT..HEAD")" -eq 3 \
    && test "$(git rev-parse HEAD^{tree})" = "$CPYTHON_EXPECTED_TREE" \
    && echo "PASS: CPython security patches reproduce the verified source tree." \
    && git log --oneline --reverse "$CPYTHON_BASE_COMMIT..HEAD"

WORKDIR /src/cpython

RUN ./configure \
      --prefix=/opt/python314 \
      --with-openssl=/usr \
      --with-ensurepip=install \
      --disable-test-modules \
      --enable-shared \
    && make -j2 \
    && make install

ENV LD_LIBRARY_PATH=/opt/python314/lib

WORKDIR /build

COPY services/api-service/requirements.txt .

RUN /opt/python314/bin/python3.14 -m pip install \
      --no-cache-dir \
      -r requirements.txt \
    && /opt/python314/bin/python3.14 -m pip check


FROM debian:trixie-slim

ENV PATH=/opt/python314/bin:$PATH \
    LD_LIBRARY_PATH=/opt/python314/lib \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       libssl3t64 \
       zlib1g \
       libbz2-1.0 \
       libreadline8t64 \
       libsqlite3-0 \
       libffi8 \
       liblzma5 \
       libncursesw6 \
       libgdbm6t64 \
       libuuid1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /opt/python314 /opt/python314

WORKDIR /app

COPY services/api-service/app.py .

RUN useradd --create-home --uid 10001 appuser

USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
