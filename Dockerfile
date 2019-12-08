# Intermediate container for Knot DNS build (not persistent)
FROM debian:stable AS knot-dns-build
ARG KNOT_DNS_VERSION=v2.9.0

# Build dependencies
ENV KNOT_DNS_BUILD_DEPS git-core build-essential libtool autoconf pkg-config \
	libgnutls28-dev	libprotobuf-dev libprotobuf-c-dev libfstrm-dev
ENV KNOT_RESOLVER_BUILD_DEPS build-essential pkg-config bsdmainutils liblmdb-dev \
	libluajit-5.1-dev libuv1-dev libprotobuf-dev libprotobuf-c-dev \
	libfstrm-dev luajit lua-sec lua-socket libssl-dev
ENV BUILDENV_DEPS ${KNOT_DNS_BUILD_DEPS} ${KNOT_RESOLVER_BUILD_DEPS}
RUN echo "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/backports.list
RUN apt-get update -qq && \
	apt-get -y -qqq install ${BUILDENV_DEPS} && \
	apt-get -y -qqq install -t stretch-backports meson

# Install Knot DNS from sources
RUN git clone -b $KNOT_DNS_VERSION --depth=1 https://gitlab.labs.nic.cz/knot/knot-dns.git /tmp/knot-dns && \
	cd /tmp/knot-dns && \
	autoreconf -if && \
	./configure --disable-static --disable-fastparser --disable-documentation \
		--disable-daemon --disable-utilities --with-lmdb=no && \
	make -j4 install && \
	ldconfig

# Copy libknot, libdnssec, libzscanner to runtime
RUN mkdir -p /tmp/root/usr/local/include /tmp/root/usr/local/lib /tmp/root/usr/local/lib/pkgconfig && \
	cp -rt /tmp/root/usr/local/include /usr/local/include/libknot /usr/local/include/libdnssec /usr/local/include/libzscanner && \
	cp -rt /tmp/root/usr/local/lib /usr/local/lib/libknot* /usr/local/lib/libdnssec* /usr/local/lib/libzscanner* && \
	cp -rt /tmp/root/usr/local/lib/pkgconfig /usr/local/lib/pkgconfig/libknot.pc /usr/local/lib/pkgconfig/libdnssec.pc /usr/local/lib/pkgconfig/libzscanner.pc


# Intermediate container with runtime dependencies
FROM debian:stable-slim AS runtime

# Install runtime dependencies
ENV KNOT_DNS_RUNTIME_DEPS libgnutls30
ENV KNOT_RESOLVER_RUNTIME_DEPS liblmdb0 luajit libluajit-5.1-2 libuv1 lua-sec lua-socket
ENV KNOT_RESOLVER_RUNTIME_DEPS_HTTP lua-http lua-mmdb
ENV KNOT_RESOLVER_RUNTIME_DEPS_EXTRA libfstrm0 lua-cqueues
ENV KNOT_RESOLVER_RUNTIME_DEPS_SSL ca-certificates
ENV RUNTIME_DEPS ${KNOT_DNS_RUNTIME_DEPS} ${KNOT_RESOLVER_RUNTIME_DEPS} \
    ${KNOT_RESOLVER_RUNTIME_DEPS_HTTP} ${KNOT_RESOLVER_RUNTIME_DEPS_EXTRA} \
    ${KNOT_RESOLVER_RUNTIME_DEPS_SSL}
RUN apt-get update -qq && \
	apt-get install -y -qqq ${RUNTIME_DEPS} && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*


# Intermediate container for Knot Resolver build
FROM knot-dns-build AS build
ENV KRES_VERSION v4.3.0

ENV BUILD_DATE 2019-12-08
RUN git clone https://gitlab.labs.nic.cz/knot/knot-resolver.git /tmp/knot-resolver && \
    cd /tmp/knot-resolver && git fetch --all --tags --prune && git checkout tags/$KRES_VERSION && cd /tmp/knot-resolver && \
    git submodule update --init

RUN mkdir /tmp/whalebone
WORKDIR /tmp/whalebone
COPY . ./
RUN cp -a /tmp/whalebone/. /tmp/knot-resolver/modules/ && \
        cd /tmp/knot-resolver/modules && \
        patch -i meson.build.patch meson.build

# Build Knot Resolver
RUN cd /tmp/knot-resolver && \
	meson build_docker --buildtype=plain --prefix=/usr --libdir=lib -Dc_args="-O2 -fstack-protector -g" && \
	DESTDIR=/tmp/root ninja -C build_docker install 

# Final container
FROM runtime

RUN mkdir /var/log/whalebone

# Export DNS over UDP & TCP, DNS-over-TLS, web interface
EXPOSE 53/UDP 53/TCP 853/TCP 8053/TCP

# Fetch Knot Resolver + Knot DNS libraries from build image
COPY --from=build /tmp/root/ /
COPY ./config.docker /etc/knot-resolver/kresd.conf
RUN ldconfig

ENTRYPOINT ["/usr/sbin/kresd"]
CMD ["-c", "/etc/knot-resolver/kresd.conf"]