ARG BASE_IMAGE="ubuntu:22.04"

ARG TARGET_LIST="x86_64-softmmu,aarch64-softmmu"

### BASE IMAGE
FROM $BASE_IMAGE as base
ARG BASE_IMAGE

# Download the Panda source code
RUN apt-get -qq update && apt-get -qq install -y git
RUN git clone https://github.com/panda-re/panda /panda/

# syz-rrr: instead of copying we take it from the clone just above
# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
RUN cp /panda/panda/dependencies/* /tmp
RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends curl $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG BASE_IMAGE
ARG TARGET_LIST

RUN apt-get -qq update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean && \
    python3 -m pip install --upgrade --no-cache-dir pip && \
    python3 -m pip install --upgrade --no-cache-dir "packaging>22.0" && \ 
    python3 -m pip install --upgrade --no-cache-dir "cffi>1.14.3" && \
    python3 -m pip install --upgrade --no-cache-dir "capstone" && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

# Then install capstone from source
RUN cd /tmp && \
    git clone https://github.com/capstone-engine/capstone/ -b 4.0.2 && \
    cd capstone/ && ./make.sh && make install && cd /tmp && \
    rm -rf /tmp/capstone && ldconfig

ENV PATH="/root/.cargo/bin:${PATH}"

# Sanity check to ensure cargo is installed
RUN cargo --help

# Install libosi
RUN cd /tmp && \
    git clone https://github.com/panda-re/libosi && \
    mkdir /tmp/libosi/build && cd /tmp/libosi/build && \
    cmake -GNinja .. && ninja && ninja package && dpkg -i libosi*.deb && \
    cd /tmp && rm -rf libosi/ && ldconfig

# Build and install panda
# Note we diable NUMA for docker builds because it causes make check to fail in docker
RUN git -C /panda submodule update --init dtc && \
    git -C /panda rev-parse HEAD > /usr/local/panda_commit_hash && \
    mkdir  /panda/build && cd /panda/build && \
    python3 -m pip install setuptools_scm && \
    python3 -m pip install build && \
    python3 -m setuptools_scm -r .. --strip-dev 2>/dev/null >/tmp/savedversion && \
    /panda/configure \
        --target-list="${TARGET_LIST}" \
        --prefix=/usr/local \
        --disable-numa \
        --enable-llvm && \
    rm -rf /panda/.git

RUN PRETEND_VERSION=$(cat /tmp/savedversion) make -C /panda/build -j "$(nproc)"

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
FROM builder as developer
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py && \
    PRETEND_VERSION=$(cat /tmp/savedversion) pip install -e . && \
    ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    cd /panda && \
    ( git config --get-regexp http > /dev/null && \
    git config --remove-section http.https://github.com/ || true ) && \
    git remote set-url origin https://github.com/panda-re/panda
WORKDIR /panda/

#### Install PANDA + pypanda from builder - Stage 4
FROM builder as installer
RUN  make -C /panda/build install && \
    rm -r /usr/local/lib/panda/*/cosi \
        /usr/local/lib/panda/*/cosi_strace \
        /usr/local/lib/panda/*/gdb \
        /usr/local/lib/panda/*/snake_hook \
        /usr/local/lib/panda/*/rust_skeleton

# Install pypanda
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py --install && \
    PRETEND_VERSION=$(cat /tmp/savedversion) pip install .
RUN python3 -m pip install --ignore-install pycparser && python3 -m pip install --force-reinstall --no-binary :all: cffi
# Build a whl too
RUN cd /panda/panda/python/core && \
    python3 create_panda_datatypes.py --install && \
    PRETEND_VERSION=$(cat /tmp/savedversion) python3 -m build --wheel .

RUN python3 -m pip show pandare

# BUG: PANDA sometimes fails to generate all the necessary files for PyPANDA. This is a temporary fix to detect and fail when this occurs
RUN ls -alt $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/
RUN bash -c "ls $(pip show pandare | grep Location: | awk '{print $2}')/pandare/autogen/panda_{aarch64_64,arm_32,mips64_64,mips_32,mipsel_32,ppc_32,ppc_64,x86_64_64,i386_32}.py"

# this layer is used to strip shared objects and change python data to be
# symlinks to the installed panda data directory
FROM installer as cleanup
RUN find /usr/local/lib/panda -name "*.so" -exec strip {} \;
RUN PKG=`pip show pandare | grep Location: | awk '{print $2}'`/pandare/data; \
    rm -rf $PKG/pc-bios && ln -s /usr/local/share/panda $PKG/pc-bios; \
    for arch in `find $PKG -name "*-softmmu" -type d -exec basename {} \;` ; do \
        ARCHP=$PKG/$arch; \
        SARCH=`echo $arch | cut -d'-' -f 1`; \
        rm $ARCHP/libpanda-$SARCH.so $ARCHP/llvm-helpers-$SARCH.bc; \
        ln -s /usr/local/share/panda/llvm-helpers-$SARCH.bc $ARCHP/llvm-helpers-$SARCH.bc1; \
        ln -s /usr/local/bin/libpanda-$SARCH.so $ARCHP/libpanda-$SARCH.so; \
        rm -rf $ARCHP/panda/plugins; \
        ln -s /usr/local/lib/panda/$SARCH/ $ARCHP/panda/plugins; \
    done

### Copy files for panda+pypanda from installer  - Stage 5
FROM base as panda

# Include dependency lists for packager
COPY --from=base /tmp/base_dep.txt /tmp
COPY --from=base /tmp/build_dep.txt /tmp

# Copy panda + libcapstone.so* + libosi libraries
COPY --from=cleanup /usr/local /usr/local
COPY --from=cleanup /usr/lib/libcapstone* /usr/lib/
COPY --from=cleanup /lib/libosi.so /lib/libiohal.so /lib/liboffset.so /lib/

# Workaround issue #901 - ensure LD_LIBRARY_PATH contains the panda plugins directories
ENV LD_LIBRARY_PATH /usr/local/lib/python3.10/dist-packages/pandare/data/x86_64-softmmu/panda/plugins/:/usr/local/lib/python3.10/dist-packages/pandare/data/i386-softmmu/panda/plugins/:/usr/local/lib/python3.10/dist-packages/pandare/data/arm-softmmu/panda/plugins/:/usr/local/lib/python3.10/dist-packages/pandare/data/ppc-softmmu/panda/plugins/:/usr/local/lib/python3.10/dist-packages/pandare/data/mips-softmmu/panda/plugins/:/usr/local/lib/python3.10/dist-packages/pandare/data/mipsel-softmmu/panda/plugins/
#PANDA_PATH is used by rust plugins
ENV PANDA_PATH /usr/local/lib/python3.10/dist-packages/pandare/data

# Ensure runtime dependencies are installed for our libpanda objects and panda plugins
RUN ldconfig && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/libpanda-*.so | grep 'not found'); then exit 1; fi && \
    if (ldd /usr/local/lib/python*/dist-packages/pandare/data/*-softmmu/panda/plugins/*.so | grep 'not found'); then exit 1; fi

# Default jupyter's cwd to /root/
WORKDIR /root

# Install runtime dependencies
RUN apt-get -qq update
RUN apt-get -qq install -y gcc libguestfs-tools make flex bison libelf-dev bc linux-image-generic pahole gdb

# Compile and install bpftool
RUN cd /tmp && git clone --branch v7.5.0 --recurse-submodules https://github.com/libbpf/bpftool.git
RUN cd /tmp/bpftool/src && make && make install

# Install python dependencies
RUN pip install --no-cache-dir --upgrade pip jupyter protobuf pandas lxml pygdbmi perfetto

# Start the jupyter server automatically
ENV SHELL=/bin/bash
CMD jupyter notebook --allow-root --no-browser --ip=* --NotebookApp.token=rrr
