# Docker image for building and running PQUIC
FROM ubuntu:20.04

ENV TZ=Europe/Brussels
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && \
    apt-get install -y build-essential git cmake \
    openssl libssl-dev libarchive-dev google-perftools libgoogle-perftools-dev pkg-config clang llvm && \
    rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/bin/clang /usr/bin/clang-6.0 && \
    ln -s /usr/bin/llc /usr/bin/llc-6.0

RUN mkdir /src
WORKDIR /src

RUN echo install Test::TCP | perl -MCPAN -
RUN echo install Scope::Guard | perl -MCPAN -

RUN git clone https://github.com/h2o/picotls.git && \
    cd picotls && \
    git submodule init && \
    git submodule update && \
    cmake . && \
    make && \
    make check


RUN mkdir /src/pquic
COPY . /src/pquic/
WORKDIR /src/pquic/

RUN git submodule init && \
    git submodule update

RUN cd ubpf/vm && make

RUN cd picoquic/michelfralloc && make

RUN cmake . && make

RUN cd plugins && make
