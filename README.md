# PQUIC

The PQUIC implementation, a framework that enables QUIC clients and servers to dynamically exchange protocol plugins that extend the protocol on a per-connection basis.

The current PQUIC implementation supports the draft-29 version of the QUIC specification.

# Using Docker

Docker builds exist on (Docker Hub)[https://hub.docker.com/r/pquic/pquic/].
They contain a build of the master branch, along with the necessary tools to build PQUIC.

~~~
    docker run -it pquic/pquic
    ./picoquicdemo -h
~~~


# Building PQUIC

More detailed instructions are available at: https://pquic.org

PQUIC is developed in C, and is based on picoquic (https://github.com/private-octopus/picoquic).
It can be built under Linux (the support of Windows is not provided yet).
Building the project requires first managing the dependencies, Picotls, uBPF, michelfralloc, libarchive
and OpenSSL.

## PQUIC on Linux

To build PQUIC on Linux, you need to:

 * Install and build Openssl on your machine

 * Install libarchive. It is usually found in distribution packages (e.g., `apt install libarchive-dev`) or on (the LibArchive page)[http://libarchive.org/]

 * Clone and compile Picotls (https://github.com/p-quic/picotls), using cmake as explained in the Picotls documentation.

 * Clone and compile PQUIC with both its uBPF and michelfralloc dependencies:

~~~
   git submodule update --init
   cd ubpf/vm
   make
   cd ../..
   cd picoquic/michelfralloc
   make
   cd ../..
   cmake .
   make
~~~

## Documentation

Generate doc with
```bash
doxygen
```
