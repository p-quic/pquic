# PQUIC

The PQUIC implementation, a framework that enables QUIC clients and servers to dynamically exchange protocol plugins that extend the protocol on a per-connection basis.

## Documentation

Generate doc with 
```bash
doxygen
```

# Building PQUIC

TL;DR: https://pquic.org

PQUIC is developed in C, and is based on picoquic (https://github.com/private-octopus/picoquic).
It can be built under Linux (the support of Windows is not provided yet).
Building the project requires first managing the dependencies, Picotls (https://github.com/h2o/picotls), uBPF, libarchive
and OpenSSL.
Please note that you will need the matching version of Picotls (as described by the "Getting Started" on https://pquic.org).

## PQUIC on Linux

To build PQUIC on Linux, you need to:

 * Install and build Openssl on your machine

 * Install libarchive. It is usually found in distribution packages (e.g., `apt install libarchive-dev`) or on (the LibArchive page)[http://libarchive.org/]

 * Clone and compile Picotls, using cmake as explained in the Picotls documentation.

 * Clone and compile Picoquic with its uBPF dependency:
~~~
   git submodule update --init
   cd ubpf/vm
   make
   cd ../..
   cmake .
   make
~~~
