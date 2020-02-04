# michelfralloc library

This small library is a wrapper around ptmalloc3 (the memory allocation library used in the version of glibc provided on Linux systems.
It allows to perform malloc, realloc and free operations inside a predefined memory area already allocated by the system's malloc
in order to provide a dynamic memory allocation system with variable block sizes.

To build the library, first get **ptmalloc3**: http://www.malloc.de/malloc/ptmalloc3-current.tar.gz and put the `ptmalloc3` directory of the archive
at the root of this directory.

Then run the following command with the directory containing this README file as your current working directory:

     patch -p0 < ptmalloc.patch

Then you can build michelfralloc by running `make` in this directory

