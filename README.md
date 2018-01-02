## Simple 64-bit user-space memory allocator

`make malloc.so` to compile shared library.
`export LD_PRELOAD=$PWD/malloc.so` to make linker to preload it.