## Simple 64-bit user-space memory allocator

`make malloc.so` to compile shared library.
`export LD_PRELOAD=$PWD/malloc.so` to make linker to preload it.


# Architesture

* first-fit
* minimal block data size: 16B
* scalng by 8B
* everything aligned to at least 8B