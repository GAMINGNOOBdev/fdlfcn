# FDLFCN: A simple dlfcn like shared object loader

This is a work in progress project to replicate how a dynamic linker would work.<br/>
This library tries to be as independent as possible, currently only relying on `malloc`, `free`, `mmap`, `mprotect`, `munmap`, `memset`, `memcpy`, `memcmp`, `strcmp` and `printf`.<br/>
Those dependencies can however be changed using defines such as `FDLFCN_malloc`, `FDLFCN_free`, etc.<br/>
**Note:** Currently there is only support for x86_64 elf64 files! More support may come soon™️

# How to build

Just include the header and compile the .c file together with your project ;-)<br/>
**Note:** I have no clue if .so file loading also works on windows. If you have the time and will to check with the windows equivalent of mmap and such, feel free to make a PR ;-)

# Currently W.I.P features:

- Lazy binding using GOT/PLT
- Initialization/Finalization routines
- Proper dependency resolution
- More debug info (helpful for both library developers and me :3)
- Symbol versioning
- TLS (unlikely to come anytime soon but will be implemented)

