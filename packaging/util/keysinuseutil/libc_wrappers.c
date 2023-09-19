// Building on newer systems will link the keysinuseutil
// with glibc >= 2.32 due to the use of cgo. We need
// cgo to access the openssl config, but still need to support
// systems with glibc < 2.32. This file contains wrappers for
// those functions to ensure compatability with older systems.

#include <signal.h>
#include <pthread.h>

#if defined __aarch64__
    __asm__(".symver pthread_sigmask,pthread_sigmask@GLIBC_2.17");
    __asm__(".symver pthread_create,pthread_create@GLIBC_2.17");
    __asm__(".symver pthread_detach,pthread_detach@GLIBC_2.17");
    __asm__(".symver pthread_attr_getstacksize,pthread_attr_getstacksize@GLIBC_2.17");
    // __asm__(".symver __libc_start_main,__libc_start_main@GLIBC_2.17");
#elif defined __x86_64__
    __asm__(".symver pthread_sigmask,pthread_sigmask@GLIBC_2.2.5");
    __asm__(".symver pthread_create,pthread_create@GLIBC_2.2.5");
    __asm__(".symver pthread_detach,pthread_detach@GLIBC_2.2.5");
    __asm__(".symver pthread_attr_getstacksize,pthread_attr_getstacksize@GLIBC_2.2.5");
    // __asm__(".symver __libc_start_main,__libc_start_main@GLIBC_2.2.5");
#endif

int __wrap_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
    return pthread_sigmask(how, set, oldset);
}
int __wrap_pthread_create(pthread_t *restrict thread,
                         const pthread_attr_t *restrict attr,
                         void *(*start_routine)(void *),
                         void *restrict arg)
{
    return pthread_create(thread, attr, start_routine, arg);
}
int __wrap_pthread_detach(pthread_t thread)
{
    return pthread_detach(thread);
}
int __wrap_pthread_attr_getstacksize(const pthread_attr_t *restrict attr,
                                    size_t *restrict stacksize)
{
    return pthread_attr_getstacksize(attr, stacksize);
}
// void __wrap___libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
// {
//     return __libc_start_main(main, argc, up);
// }