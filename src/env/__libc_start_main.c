#include "atomic.h"
#include "libc.h"
#include "stdio_impl.h"
#include "syscall.h"
#include <elf.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

static void dummy(void) {}
weak_alias(dummy, _init);

extern weak hidden void (*const __init_array_start)(void),
    (*const __init_array_end)(void);

static void dummy1(void *p) {}
weak_alias(dummy1, __init_ssp);

#define AUX_CNT 38

#ifdef __GNUC__
__attribute__((__noinline__))
#endif
void __init_libc(char **envp, char *pn)
{
  write(1, "__init_libc!\n", 13);
  size_t i, *auxv, aux[AUX_CNT] = {0};
  __environ = envp;
  for (i = 0; envp[i]; i++)
    ;
  write(1, "__init_libc 0\n", 14);
  libc.auxv = auxv = (void *)(envp + i + 1);
  write(1, "__init_libc 1\n", 14);
  for (i = 0; auxv[i]; i += 2)
    if (auxv[i] < AUX_CNT)
      aux[auxv[i]] = auxv[i + 1];
  write(1, "__init_libc 2\n", 14);
  __hwcap = aux[AT_HWCAP];
  write(1, "__init_libc 3\n", 14);
  if (aux[AT_SYSINFO])
    __sysinfo = aux[AT_SYSINFO];
  write(1, "__init_libc 4\n", 14);
  libc.page_size = aux[AT_PAGESZ];
  write(1, "__init_libc 5\n", 14);

  if (!pn)
    pn = (void *)aux[AT_EXECFN];
  if (!pn)
    pn = "";
  __progname = __progname_full = pn;
  for (i = 0; pn[i]; i++)
    if (pn[i] == '/')
      __progname = pn + i + 1;
  write(1, "__init_libc 6\n", 14);

  __init_tls(aux);
  write(1, "__init_libc 7\n", 14);
  __init_ssp((void *)aux[AT_RANDOM]);
  write(1, "__init_libc 8\n", 14);

  if (aux[AT_UID] == aux[AT_EUID] && aux[AT_GID] == aux[AT_EGID] &&
      !aux[AT_SECURE]) {
    write(1, "__init_libc 8\n", 14);
    return;
  }
  write(1, "__init_libc 9\n", 14);

  struct pollfd pfd[3] = {{.fd = 0}, {.fd = 1}, {.fd = 2}};
  int r =
#ifdef SYS_poll
      write(1, "__init_libc 10\n", 14);
  __syscall(SYS_poll, pfd, 3, 0);
#else
      __syscall(SYS_ppoll, pfd, 3, &(struct timespec){0}, 0, _NSIG / 8);
#endif
  write(1, "__init_libc 11\n", 14);
  if (r < 0)
    a_crash();
  write(1, "__init_libc 12\n", 14);
  for (i = 0; i < 3; i++)
    if (pfd[i].revents & POLLNVAL)
      if (__sys_open("/dev/null", O_RDWR) < 0)
        a_crash();
  write(1, "__init_libc 13\n", 14);
  libc.secure = 1;
  write(1, "__init_libc 14\n", 14);
}

static void libc_start_init(void) {
  write(1, "_init\n", 6);
  _init();
  uintptr_t a = (uintptr_t)&__init_array_start;
  for (; a < (uintptr_t)&__init_array_end; a += sizeof(void (*)())) {
    {
      unsigned long v = (unsigned long)(a);
      write(1, "a=0x", 4);
      while (v != 0) {
        char c = v % 16;
        if (c <= 9) {
          c = '0' + c;
        } else {
          c = 'a' + c - 10;
        }
        write(1, &c, 1);
        v /= 16;
      }
      char c = '\n';
      write(1, &c, 1);
    }
    (*(void (**)(void))a)();
  }
}

weak_alias(libc_start_init, __libc_start_init);

typedef int lsm2_fn(int (*)(int, char **, char **), int, char **);
static lsm2_fn libc_start_main_stage2;

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init_dummy)(), void (*fini_dummy)(),
                      void (*ldso_dummy)()) {
  char **envp = argv + argc + 1;

  /* External linkage, and explicit noinline attribute if available,
   * are used to prevent the stack frame used during init from
   * persisting for the entire process lifetime. */
  __init_libc(envp, argv[0]);

  /* Barrier against hoisting application code or anything using ssp
   * or thread pointer prior to its initialization above. */
  lsm2_fn *stage2 = libc_start_main_stage2;
  __asm__("" : "+r"(stage2) : : "memory");
  return stage2(main, argc, argv);
}

static int libc_start_main_stage2(int (*main)(int, char **, char **), int argc,
                                  char **argv) {
  char **envp = argv + argc + 1;
  __libc_start_init();

  /* Pass control to the application */
  exit(main(argc, argv, envp));
  return 0;
}

struct _IO_FILE2 {
  unsigned flags;
  unsigned char *rpos, *rend;
  int (*close)(FILE *);
  unsigned char *wend, *wpos;
  unsigned char *mustbezero_1;
  unsigned char *wbase;
  size_t (*read)(FILE *, unsigned char *, size_t);
  size_t (*write)(FILE *, const unsigned char *, size_t);
  off_t (*seek)(FILE *, off_t, int);
  unsigned char *buf;
  size_t buf_size;
  FILE *prev, *next;
  int fd;
  int pipe_pid;
  long lockcount;
  int mode;
  volatile int lock;
  int lbf;
  void *cookie;
  off_t off;
  char *getln_buf;
  void *mustbezero_2;
  unsigned char *shend;
  off_t shlim, shcnt;
  FILE *prev_locked, *next_locked;
  struct __locale_struct *locale;
};

void libc_fixup(void *offset) {
  struct _IO_FILE2 *stdo = (struct _IO_FILE2 *)stdout;
  void **stdow = (void **)&stdo->write;
  *stdow = (unsigned long)offset + (unsigned char *)stdo->write;

  void **stdos = (void **)&stdo->seek;
  *stdos = (unsigned long)offset + (unsigned char *)stdo->seek;

  void **stdoc = (void **)&stdo->close;
  *stdoc = (unsigned long)offset + (unsigned char *)stdo->close;

  libc.offset = (size_t)offset;

  __ofl_init();
}
