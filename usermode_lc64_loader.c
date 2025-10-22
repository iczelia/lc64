#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char ** environ;

// Jumps to entry with registers zeroed (except rdi,rsi,rdx,rsp)
void enter_lc64(void *entry, long argc, char **argv, char **envp, void *stack_top);

static void die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  if (fmt[0] && fmt[strlen(fmt)-1] != '\n') fprintf(stderr, "\n");
  _exit(127);
}

static off_t get_file_size(int fd) {
  struct stat st;
  if (fstat(fd, &st) < 0) return -1;
  return st.st_size;
}

static bool read_exact(int fd, void *buf, size_t n) {
  uint8_t *p = (uint8_t*)buf;
  size_t total = 0;
  while (total < n) {
    ssize_t r = read(fd, p + total, n - total);
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (r == 0) return false; // EOF
    total += (size_t)r;
  }
  return true;
}

static size_t page_align_up(size_t x) {
  size_t ps = (size_t)sysconf(_SC_PAGESIZE);
  return (x + ps - 1) & ~(ps - 1);
}

static void *x_mmap_fixed_rwxo(void *addr, size_t len) {
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
#ifdef MAP_FIXED_NOREPLACE
  void *p = mmap(addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED && errno == EEXIST) {
    p = MAP_FAILED;
  }
  if (p != MAP_FAILED) return p;
#endif
  void *p2 = mmap(addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  return p2;
}

int main(int argc, char * argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <file.lc64> [args for program...]\n", argv[0]);
    return 2;
  }

  const char * path = argv[1];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) die("failed to open %s: %s", path, strerror(errno));

  uint8_t header[6];
  if (!read_exact(fd, header, sizeof(header))) die("short read on header");
  if (memcmp(header, "LC64", 4) != 0) die("bad magic (expected 'LC64')");
  uint16_t commit_pages = (uint16_t)(header[4] | ((uint16_t)header[5] << 8));

  off_t fsz = get_file_size(fd);
  if (fsz < 0) die("stat failed: %s", strerror(errno));
  if (fsz < (off_t)sizeof(header)) die("file too small");

  size_t code_size = (size_t)(fsz - (off_t)sizeof(header));
  size_t ps = (size_t)sysconf(_SC_PAGESIZE);

  // Calculate mapping sizes, check overflows
  size_t code_rounded = page_align_up(code_size);
  size_t commit_bytes = (size_t)commit_pages * ps;
  if (code_rounded < code_size) die("overflow");
  if (commit_pages != 0 && commit_bytes / ps != commit_pages) die("overflow");
  if (SIZE_MAX - code_rounded < commit_bytes) die("size overflow");
  size_t total_map = code_rounded + commit_bytes;

  // Load address
  uintptr_t base = 0x40000ull;

  // Map code region RWX and copy bytes in
  void * region = x_mmap_fixed_rwxo((void *) base, total_map);
  if (region == MAP_FAILED) die("mmap at 0x%lx failed: %s", (unsigned long)base, strerror(errno));

  // Read code into mapping starting at base
  uint8_t * dst = (uint8_t *) region;

  // We already read 6 bytes, so now copy the rest
  size_t to_read = code_size;
  size_t copied = 0;
  while (copied < to_read) {
    ssize_t r = read(fd, dst + copied, to_read - copied);
    if (r < 0) {
      if (errno == EINTR) continue;
      die("read error: %s", strerror(errno));
    }
    if (r == 0) die("unexpected EOF while reading code");
    copied += (size_t)r;
  }

  close(fd);

  // Zero any padding up to rounded size is already zero from mmap
  // commit pages are part of the same mapping (already zero-filled)
  if (code_rounded > code_size) {
    memset(dst + code_size, 0, code_rounded - code_size);
  }

  // Prepare guest argc/argv/envp
  long guest_argc = (long)(argc - 1);
  char ** guest_argv = &argv[1];
  char ** guest_envp = environ;

  // Create a fresh stack for the guest
  size_t stack_size = 8 * 1024 * 1024; // 8 MiB
  void * stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) die("mmap stack failed: %s", strerror(errno));

  // Top of stack, 16-byte aligned
  uintptr_t sp = (uintptr_t) stack + stack_size;
  sp &= ~((uintptr_t) 0xF);

  void * entry = (void *) base; // entry at start of mapping

  // Jump to guest (noreturn)
  enter_lc64(entry, guest_argc, guest_argv, guest_envp, (void *) sp);

  // Should never return
  _exit(111);
}
