#include <linux/types.h>
#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/personality.h>

#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/elf.h>

#define LC64_MAGIC "LC64"
#define LC64_HDR_SIZE 6
#define LC64_LOAD_ADDR 0x0000000000040000UL

static int lc64_debug = 1;
module_param(lc64_debug, int, 0644);
MODULE_PARM_DESC(lc64_debug, "Enable debug logging");

static int lc64_trap_on_start = 0;
module_param(lc64_trap_on_start, int, 0644);
MODULE_PARM_DESC(lc64_trap_on_start, "Patch 0xCC at entry to break into debugger");

static struct linux_binfmt lc64_format;

static inline unsigned long page_align_up_ul(unsigned long x)
  { return PAGE_ALIGN(x); }

// Read entire file into kernel buffer (after header)
static int lc64_read_code(struct file * file, loff_t pos, size_t size, u8 ** out_buf) {
  u8 * buf;
  ssize_t r;

  if (size == 0) {
    *out_buf = NULL;
    return 0;
  }
  buf = vmalloc(size);
  if (!buf)
    return -ENOMEM;

  r = kernel_read(file, buf, size, &pos);
  if (r < 0) {
    vfree(buf);
    return r;
  }
  if ((size_t)r != size) {
    vfree(buf);
    return -EIO;
  }

  *out_buf = buf;
  return 0;
}

// Build argv/envp arrays by scanning NUL-terminated strings starting at bprm->p.
// Assume the first argc strings are argv, followed by envc env strings.
static int lc64_build_vectors_from_bprm(unsigned long start,
                unsigned long argv_base_user, int argc,
                unsigned long envp_base_user, int envc)
{
  unsigned long p = start;
  int i;
  char c;

  if (lc64_debug)
    pr_info("lc64: build_vectors_from_bprm argc=%d envc=%d start=%lx argv_base=%lx envp_base=%lx\n",
        argc, envc, start, argv_base_user, envp_base_user);

  // argv pointers
  for (i = 0; i < argc; i++) {
    if (put_user(p, (unsigned long __user *) (argv_base_user + i * sizeof(unsigned long)))) {
      if (lc64_debug) pr_err("lc64: put_user argv[%d] fault at %lx\n", i, argv_base_user + i * sizeof(unsigned long));
      return -EFAULT;
    }
    do {
      if (get_user(c, (char __user *) p)) {
        if (lc64_debug) pr_err("lc64: get_user argv char fault at %lx\n", p);
        return -EFAULT;
      }
      p++;
    } while (c != '\0');
  }
  if (put_user(0UL, (unsigned long __user *) (argv_base_user + i * sizeof(unsigned long)))) {
    if (lc64_debug) pr_err("lc64: put_user argv terminator fault at %lx\n", argv_base_user + i * sizeof(unsigned long));
    return -EFAULT;
  }

  // envp pointers
  for (i = 0; i < envc; i++) {
    if (put_user(p, (unsigned long __user *) (envp_base_user + i * sizeof(unsigned long)))) {
      if (lc64_debug) pr_err("lc64: put_user envp[%d] fault at %lx\n", i, envp_base_user + i * sizeof(unsigned long));
      return -EFAULT;
    }
    do {
      if (get_user(c, (char __user *) p)) {
        if (lc64_debug) pr_err("lc64: get_user env char fault at %lx\n", p);
        return -EFAULT;
      }
      p++;
    } while (c != '\0');
  }
  if (put_user(0UL, (unsigned long __user *) (envp_base_user + i * sizeof(unsigned long)))) {
    if (lc64_debug) pr_err("lc64: put_user env terminator fault at %lx\n", envp_base_user + i * sizeof(unsigned long));
    return -EFAULT;
  }

  return 0;
}

static int lc64_load_binary(struct linux_binprm * bprm) {
  struct file * file = bprm->file;
  loff_t sz;
  u8 * code = NULL;
  int ret;
  unsigned long load = LC64_LOAD_ADDR;
  unsigned long code_sz, code_rounded, commit_pages, commit_bytes, total_map;
  unsigned long ps = PAGE_SIZE;

  // Check header in bprm->buf
  if (memcmp(bprm->buf, LC64_MAGIC, 4) != 0)
    return -ENOEXEC;
  commit_pages = (unsigned long)bprm->buf[4] | ((unsigned long)bprm->buf[5] << 8);

  sz = i_size_read(file_inode(file));
  if (sz < LC64_HDR_SIZE)
    return -ENOEXEC;
  code_sz = (unsigned long)(sz - LC64_HDR_SIZE);

  ret = lc64_read_code(file, LC64_HDR_SIZE, code_sz, &code);
  if (ret)
    return ret;

  code_rounded = page_align_up_ul(code_sz);
  commit_bytes = commit_pages * ps;
  if (code_rounded < code_sz)
    goto out_overflow;
  if (commit_pages != 0 && commit_bytes / ps != commit_pages)
    goto out_overflow;
  if (code_rounded > ULONG_MAX - commit_bytes)
    goto out_overflow;
  total_map = code_rounded + commit_bytes;

#if defined(BEGIN_NEW_EXEC_RETURNS_INT) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
  ret = begin_new_exec(bprm);
  if (ret)
    goto out_free;
#else
  setup_new_exec(bprm);
#endif

  // Set personality defaults
  set_personality(PER_LINUX);

  // Map anonymous RWX region at fixed address
  {
    unsigned long addr;
    addr = vm_mmap(NULL, load, total_map,
             PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0);
    if (IS_ERR_VALUE(addr)) {
      ret = (long)addr;
      goto out_free;
    }
    if (addr != load) {
      ret = -ENOMEM;
      goto out_free;
    }
    if (lc64_debug) pr_info("lc64: mapped %lx - %lx (size %lu)\n", load, load + total_map, total_map);
  }

  // Copy code into user mapping
  if (code_sz) {
    if (copy_to_user((void __user *) load, code, code_sz)) {
      ret = -EFAULT;
      goto out_free;
    }
    if (lc64_debug) pr_info("lc64: copied code %lu bytes to %lx\n", code_sz, load);
    // Zero padding already zero due to anon mapping
  }

  // Setup the user stack from bprm pages, via default exestack setup
  {
    ret = setup_arg_pages(bprm, STACK_TOP_MAX, EXSTACK_DEFAULT);
    if (ret)
      goto out_free;
  }

  // Choose a stack pointer. Use bprm->p (where tables would normally be placed), align to 16
  {
    unsigned long sp = (bprm->p) & ~0xFUL;
    struct pt_regs * regs = task_pt_regs(current);
    unsigned long argv_base_user, envp_base_user;
    int argc = bprm->argc;
    int envc = bprm->envc;
    if (lc64_debug) pr_info("lc64: argc=%d envc=%d bprm->p=%lx\n", argc, envc, (unsigned long)bprm->p);

    // Reserve space at the end of code mapping for argv/envp vectors
    // Layout: [argv pointers...(argc+1)] [envp pointers...(envc+1)]
    argv_base_user = load + code_rounded; // first byte after rounded code
    envp_base_user = argv_base_user + (unsigned long)(argc + 1) * sizeof(unsigned long);
    // Ensure vectors fit in mapped region
    if (envp_base_user + (unsigned long)(envc + 1) * sizeof(unsigned long) > load + total_map) {
      // If not enough space in commit pages, fall back to placing vectors on the stack just below sp
      unsigned long total_ptrs = (unsigned long)(argc + 1 + envc + 1);
      sp -= total_ptrs * sizeof(unsigned long);
      envp_base_user = sp + (unsigned long)(argc + 1) * sizeof(unsigned long);
      argv_base_user = sp;
      if (lc64_debug) pr_info("lc64: placing argv/envp on stack: argv_base=%lx envp_base=%lx sp=%lx\n", argv_base_user, envp_base_user, sp);
    } else {
      if (lc64_debug) pr_info("lc64: placing argv/envp in commit pages: argv_base=%lx envp_base=%lx\n", argv_base_user, envp_base_user);
    }

    ret = lc64_build_vectors_from_bprm((unsigned long)bprm->p, argv_base_user, argc, envp_base_user, envc);
    if (ret)
      goto out_free;

    // Enter: zero registers except rdi/rsi/rdx/rsp, set RIP to load
    // start_thread sets CS/SS and ip/sp
    start_thread(regs, load, sp);

    // Zero GPRs
    regs->ax = 0; regs->bx = 0; regs->cx = 0; regs->bp = 0;
    regs->r8 = 0; regs->r9 = 0; regs->r10 = 0; regs->r11 = 0;
    regs->r12 = 0; regs->r13 = 0; regs->r14 = 0; regs->r15 = 0;
    // Set argument registers
    regs->di = argc;
    regs->si = argv_base_user;
    regs->dx = envp_base_user;
    // rsp already set by start_thread

    if (lc64_trap_on_start) {
      // Patch int3 at entry to stop under debugger
      u8 cc = 0xCC;
      if (copy_to_user((void __user *)load, &cc, 1)) {
        if (lc64_debug) pr_err("lc64: failed to plant int3 at %lx\n", load);
      } else {
        if (lc64_debug) pr_info("lc64: planted int3 at entry %lx\n", load);
      }
    }

    // Return 0 to indicate successful exec setup
    ret = 0;
  }
out_free:
  if (code)
    vfree(code);
  return ret;
out_overflow:
  ret = -EOVERFLOW;
  goto out_free;
}

static int lc64_load_shlib(struct file * file) {
  return -ENOEXEC;
}

static struct linux_binfmt lc64_format = {
  .module = THIS_MODULE,
  .load_binary = lc64_load_binary,
};

static int __init lc64_init(void) {
  register_binfmt(&lc64_format);
  pr_info("lc64: registered binfmt (LC64 @ 0x%lx)\n", LC64_LOAD_ADDR);
  return 0;
}

static void __exit lc64_exit(void) {
  unregister_binfmt(&lc64_format);
  pr_info("lc64: unregistered binfmt\n");
}

module_init(lc64_init);
module_exit(lc64_exit);
MODULE_DESCRIPTION("LC64 flat binary binfmt loader (x86_64)");
MODULE_AUTHOR("binfmt-raw");
MODULE_LICENSE("GPL");
