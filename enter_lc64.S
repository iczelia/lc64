.text
.globl enter_lc64
.type enter_lc64,@function
// void enter_lc64(void *entry, long argc, char **argv, char **envp, void *stack_top) noreturn
// System V AMD64
enter_lc64:
  mov %rdi, %r11
  mov %rsi, %rdi       // rdi = argc
  mov %rdx, %rsi       // rsi = argv
  mov %rcx, %rdx       // rdx = envp
  mov %r8,  %rsp       // rsp = stack_top
  xor %rax, %rax
  xor %rbx, %rbx
  xor %rcx, %rcx
  xor %rbp, %rbp
  xor %r8,  %r8
  xor %r9,  %r9
  xor %r10, %r10
  xor %r12, %r12
  xor %r13, %r13
  xor %r14, %r14
  xor %r15, %r15
  jmp *%r11
