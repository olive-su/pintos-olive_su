#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif
#define USERPROG // syscall.c 파일에서 에러 뜨는 부분 방지

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/*------------------------- [P2] System Call --------------------------*/
#define FDT_PAGES 3 // fdt 할당시 필요한 페이지 개수
#define FDCOUNT_LIMIT FDT_PAGES *(1<<9) // 3(테이블 개수) * 512(한 테이블 당 전체 엔트리 개수)
// ↳ [comment] FDT_PAGES < 3 으로 하면 "multi-oom"테스트에서 터진다.
/*
	- 한 페이지 당 엔트리 개수가 512인 이유?
		- 기본으로 설정된 페이지 하나의 사이즈 : PGSIZE(1 << 12) _ Ref. "threads/vaddr.h"
		- PGSIZE / sizeof(struct file**)[= 8byte] = 512(개의 엔트리)
*/

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	/*------------------------- [P1] Alarm Clock & Priority Scheduling --------------------------*/
	int priority_base; // donation 이후 우선순위 초기화를 위한 초기 우선 순위 값
	struct lock *wait_on_lock; // 해당 스레드가 대기하고 있는 lock의 주소
	int64_t wakeup_tick; // 해당 스레드를 깨워야하는 시간(local ticks)

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	struct list donations; // 해당 스레드에 priority donation 해준 스레드 리스트
	struct list_elem d_elem; // donations 를 위한 elem


/*------------------------- [P2] System Call --------------------------*/
#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
	struct file **fdt; // 파일 디스크립터 테이블(프로세스당 개별적으로 존재)
	int next_fd; // 다음 fd 인덱스

	// Ref_92p. Hanyang Univ
	struct intr_frame parent_if; // 부모 프로세스의 인터럽트 프레임
	struct list child_list; // 자식 프로세스 리스트
	struct list_elem child_elem; // 자식 프로세스 리스트의 element
	
	struct file *running; // 현재 실행 중인 파일
	int exit_status; // 프로세스의 종료 유무 확인

	struct semaphore fork_sema; // fork가 완료될 때 sema_up 수행
    struct semaphore free_sema; // 자식 프로세스가 종료될 때까지 부모 프로세스는 대기
	struct semaphore wait_sema; // 자식 프로세스가 종료될 때까지 대기. 종료 상태 저장
	

#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/*------------------------- [P1] Alarm Clock & Priority Scheduling --------------------------*/
int64_t get_global_ticks(void);
void set_global_ticks(int64_t ticks);
void thread_awake(int64_t ticks);
void thread_sleep(int64_t ticks);
bool cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

#endif /* threads/thread.h */
