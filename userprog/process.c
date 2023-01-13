#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

#include "lib/user/syscall.h" // need to Calling syscall_close.

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/*------------------------- [P2] Argument Passing --------------------------*/
static void argument_parse(char *file_name, int *argc_ptr, char *argv[]);
static void argument_stack(int argc, char **argv, struct intr_frame *if_);

/*------------------------- [P2] System Call - Thread --------------------------*/
struct thread *get_child_process(int pid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
/*------------------------- [P2] Argument Passing --------------------------*/
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy, *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	/* Create a new thread to execute FILE_NAME. */
	strtok_r (file_name, " ", &save_ptr); // 실행 파일 이름 파싱
	// ↳해당 라인을 추가하지 않으면 커맨드 라인 전체가 스레드 이름으로 지정된다.
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */

/* 현재 프로세스로 'name'이라는 이름을 가진 프로세스를 복사한다.
 * 성공 시, 새 프로세스의 tid 반환
 * 실패 시, TID_ERROR(-1) 반환 */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/

	struct thread *curr = thread_current();

	memcpy(&curr->parent_if, if_, sizeof(struct intr_frame)); // 전달받은 intr_frame을 parent_if필드에 복사한다.
	// ↳ '__do_fork' 에서 자식 프로세스에 부모의 컨텍스트 정보를 복사하기 위함(부모의 인터럽트 프레임을 찾는 용도로 사용)

	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr); // __do_fork를 실행하는 스레드 생성, 현재 스레드를 인자로 넘겨준다.
	if (tid == TID_ERROR)
		return TID_ERROR;

	struct thread *child = get_child_process(tid);
	sema_down(&child->fork_sema); // 자식 프로세스가 로드될 때까지 부모 프로세스는 대기한다.
	if (child->exit_status == TID_ERROR)
		return TID_ERROR;

	return tid; // 부모 프로세스의 리턴값 : 생성한 자식 프로세스의 tid
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* 부모의 페이지 테이블을 자식의 페이지 테이블로 복제한다. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
	{
		return true;
	} 
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	if (parent_page == NULL)
	{
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
	{
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage,parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 부모의 실행 컨텍스트를 복사하는 스레드 함수
 * parent->tf는 프로세스의 사용자 컨텍스트를 가지고 있지 않는다.
 * process_fork의 두 번째 인수를 이 함수에 전달해야 한다. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux; // 부모 프로세스
	struct thread *current = thread_current (); // 새로 생성된 자식 프로세스
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	/* TODO: process_fork의 두 번째 인자인 parent_if를 전달한다. */
	struct intr_frame *parent_if;
	bool succ = true;

	parent_if = &parent->parent_if; // process_fork에서 복사 해두었던 intr_frame
	/* 1. Read the cpu context to local stack. */
	/* 1. 부모의 인터럽트 프레임을 읽어온다.(if_로 복사) */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	if_.R.rax = 0; // fork 시스템 콜의 결과로 자식 프로세스는 0을 리턴해야하므로 0을 넣어준다.

	/* 2. Duplicate PT */
	/* 2. 페이지 테이블을 복제한다. */
	current->pml4 = pml4_create(); // 부모의 pte를 복사하기 위해 페이지 테이블을 생성한다.
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	// "pml4_for_each" : Apply FUNC to each available pte entries including kernel's.
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) // "duplicate_pte" : 페이지 테이블을 복제하는 함수(부모 -> 자식) 
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	/*
	 * 파일 객체를 복제하려면 'file_duplicate'를 사용하라.
	 * 이 함수가 부모의 리소스를 성공적으로 복제할 때까지 부모 프로세스는 fork로 부터 리턴할 수 없다.
	*/
	if (parent->next_fd == FDCOUNT_LIMIT)
		goto error;

	// 부모의 fdt를 자식의 fdt로 복사한다.
	for (int fd = 2; fd < FDCOUNT_LIMIT; fd++) {
		struct file *file = parent->fdt[fd];
		if (file == NULL) // fd엔트리가 없는 상태에는 그냥 건너뛴다.
			continue;
		current->fdt[fd] = file_duplicate (file);
	}

	current->next_fd = parent->next_fd; // 부모의 next_fd를 자식의 next_fd로 옮겨준다.
	sema_up(&current->fork_sema); // fork가 정상적으로 완료되었으므로 현재 wait중인 parent를 다시 실행 가능 상태로 만든다. 

	/* Finally, switch to the newly created process. */
	/* 새로 생성된 프로세스에 대해 컨텍스트 스위치를 수행한다. */
	if (succ)
		do_iret (&if_);
error: // 제대로 복제가 안된 상태 - TID_ERROR 리턴 
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	// thread_exit ();
}

/*------------------------- [P2] Argument Passing --------------------------*/
/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name; // 실행할 파일 이름(argv[0])
	// char *file_name_copy[48];
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	int argc = 0;
	char *argv[128]; // 64bit computer(uint64_t : 8byte)

	/* We first kill the current context */
	process_cleanup ();

	/*-------------------------[P3]hash table---------------------------------*/
	#ifdef VM
		supplemental_page_table_init(&thread_current() -> spt);
	#endif
	/*-------------------------[P3]hash table---------------------------------*/

	/* 커맨드 라인을 파싱한다. */
	argument_parse(file_name, &argc, argv);

	/* And then load the binary */
	success = load (file_name, &_if);


	/* If load failed, quit. */
	if (!success){
		palloc_free_page (file_name);
		return -1;
	}

	argument_stack(argc, argv, &_if); // argc, argv로 커맨드 라인 파싱
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true); // 메모리에 적재된 상태 출력

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
/* 스레드 TID가 종료될 때까지 기다렸다가 종료 상태를 반환한다.
 * 커널에 의해 종료된 경우(예외로 인해 종료된 경우) -1을 반환한다.
 * TID가 잘못되었거나 TID가 호출 프로세스의 하위 프로세스가 아니거나 
 * process_wait()이미 성공적으로 호출되었을 때, 대기하지 않고 -1을 즉시 반환한다. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	* XXX:       to add infinite loop here before
	* XXX:       implementing the process_wait. */
	// for(int i = 0 ; i<10000000; i++);
	
	// return -1;
	struct thread *child = get_child_process(child_tid);

	if(child == NULL) // 해당 자식이 존재하지 않는다면 -1 리턴
		return -1;

	sema_down(&child->wait_sema); // 자식 프로세스가 종료할 때까지 대기한다.
	// 컨텍스트 스위칭 발생

	int exit_status = child->exit_status; // 자식으로 부터 종료인자를 전달 받고 리스트에서 삭제한다.
	list_remove(&child->child_elem);
	
	// sema_up(&child->free_sema); // 자식 프로세스 종료 상태를 받은 후 자식 프로세스를 종료하게 한다.

	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	
	for (int i = 0; i < FDCOUNT_LIMIT; i++) // 프로세스 종료 시, 해당 프로세스의 fdt의 모든 값을 0으로 만들어준다.
		close(i);
	palloc_free_multiple(curr->fdt, FDT_PAGES); // fd table 메모리 해제

	file_close(curr->running); // 현재 프로세스가 실행중인 파일을 종료한다.	

	process_cleanup ();

	sema_up(&curr->wait_sema); // 부모 프로세스가 자식 프로세스의 종료상태를 확인하게 한다.
	thread_sleep(300);
	// sema_down(&curr->free_sema); // 부모 프로세스가 자식 프로세스의 종료 상태를 받을때 까지 대기한다. 
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	t->running = file;
	
	file_deny_write(file); // 현재 오픈한 파일에 접근 못하게 함

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	/* 커맨드 라인을 파싱한다. */
	// argument_stack(argc, argv, if_->rsp, &if_);
	// argument_stack(arg_list, token_count, &if_);

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
/*================================ Project 3 ======================================*/

static bool
lazy_load_segment (struct page *page, void *aux) {
	// aux는 load_segment에서 설정한 정보
	// 이 정보를 사용하여 세그먼트를 읽을 파일을 찾고 세그먼트를 메모리로 읽어야 함
	if (page == NULL) // 페이지 주소에 대한 유효성 검증
		return false;

	/* TODO: Load the segment from the file */
	/* TODO: 파일에서 세그먼트를 로드 */
	// 인자로 넘긴 aux에 대한 encapsulation을 진행한다.
	struct segment_aux* segment_aux = (struct segment_aux *) aux;
	/*-------------------------[P3]Anonoymous page---------------------------------*/
	struct file *file = ((struct segment_aux *)aux) -> file;
	off_t offset = ((struct segment_aux *)aux) -> offset;
	size_t page_read_bytes = ((struct segment_aux *)aux) -> page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: 주소 VA에서 첫번째 페이지 폴트가 발생할 때 호출 */
	file_seek(file, offset); // 파일의 오프셋을 설정한다.

	// file_read : 읽어온 바이트 수를 리턴
	// 만약 읽어온 바이트 수가 page_readbytes 와 다르다면 false
    if (file_read(file, page->frame->kva, page_read_bytes) != (int)page_read_bytes) { // 파일을 읽어온다.
		palloc_free_page(page->frame->kva);
        return false;
    }

	/* TODO: VA is available when calling this function. */
	/* TODO: VA는 이 기능을 호출할 때 사용할 수 있음 */
	// 페이지에 대한 초기화 작업 수행
    memset(page->frame->kva + page_read_bytes, 0, page_zero_bytes); // 나머지 0을 채우는 용도

    return true;
	/*-------------------------[P3]Anonoymous page---------------------------------*/

}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

/* 파일의 UPAGE(유저 가상 페이지)주소에서부터 OFS 오프셋에서 시작하는 세그먼트를 로드한다.
 * 가상 메모리의 READ_BYTES + ZERO_BYTES는 다음과 같이 초기화된다.
 * 
 * - UPPAGE의 READ_BYTES는 오프셋 OFS에서 시작하는 FILE에서 읽어야 한다.
 * - ZERO_BYTES(UPAGE + READ_BYTES)는 반드시 0이어야 한다.
 * 
 * 해당 함수로 초기화된 페이지는 반드시 유저 프로세스에 의해 쓰기가 가능해야 하며, 
 * 그렇지 않은 경우는 read-only여야한다.
 * 
 * 성공하면 true를 리턴하고 만약 메모리 할당 에러 또는 디스크 읽기 오류 발생시,
 * false를 리턴한다. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	// 읽어야할 파일, 파일의 ofs부터 읽기, vm에 올릴 시작 주소, 읽고 싶은 byte, 0으로 채우고자하는 바이트
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	// 한 페이지씩 읽으니까, read_bytes와 zero_bytes가 <= 0 될때까지 반복
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		// file에서 page_read_bytes를 읽고, 마지막 page_zero_bytes를 0으로 만듦
		// 페이지보다 작은 메모리를 읽어올 때 (페이지-메모리) 공간을 0으로 만듦
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		// 남아있는 읽어야할 read_bytes가 4kb보다 크면 PGSIZE, 
		//                           4kb보다 작으면 read_bytes
		//         ↳ why? 페이지 크기(4kb)에 맞추기 위함
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		//         ↳ 페이지(4kb)에서 남은 부분

	/*-------------------------[P3]Anonoymous page---------------------------------*/
		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		/* TODO: lazy_load_segment에 정보를 전달하도록 aux를 설정한다. */
		
		// void *aux = NULL;
	
		// 새 UNINIT 페이지를 만들어 현재 프로세스의 spt에 넣음
		// 페이지에 해당하는 파일의 정보들을 segment_aux 구조체에 담아서 aux로 넘겨줌
		struct segment_aux* segment_aux = (struct segment_aux *)malloc(sizeof(struct segment_aux));
		
		segment_aux->file = file; // 세그먼트를 읽어올 파일
		segment_aux->page_read_bytes = page_read_bytes; // 총 읽어올 바이트
		segment_aux->offset = ofs; // 시작 오프셋

		ofs += page_read_bytes;
	/*-------------------------[P3]Anonoymous page---------------------------------*/
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, segment_aux))
			return false;
		// 페이지 폴트 호출시 페이지 타입별로 초기화되고 lazy_load_segment 실행

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE); 
	// 스택은 아래로 커지니까 새로 추가하려는 페이지 사이즈 만큼 빼준 뒤, 해당 공간으로부터 페이지를 할당한다.
	// ↳ [Ref. Gitbook Project 2 - Introduction]

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	/*
	 * TODO: 스택을 stack_bottom에 매핑하고 즉시 페이지 할당,
	 * TODO: 페이지를 스택으로 표시해야함
	*/
	/*-------------------------[P3]Anonoymous page---------------------------------*/
	// vm_alloc_page(type, upage, writable)
	// writable : bool type
	// anon page로 만들 uninit page를 stack_bottom에서 위로 1page만큼 만든다. 이때 type에 VM_MARKER_0 flag를 추가함으로써 이 page가 stack임을 표시
	// 스택의 크기인 1mb범위 내에 있는지 확인
	// (VM_ANON | VM_MARKER_0) -> 페이지 타입으로 ANON이며, 스택 페이지임을 나타낼 수 있게 VM_MARKER_0 매크로를 함께 넣어준다.
	if(vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1)){ // = vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
		success = vm_claim_page(stack_bottom); // stack_bottom에 프레임 할당

		if (success) {
			if_->rsp = USER_STACK; // 스택을 위한 공간 할당했으니까 rsp 위치 지정
			thread_current()->stack_bottom = stack_bottom; // stack_bottom 지정
	
		}
	}
	/*-------------------------[P3]Anonoymous page---------------------------------*/

	return success;
}
#endif /* VM */

/*------------------------- [P2] Argument Passing --------------------------*/
static void argument_parse(char *file_name, int *argc_ptr, char *argv[]){
	char *token, *save_ptr;
	
	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
        argv[(*argc_ptr)++] = token;

	argv[*argc_ptr] = token;
}

static void argument_stack(int argc, char **argv, struct intr_frame *if_){
	char *argv_addr[128];
	for (int i = argc - 1; i >= 0; i--){ // argument
		if_->rsp -= strlen(argv[i]) + 1;
		// if_->rsp = argv[i];
		memcpy(if_->rsp, argv[i], strlen(argv[i]) + 1); // *(if_->rsp) = *argv[1]; 'if_->rsp'의 크기를 몰라서 이렇게 하면 안됨
		argv_addr[i] = if_->rsp;
	}

	while (if_->rsp % 8 > 0){ // word-aline padding
		if_->rsp -= 1;
		memset(if_->rsp, 0, 1);
	}
	
	if_->rsp -= sizeof(char *);	
	memset(if_->rsp, 0, sizeof(char *));

	for (int i = argc - 1; i >= 0; i--){
		if_->rsp -= sizeof(char *);
		// if_->rsp = argv_addr[i];
		memcpy(if_->rsp, &argv_addr[i], sizeof(char *));
	}
	
	if_->rsp -= sizeof(char *);
	memset(if_->rsp, 0, sizeof(char *));

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp + 8; 
}


/*------------------------- [P2] System Call - Thread --------------------------*/
// 자식 리스트를 검색하여 해당 프로세스 디스크립터 리턴
struct thread *get_child_process(int pid){
	struct thread *curr = thread_current();
	struct list *child_list = &curr->child_list;

	// 자식 리스트를 순회하면서 프로세스 디스크립터 검색
	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid) // 해당 pid가 존재하면 프로세스 디스크립터 리턴
			return t;
	}
	return NULL; // 리스트에 존재하지 않으면 NULL
}
