/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "threads/vaddr.h"


/*-------------------------[P3]frame table---------------------------------*/
static struct list frame_table;
/*-------------------------[P3]frame table---------------------------------*/

static unsigned hash_func (const struct hash_elem *e, void *aux UNUSED); // Implement hash_hash_func
static unsigned less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux); // Implement hash_less_func
static bool insert_page(struct hash *h, struct page *p);
static bool delete_page(struct hash *h, struct page *p);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
/* 아래의 초기화 코드를 호출하여 가상 메모리 하위 시스템을 초기화한다. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table); // frame_table에 대한 초기화
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* Initializer를 사용하여 보류 중인 페이지 개체를 만든다. 
 * 페이지를 생성하려면 직접 생성하지 말고 이 함수 또는 'vm_alloc_page'를 통해 생성한다. */

/*
1. 커널이 새 page를 요청하면 vm_alloc_page_with_initializer 호출
	initializer는 페이지 구조를 할당하고 페이지 type에 따라 적절한 initalizer를 할당하고 
	SPT 페이지에 추가 후 userprogram으로 반환함
2. 해당 페이지에 access 호출이 오면 내용이 없는 페이지 임으로 page fault가 발생
	uninit_initialize 를 호출하고 이전에 설정한 initializer를 호출한다.
	page를 frame가 연결하고 lazy_load_segment 를 호출하여 필요한 데이터를 물리 메모리에 올린다.
*/

bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) 
{

	ASSERT (VM_TYPE(type) != VM_UNINIT) // vm_type은 VM_ANON과 VM_FILE만 가능하다.

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
	// ↳ upage라는 가상 메모리에 매핑되는 페이지 존재 x -> 새로 만들어야함
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. 
		 * 페이지를 만들고 vm유형에 따라 이니셜을 가져온 다음 uninit_new를 호출하여 uninit 페이지 구조를 만듦
		 * uninit_new를 호출한 후 필드를 수정해야 함*/

		struct page* page = (struct page*)malloc(sizeof(struct page));
		
		// 페이지 타입에 따라 initializer가 될 초기화 함수를 매칭해준다.
        typedef bool (*initializer_by_type)(struct page *, enum vm_type, void *);
        initializer_by_type initializer = NULL;

		// switch-case 문 : VM_TYPE 이 enum이므로
        switch(VM_TYPE(type)) { // 페이지 타입에 따라 initiailizer를 설정한다.
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
		}

        uninit_new(page, upage, init, type, aux, initializer); // UNINIT 페이지 생성
        page->writable = writable; // page의 w/r 여부

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page); // 새로 만든 페이지를 spt에 삽입한다.
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */
	/*
	* va를 통해 page를 찾아야하는데, hash_find의 인자는 hash_elem이므로 이에 해당하는 hash_elem을 만들어준다.
	* 
	* 1. dummy page 생성(hash_elem 포함)
	* 2. va 매핑
	* 3. 해당 페이지와 같은 해시 값을 갖는 hash_elem을 찾는다.
	*/
	/*-------------------------[P3]hash table---------------------------------*/
	// 인자로 받은 va에 해당하는 vm_entry를 검색 후 반환
	// 가상 메모리 주소에 해당하는 페이지 번호 추출 (pg_round_down())
	// hash_find() 함수를 이용하여 vm_entry 검색 후 반환
	
	struct page *page = (struct page*)malloc(sizeof(struct page));	// 임의의 페이지 만들어주기
	// ↳ page를 새로 만들어주는 이유? : 해당 가상 주소에 대응하는 해시 값 도출을 위함
	//   page 생성 시, hash_elem도 생성된다.
	struct hash_elem *e;
	
	// 인자로 받은 spt내에서 va를 키로 전달해 이를 갖는 page 리턴
	// hash_find로 부터 해당 page를 찾을 수 있음 (p->value : key, struct page: value)
	// spt의 hash 테이블 구조체를 인자로 넣어야 하는데 va만 인자로 받아왔기 때문에,
	// dummy 페이지를 만들고 해당 페이지의 가상주소를 va로 만듦
	// va가 속해있는 페이지 시작 주소를 갖는 page를 만듦(pg_round_down)
	page->va = pg_round_down(va);
	/* e와 같은 해시값을 갖는 page를 spt에서 찾은 다음 해당 hash_elem을 리턴 */
	e = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page);

	if (e == NULL)
		return NULL;
	else
		return hash_entry(e, struct page, hash_elem); // e에 해당하는 page 리턴
	/*-------------------------[P3]hash table---------------------------------*/
}

// 삽입 성공시 true, 실패시 false
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	return insert_page(&spt -> spt_hash, page);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	/*-------------------------[P3]frame table---------------------------------*/
	// victim = list_entry(list_pop_front(&frame_table), struct frame, frame_elem);

	struct thread *curr = thread_current();
    struct list_elem *frame_e;

	// LRU 방식
	// frame table의 처음과 끝을 순회하면서 access bit가 0인 프레임을 찾는다.
	for (frame_e = list_begin(&frame_table); frame_e != list_end(&frame_table); frame_e = list_next(frame_e)) {
        victim = list_entry(frame_e, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va)) // access bit가 1이라면 true
            pml4_set_accessed (curr->pml4, victim->page->va, 0); // access bit를 초기화 해준다.
        else
            return victim;
    }
	/*-------------------------[P3]frame table---------------------------------*/

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	/*-------------------------[P3]frame table---------------------------------*/
	if(victim->page != NULL){
		swap_out(victim -> page);
		return victim;
	}
	/*-------------------------[P3]frame table---------------------------------*/

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc()을 하고 frame을 가져온다. 사용 가능한 페이지가 없는 경우, 페이지를 내쫓고 해당 페이지를 반환한다.
 * 항상 유효한 주소를 반환한다. 즉, 유저 풀 메모리가 가득 차면 해당 함수는 사용 가능한 메모리 공간을 얻기 
 * 위해 프레임을 제거한다.*/
static struct frame *
// 사용자 메모리가 가득차면 사용 가능한 메모리 공간을 얻기 위해 프레임 공간을 디스크로 내림(프레임 할당)
vm_get_frame (void) { //프레임 할당
	/* TODO: Fill this function. */
	/*-------------------------[P3]frame table---------------------------------*/
	// struct frame *frame = NULL;
	// void *kva = palloc_get_page(PAL_USER); // 사용가능한 단일 페이지(물리적 페이지)를 가져옴 - PAL_USER : 페이지를 사용자 풀에서 가져옴, 그 외에는 커널 풀에서 가져옴

	// if (kva == NULL) { // NULL이면 palloc으로 가져올수 있는 페이지가 없다는 것
	// 	frame = vm_evict_frame(); // 페이지 삭제 후 frame 리턴
	// }
	// else {
	// 	frame = malloc(sizeof(struct frame));
	// 	frame->kva = kva;
	// }

	struct frame *frame = (struct frame*)malloc(sizeof(struct frame)); 
	// frame 구조체를 위한 공간 할당한다.(작으므로 malloc으로 _Gitbook Memory Allocation 참조)

	frame->kva = palloc_get_page(PAL_USER); 
	// 유저 풀(실제 메모리)로부터 페이지 하나를 가져온다. 
	// ↳ 사용 가능한 페이지가 없을 경우, NULL 리턴
    if(frame->kva == NULL) { // 사용 가능한 페이지가 없는 경우
        frame = vm_evict_frame(); // swap out 수행 (frame을 내쫓고 해당 공간을 가져온다.)
        frame->page = NULL;

        return frame; // 무조건 유효한 주소만 리턴한다는 말이 통하는 이유 : swap out을 통해 공간 확보후, 리턴하기 떄문
    }
    list_push_back (&frame_table, &frame->frame_elem); // 새로 frame을 생성한 경우
    frame->page = NULL;
	/*-------------------------[P3]frame table---------------------------------*/
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	
	/* page_fault로 부터 넘어온 인자
	 * not_present : 페이지 존재 x (bogus fault)
	 * user : 유저에 의한 접근(true), 커널에 의한 접근(false)
	 * write : 쓰기 목적 접근(true), 읽기 목적 접근(false)
	*/
	// ! Stack Growth 에서 다시 보기
	// page fault 주소에 대한 유효성 검증
	// 커널 가상 주소 공간에 대한 폴트 처리 불가, 사용자 요청에 대한 폴트 처리 불가
	if (is_kernel_vaddr (addr) && user) // real fault
		return false;

    void *rsp_stack = is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp;
    if (not_present){
        if (!vm_claim_page(addr)) return false;
        else return true;
    }
	
	// return vm_do_claim_page (page);
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
    struct thread *curr = thread_current();
	/* TODO: Fill this function */
	struct page *page = spt_find_page(&curr -> spt, va); // va에 해당하는 페이지가 존재하는지 확인한다.
	if (page == NULL)
		return false;

	return vm_do_claim_page (page); // 해당 페이지에 프레임을 할당한다.
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame (); // 프레임 하나를 얻는다.

	/* Set links */
	frame->page = page; // 프레임의 페이지(가상)로 얻은 페이지를 연결해준다.
	page->frame = frame; // 페이지의 물리적 주소로 얻은 프레임을 연결해준다.

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
    struct thread *curr = thread_current();
	bool writable = page -> writable; // 해당 페이지의 R/W 여부
	pml4_set_page(curr->pml4, page->va, frame->kva, writable); // 현재 페이지 테이블에 가상 주소에 따른 frame 매핑

	return swap_in (page, frame->kva);
}


/* Initialize new supplemental page table */ 
// 보조페이지 테이블 사용 자료구조 선택 가능
// 보조페이지 테이블 spt에서 가상주소 va와 대응되는 페이지 구조체 찾아서 리턴
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/*-------------------------[P3]hash table---------------------------------*/
	hash_init(&spt->spt_hash, hash_func, less_func, NULL);
	/*-------------------------[P3]hash table---------------------------------*/
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}

/*-------------------------[P3]hash table---------------------------------*/
/* [KAIST 35p.] vm_hash_func 
 * spt에 넣을 인덱스를 해쉬 함수를 돌려서 도출한다.
 * hash.c - 'hash_hash_func' 의 구현 형태
 * hash_bytes 설명 : Returns a hash of the SIZE bytes in BUF(hash_elem).
 * hash 함수로 가상주소를 hashed index(해시값)으로 변환하기 위함
*/
static unsigned 
hash_func (const struct hash_elem *e, void *aux UNUSED) {
	const struct page *p = hash_entry(e, struct page, hash_elem); // hash 테이블이 hash_elem을 원소로 가지고 있으므로 페이지 자체에 대한 정보를 가져온다.
	return hash_bytes(&p->va, sizeof(p->va)); // 인덱스를 리턴해야하므로 hash_bytes를 리턴한다. 
}

/* [KAIST 35p.] vm_less_func 
 * 체이닝 방식의 spt를 구현하기 위한 함수
 * 해시 테이블 버킷 내의 두 페이지의 주소값 비교
 * hash.c - 'hash_less_func' 의 구현 형태
 * Returns true if page a precedes page b.
 * // 충돌 비교?
*/
static unsigned 
less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	const struct page *a_p = hash_entry(a, struct page, hash_elem);
	const struct page *b_p = hash_entry(b, struct page, hash_elem);
	return a_p->va < b_p->va; // b_p가 크면 true 반환 
}

/* [KAIST 34p.] insert_vme
 * spt 해시 테이블에 페이지를 삽입한다.
*/
static bool 
insert_page(struct hash *h, struct page *p) {
    if(!hash_insert(h, &p->hash_elem))
		return true;
	else
		return false;
}

/* [KAIST 34p.] delete_vme
 * spt 해시 테이블에서 페이지를 삭제한다.
*/
// ? 이거 왜 구현하는 거지...?
static bool 
delete_page(struct hash *h, struct page *p) {
	if(!hash_delete(h, &p->hash_elem))
		return true;
	else
		return false;
}
/*-------------------------[P3]hash table---------------------------------*/