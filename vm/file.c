/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h" // lazy_load_segment
#include "threads/mmu.h" // function "pml4*"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	if (page == NULL)
        return false;

    struct segment_aux *segment_aux = (struct segment_aux *)page->uninit.aux;

    struct file *file = segment_aux->file;
	off_t offset = segment_aux->offset;
    size_t page_read_bytes = segment_aux->page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

	file_seek (file, offset);

    if (file_read (file, kva, page_read_bytes) != (int) page_read_bytes) {
        // palloc_free_page (kva);
        return false;
    }

    memset (kva + page_read_bytes, 0, page_zero_bytes);

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
    if (page == NULL)
        return false;

    struct segment_aux * segment_aux = (struct segment_aux *) page->uninit.aux;

    // CHECK dirty page
    if(pml4_is_dirty(thread_current()->pml4, page->va)){
        file_write_at(segment_aux->file, page->va, segment_aux->page_read_bytes, segment_aux->offset);
        pml4_set_dirty (thread_current()->pml4, page->va, 0);
    }

    pml4_clear_page(thread_current()->pml4, page->va);

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file *re_file = file_reopen(file);

    void * mmap_addr = addr; // 페이지 확장 시, 리턴 주소 값 변경 방지
    size_t read_bytes = length > file_length(file) ? file_length(file) : length; // 실제 읽어올 바이트 수
    size_t zero_bytes = PGSIZE - (read_bytes % PGSIZE); // 페이지에서 read_bytes를 제외한 공간은 0으로 채운다.

	// 읽으려는 바이트 수만큼 페이지를 할당한다.
	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = page_read_bytes == PGSIZE ? 0 : PGSIZE - page_read_bytes;

        struct segment_aux *segment_aux = (struct segment_aux*)malloc(sizeof(struct segment_aux));
        segment_aux->file = re_file;
        segment_aux->offset = offset;
        segment_aux->page_read_bytes = page_read_bytes;

		// vm_alloc_page가 안되는 이유? -> aux(segment_aux) 값으로 파일에 대한 정보를 넘겨줘야한다.
		if (!vm_alloc_page_with_initializer (VM_FILE, mmap_addr, writable, lazy_load_segment, segment_aux)) {
			free(mmap_addr); // 안전장치
			return NULL;
        }
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;

		// 페이지 하나 할당에 따른 주소값, 오프셋 변경
		mmap_addr += PGSIZE;
		offset += page_read_bytes;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	while (true) {
        struct page* page = spt_find_page(&thread_current()->spt, addr);

        if (page == NULL)
            break;

        struct segment_aux * segment_aux = (struct segment_aux *) page->uninit.aux;

        // dirty bit(사용된 적이 있으면) -> 파일에 다시 쓰고 dirty bit를 0으로 만들어줌
        if(pml4_is_dirty(thread_current()->pml4, page->va)) {
            file_write_at(segment_aux->file, addr, segment_aux->page_read_bytes, segment_aux->offset); // ? i-node에 내가 쓰던 파일이 해제됨을 알린다고 보면 될 듯?
            pml4_set_dirty (thread_current()->pml4, page->va, 0);
        }

        pml4_clear_page(thread_current()->pml4, page->va);
        addr += PGSIZE;
    }
}
