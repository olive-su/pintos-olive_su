#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

void close (int fd);

struct lock filesys_lock; // 파일 점유시 필요한 락

#endif /* userprog/syscall.h */
