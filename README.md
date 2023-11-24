# xv6-mmap
Extends the functionality of the xv6 operating system to include a simplified version of the standard C mmap() and munmap() calls. The two system calls are simplified as they can only ever accept page-aligned addressing, and will fail
if given a non-page-aligned address. In addition, many of the flags that are included within the standard C version of mmap are missing (may be added at a later date).
## mmap
`void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`

The following are the available *prot* flags:
* **PROT_READ**:
&nbsp;Pages may be read.
* **PROT_WRITE**:
&nbsp;Pages may be written.

Notably, **PROT_NONE** is not an available flag, and is applied implicitly when the *prot* argument is blank.

The following are the available *flags* flags:
* **MAP_ANONYMOUS**:
&nbsp;The mapping is NOT file-backed.
* **MAP_SHARED**:
&nbsp;The mapping is shared, that is, a child process created by the fork() system call will point to the same memory mappings as the parent. Any changes done by the child or parent are reflected in the other.
* **MAP_PRIVATE**:
&nbsp;The mapping is not shared. Child processes created by the fork() system call will initially copy over the contents of the parent's mappings, but changes will not be propagated from child to parent or vice versa.
Mutually exclusive with **MAP_SHARED**; using both **MAP_SHARED** and **MAP_PRIVATE** will cause an error.
* **MAP_GROWSUP**:
&nbsp;Memory mappings in this implementation are placed in the heap. Operates similarly to the **MAP_GROWSDOWN** flag from standard C mmap, with two key differences: the mapping grows upwards, and the return address is not changed.
* **MAP_FIXED**:
&nbsp;Same as the **MAP_FIXED_NOREPLACE** flag in the standard C mmap implementation. Mappings (and unmappings) in this implementation will never be allowed to cut through an existing mapping!
## munmap
`int munmap(void *addr, size_t length);`

This implementation of the munmap() system call operates similarly to the standard C version, with one key difference: because existing mappings cannot be overlapped, the address passed into munmap() must be aligned
with the start of the mapping. If addr is not aligned with the start of a mapping, munmap() will fail.
