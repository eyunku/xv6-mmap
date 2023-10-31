/* Define mmap flags */
#define MAP_PRIVATE 0x0001
#define MAP_SHARED 0x0002
#define MAP_ANONYMOUS 0x0004
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FIXED 0x0008
#define MAP_GROWSUP 0x0010
#define MAP_FAILED (void*)-1

/* Protections on memory mapping */
#define PROT_READ 0x1
#define PROT_WRITE 0x2

// Structure that represents mapped memory
struct mappedmem {
    uint addr;          // Starting address of map
    uint sz;            // Size of map
    int flags;          // 
    struct file* fp;    // File if mapping is not anonymous
    off_t offset;       // Offset into file
};
