#include <stdlib.h>
#include "taintgrind.h"

void *__real_malloc (size_t);

void * __wrap_malloc (size_t size) {
    void *lptr = __real_malloc(size);
    TNT_MAKE_MEM_TAINTED(&lptr, sizeof(lptr));
    return lptr;
}

void *__real_realloc (void*, size_t);

void * __wrap_realloc (void* p, size_t size) {
    void *lptr = __real_realloc(p, size);
    TNT_MAKE_MEM_TAINTED(&lptr, sizeof(lptr));
    return lptr;
}

void *__real_calloc (size_t, size_t);

/* This function wraps the real malloc */
void * __wrap_calloc (size_t num, size_t size) {
    void *lptr = __real_calloc(num, size);
    TNT_MAKE_MEM_TAINTED(&lptr, sizeof(lptr));
    return lptr;
}

size_t __real_write(int, void*, int);

size_t __wrap_write(int channel, void* data, int size) {
    short* d = (short*) data;
    short c = 0;
    // for some reasons it does not work with chars
    for (int i=0; i<(size/2); ++i) {
        c |= d[i];
    }
    c |= (short) ((char*) data)[size-1];
    if (c) {
        __real_write(channel, data, size);
    } else {
        __real_write(channel, data, size);
    }
}
