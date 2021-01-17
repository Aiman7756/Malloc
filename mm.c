#include "memlib.h"
#include "mm.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

team_t team = {
    "Name",
    "UID",
    "Comment",
};

typedef struct {
    uint32_t allocated : 1;
    uint32_t block_size : 31;
    uint32_t _;
} header_t;

typedef header_t footer_t;

typedef struct block_t{
    uint32_t allocated : 1;
    uint32_t block_size : 31;
    uint32_t _;
    union {
        struct {
            struct block_t* next;
            struct block_t* prev;
        };
        int payload[0];
    } body;
} block_t;

enum block_state { FREE, ALLOC };

#define CHUNKSIZE (1 << 16)
#define OVERHEAD (sizeof(header_t) + sizeof(footer_t))
#define MIN_BLOCK_SIZE (32)
#define SEGLIST_NUMBER (12)

static block_t *prologue;
static block_t** segList;

static block_t *extend_heap(size_t words);
static void *place(block_t *block, size_t asize);
static block_t *find_fit(size_t asize);
static block_t *coalesce(block_t *block);
static footer_t *get_footer(block_t *block);
static void printblock(block_t *block);
static void checkblock(block_t *block);
void mm_checkheap(int verbose);

static void remove_free(block_t *block, int index);
static void insert_free(block_t *block, int index);
static int find_segbucket(size_t size);

static void print_explicit_free_list(int index);

int mm_init(void) {

    if ((segList = mem_sbrk(SEGLIST_NUMBER * 8)) == (void*)-1)
        return -1;
    
    for (int i = 0; i < SEGLIST_NUMBER; i++){
        segList[i] = NULL;
    }

    if ((prologue = mem_sbrk(CHUNKSIZE)) == (void*)-1)
        return -1;

    prologue->allocated = ALLOC;
    prologue->block_size = sizeof(header_t);

    block_t *init_block = (void *)prologue + sizeof(header_t);
    init_block->allocated = FREE;
    init_block->block_size = CHUNKSIZE - OVERHEAD;
    footer_t *init_footer = get_footer(init_block);
    init_footer->allocated = FREE;
    init_footer->block_size = init_block->block_size;

    insert_free(init_block, find_segbucket(init_block->block_size));

    block_t *epilogue = (void *)init_block + init_block->block_size;
    epilogue->allocated = ALLOC;
    epilogue->block_size = 0;
    return 0;
}

void *mm_malloc(size_t size) {
    uint32_t asize;
    uint32_t extendsize;
    uint32_t extendwords;
    block_t *block;

    if (size == 0)
        return NULL;

    size += OVERHEAD;

    asize = ((size + 7) >> 3) << 3;
    
    if (asize < MIN_BLOCK_SIZE) {
        asize = MIN_BLOCK_SIZE;
    }

    if ((block = find_fit(asize)) != NULL) {
        return place(block, asize);
    }

    extendsize = (asize > CHUNKSIZE)
                     ? asize
                     : CHUNKSIZE;
    extendwords = extendsize >> 3;
    if ((block = extend_heap(extendwords)) != NULL) {

        return place(block, asize);
    }
    return NULL;
}


void mm_free(void *payload) {
    block_t *block = payload - sizeof(header_t);
    block->allocated = FREE;
    footer_t *footer = get_footer(block);
    footer->allocated = FREE;
    coalesce(block);
}


void *mm_realloc(void *ptr, size_t size) {
    void *newp;
    size_t copySize;

    if ((newp = mm_malloc(size)) == NULL) {
        printf("ERROR: mm_malloc failed in mm_realloc\n");
        exit(1);
    }
    block_t* block = ptr - sizeof(header_t);
    copySize = block->block_size;
    if (size < copySize)
        copySize = size;
    memcpy(newp, ptr, copySize);
    mm_free(ptr);
    return newp;
}

void mm_checkheap(int verbose) {
    block_t *block = prologue;

    if (verbose)
        printf("Heap (%p):\n", prologue);

    if (block->block_size != sizeof(header_t) || !block->allocated)
        printf("Bad prologue header\n");
    checkblock(prologue);

    for (block = (void*)prologue+prologue->block_size; block->block_size > 0; block = (void *)block + block->block_size) {
        if (verbose)
            printblock(block);
        checkblock(block);
    }
    
    if (verbose)
        printblock(block);
    if (block->block_size != 0 || !block->allocated)
        printf("Bad epilogue header\n");
}

static block_t *extend_heap(size_t words) {
    block_t *block;
    uint32_t size;
    size = words << 3;
    if (size == 0 || (block = mem_sbrk(size)) == (void *)-1)
        return NULL;

    block = (void *)block - sizeof(header_t);
    block->allocated = FREE;
    block->block_size = size;

    footer_t *block_footer = get_footer(block);
    block_footer->allocated = FREE;
    block_footer->block_size = block->block_size;
 
    header_t *new_epilogue = (void *)block_footer + sizeof(header_t);
    new_epilogue->allocated = ALLOC;
    new_epilogue->block_size = 0;
 
    return coalesce(block);
}

static void *place(block_t *block, size_t asize) {
    size_t split_size = block->block_size - asize;

    if (split_size >= MIN_BLOCK_SIZE) {
        if(asize <= 104){
            remove_free(block, find_segbucket(block->block_size));

            block->block_size = split_size;
            block->allocated = FREE;
            footer_t *footer = get_footer(block);
            footer->block_size = split_size;
            footer->allocated = FREE;

            block_t *new_block = (void *)block + block->block_size;
            new_block->block_size = asize;
            new_block->allocated = ALLOC;
            footer_t *new_footer = get_footer(new_block);
            new_footer->block_size = asize;
            new_footer->allocated = ALLOC;
            insert_free(block, find_segbucket(split_size));
            return new_block->body.payload;
            }

        else {
            remove_free(block, find_segbucket(block->block_size));

            block->block_size = asize;
            block->allocated = ALLOC;
            footer_t *footer = get_footer(block);
            footer->block_size = asize;
            footer->allocated = ALLOC;


            block_t *new_block = (void *)block + block->block_size;
            new_block->block_size = split_size;
            new_block->allocated = FREE;
            footer_t *new_footer = get_footer(new_block);
            new_footer->block_size = split_size;
            new_footer->allocated = FREE;

            insert_free(new_block, find_segbucket(split_size));
            return block->body.payload;
            }

    } else {
        remove_free(block, find_segbucket(block->block_size));
        block->allocated = ALLOC;
        footer_t *footer = get_footer(block);
        footer->allocated = ALLOC;
        return block->body.payload;
    }
}

static block_t *find_fit(size_t asize) {
    int index = find_segbucket(asize);
    block_t *b;
    for(int i = index; i < SEGLIST_NUMBER; i++){
        for (b = segList[i]; b != NULL; b = b->body.next){
            if (b->block_size >= asize) {
                return b;
            }
        }
    }
    return NULL;
}

static block_t *coalesce(block_t *block) {

    footer_t *prev_footer = (void *)block - sizeof(header_t);
    header_t *next_header = (void *)block + block->block_size;
    bool prev_alloc = prev_footer->allocated;
    bool next_alloc = next_header->allocated;
    block_t *prev_block = (void *)prev_footer - prev_footer->block_size + sizeof(header_t);

    if (block->body.prev == block){
        prev_alloc = 1;
    }

    if (prev_alloc && next_alloc) {}

    else if (prev_alloc && !next_alloc) {
        remove_free((block_t*) next_header, find_segbucket(next_header->block_size));
        block->block_size += next_header->block_size;
        
        footer_t *next_footer = get_footer(block);
        next_footer->block_size = block->block_size;
    }

    else if (!prev_alloc && next_alloc) {
        remove_free(prev_block, find_segbucket(prev_block->block_size));
        prev_block->block_size += block->block_size;

        footer_t *footer = get_footer(prev_block);
        footer->block_size = prev_block->block_size;
        block = prev_block;
    }

    else {
        remove_free(prev_block, find_segbucket(prev_block->block_size));
        remove_free((block_t*) next_header, find_segbucket(next_header->block_size));
        prev_block->block_size += block->block_size + next_header->block_size;
        
        footer_t *next_footer = get_footer(prev_block);
        next_footer->block_size = prev_block->block_size;
        block = prev_block;
    }
    insert_free(block, find_segbucket(block->block_size));
    return block;
}

static footer_t* get_footer(block_t *block) {
    return (void*)block + block->block_size - sizeof(footer_t);
}

static void printblock(block_t *block) {
    uint32_t hsize, halloc, fsize, falloc;

    hsize = block->block_size;
    halloc = block->allocated;
    footer_t *footer = get_footer(block);
    fsize = footer->block_size;
    falloc = footer->allocated;

    if (hsize == 0) {
        printf("%p: EOL\n", block);
        return;
    }

    printf("%p: header: [%d:%c] footer: [%d:%c]\n", block, hsize,
           (halloc ? 'a' : 'f'), fsize, (falloc ? 'a' : 'f'));
}

static void checkblock(block_t *block) {
    if ((uint64_t)block->body.payload % 8) {
        printf("Error: payload for block at %p is not aligned\n", block);
    }
    footer_t *footer = get_footer(block);
    if (block->block_size != footer->block_size) {
        printf("Error: header does not match footer\n");
    }
}

static void remove_free(block_t* block, int index){
    if (segList[index] == NULL)
    {return;}

    else if (block->body.next == NULL && block->body.prev == NULL){
        segList[index] = NULL;
        return;
    }

    else if (block->body.next == NULL){
        block->body.prev->body.next = NULL;
        return;
    }

    else if (block->body.prev == NULL || segList[index] == block){
        segList[index] = block->body.next;
        segList[index]->body.prev = NULL;
    }
    else {
        block->body.prev->body.next = block->body.next;
        block->body.next->body.prev = block->body.prev;
    }

}

static void insert_free(block_t* block, int index){

    if (segList[index] == NULL){
        segList[index] = block;
        segList[index]->body.next = NULL;
        segList[index]->body.prev = NULL;

    }
    else {
        block->body.next = segList[index];
        block->body.prev = NULL;
        segList[index]->body.prev = block;
        segList[index] = block;
        
    }
}

static int find_segbucket(size_t size){
    switch(size){
        case 32 ... 128:      {return 1;}
        case 129 ... 255:     {return 2;}
        case 256 ... 511:     {return 3;}
        case 512 ... 1023:    {return 4;}
        case 1024 ... 2047:   {return 5;}
        case 2048 ... 4095:   {return 6;}
        case 4096 ... 8191:   {return 7;}
        case 8192 ... 16383:  {return 8;}
        case 16384 ... 32767: {return 9;}
        case 32768 ... 65535: {return 10;}
        default:              {return 11;}
    }
}

static void print_explicit_free_list(int index){

block_t* block = segList[index];
for (block = *(segList + index); block != NULL; block = block->body.next){
    checkblock(block);
}
}
