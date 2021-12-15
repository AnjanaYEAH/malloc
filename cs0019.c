#define CS0019_DISABLE 1
#include "cs0019.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node{
  long key;
  long val;
  const char* file;
  int line;
  char* deleted;
  struct node* next;
  struct node* previous;
};

struct table{
  long size;
  struct node** list;
};

struct table* t = NULL;
struct node* notFound = NULL;

void createTable(){
    t = (struct table*)malloc(sizeof(struct table));
    t -> list = (struct node**)malloc(sizeof(struct node*)*10);
    t -> size = 10;
    notFound = (struct node*)malloc(sizeof(struct node));
    notFound -> val = -1;
    for(int i = 0; i < 10; i++){
        t -> list[i] = NULL;
    }
}


long hashCode(long key){
    if(key<0){return -(key%(t -> size));}
    return key%(t -> size);
}

void insert(long key, long val, const char* file, int line){
    long pos = hashCode(key);
    char* a = (char*)malloc(1);
    *(a) = 'a';
    struct node *list = t -> list[pos];
    struct node *newNode = (struct node*)malloc(sizeof(struct node));
    struct node *temp = list;
    struct node *lastNode;
    while(temp){
        if(temp -> key==key){
            temp -> val = val;
            temp -> file = file;
            temp -> line = line;
            return;
        }
        lastNode = temp;
        temp = temp -> next;
    }
    if(list == NULL){
      newNode -> key = key;
      newNode -> val = val;
      newNode -> file = file;
      newNode -> line = line;
      newNode -> next = list;
      newNode -> deleted = a;
      newNode -> previous = NULL;
      t -> list[pos] = newNode;
    }else{
      lastNode -> next = newNode;
      newNode -> key = key;
      newNode -> val = val;
      newNode -> file = file;
      newNode -> line = line;
      newNode -> next = NULL;
      newNode -> deleted = a;
      newNode -> previous = lastNode;
    }
}

char* change(char* a){
  *(a) = 'c';
return a;
}

int equalTo(char* a){
if(*(a) == 'a'){return 1;}
return 0;
}


struct node* lookup(long key){
    long pos = hashCode(key);
    struct node* list = t->list[pos];
    struct node* temp = list;
    while(temp && equalTo(temp->deleted)){
        if(temp->key==key){return temp;}
        temp = temp->next;
    }
    return notFound;
}


long delete(long key){
    long pos = hashCode(key);
    struct node* list = t->list[pos];
    struct node* temp3;
    struct node* temp2 = list;
    struct node* temp1;
    long val;
    if(temp2==NULL){
        return -1;
    }
    //code to delete the first item on list
    if(temp2->key==key){
        if(temp2->next == NULL && temp2->previous == NULL && equalTo(temp2->deleted)){
            t->list[pos] = NULL;
            val = temp2->val;
            temp2->deleted = change(temp2->deleted);
            free(temp2);
            return val;
        }else if(equalTo(temp2->deleted)){
            temp3 = temp2->next;
            temp1 = temp2->previous;
            t->list[pos] = temp3;
            temp3->previous = NULL;
            val = temp2->val;
            temp2->deleted = change(temp2->deleted);
            free(temp2);
            return val;
        }
    }
    temp2 = temp2->next;
    //code to delete other items on list
    while(temp2){
        if(equalTo(temp2->deleted)){
            if(temp2->key==key){
                temp3 = temp2->next;
                temp1 = temp2->previous;
                if(temp3==NULL){
                    temp1->next = NULL;
                    val = temp2->val;
                    temp2->deleted = change(temp2->deleted);
                    free(temp2);
                    return val;
                }else{
                    temp1->next = temp3;
                    temp3->previous = temp1;
                    val = temp2->val;
                    temp2->deleted = change(temp2->deleted);
                    free(temp2);
                    return val;
                }
            }
            temp2 = temp2->next;
        }else{
            return -1;
        }
    }
    return -1;
}




struct cs0019_statistics stats = {
.nactive = 0,
.active_size = 0,
.ntotal = 0,
.total_size = 0,  // # bytes in total allocations
.nfail = 0,       // # failed allocation attempts
.fail_size = 0,   // # bytes in failed alloc attempts
.heap_min = 0,                 // smallest allocated addr
.heap_max = 0  

};
struct cs0019_statistics *s = &stats;
/// cs0019_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then cs0019_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

struct table* t0 = NULL;

void fillWithX(void* addr, size_t sz, long x){
    for(int i = 0; i<400; i++){
        *((char*)addr + sz + i) = x;
    }
}

int checkIfFilledX(void* addr, size_t sz, long x){
    for(int i = 0; i<400; i++){
        if(*((char*)addr + sz + i) != x){
            return 0;
        }
    }
    return 1;
}

void *cs0019_malloc(size_t sz, const char *file, int line) {
  (void)file, (void)line; // avoid uninitialized variable warnings
  if (sz >= (size_t)-1 - 150){
    s -> nfail++;
    s -> fail_size = sz;
    return NULL;
  }else{
    s -> ntotal++;
    s -> nactive++;
    s -> total_size+=sz;
    s -> active_size+=sz;

    void* addr = base_malloc(sz + 400);
    if(t == NULL){
      createTable();
      s -> heap_min = addr;
    }

    if((long)addr < (long)(s -> heap_min)){
      s -> heap_min = addr;
    }
    if((long)addr + (long)sz + 400 > (long)(s -> heap_max)){
      s -> heap_max = addr + sz + 400;
    }
    fillWithX(addr, sz, 0x42);
    //*((char*)addr + (long)sz) = 0x42; //check for this
    
    insert((long)addr, (long)sz, file, line);
    return addr;
  }

}

/// cs0019_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to cs0019_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.
struct node* getErrorInfo(void* ptr){
  struct node* list;
  struct node* temp;
  for(int i = 0; i<10; i++){
    list = t->list[i];
    temp = list;
    while(temp){
      if(temp->key < (long)ptr && temp->key + temp->val > (long)ptr){
        return temp;
      }
      temp = temp->next;
    }
  }
  return notFound;
}
void cs0019_free(void *ptr, const char *file, int line) {
  (void)file, (void)line;
  if(!ptr){
    return;
  }
  if(t == NULL|| (long)ptr < (long)(s->heap_min) || (long)ptr >(long)(s->heap_max)){
    printf("MEMORY BUG: %s:%d: invalid free of pointer 0x%lx, not in heap", file, line, (long)ptr);
    exit(0);
  }

  if(lookup((long)ptr) -> val == (long)-1){
    printf("MEMORY BUG: %s:%d: invalid free of pointer 0x%lx, not allocated\n", file, line, (long)ptr);
    struct node* err = getErrorInfo(ptr);
    if(err->val == (long)-1){
      exit(0);
    }
    printf("  %s:%d: 0x%lx is %ld bytes inside a %ld byte region allocated here",err->file, err->line, (long)ptr, (long)ptr - err->key, err->val);
    exit(0);
  }
  
  long sz = delete((long)ptr);
//*((char*)ptr + sz) != 0x42
  if(!checkIfFilledX(ptr, (size_t)sz, 0x42)){
    printf("MEMORY BUG: %s:%d: detected wild write during free of pointer %p", file, line, ptr);
    exit(0);
  }
  fillWithX(ptr, sz, 0x43);
  s -> nactive--;
  s -> active_size-=sz;
  base_free(ptr);

}

// void getNameLine(char* filename, int line){
//     
// }
// #define cs0019_free() 

/// cs0019_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `cs0019_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `cs0019_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void *cs0019_realloc(void *ptr, size_t sz, const char *file, int line) {
  (void)file, (void)line;
  void *new_ptr = NULL;
  if (t == NULL){
    if (sz) {
      new_ptr = cs0019_malloc(sz, file, line);
    }
    if (ptr && new_ptr) {
      memcpy(new_ptr, ptr, lookup((long)ptr)->val);
      fillWithX(new_ptr, sz, 0x42);
      //*((char*)new_ptr + sz) = 0x42;
    }
  }else{
    long exists = lookup((long)ptr) -> val;
    if (exists == (long)-1){
      printf("MEMORY BUG: %s:%d: invalid realloc of pointer 0x%lx", file, line, (long)ptr);
      exit(0);
    }else{
      if (sz) {
        new_ptr = cs0019_malloc(sz, file, line);
      }
      if (ptr && new_ptr) {
        memcpy(new_ptr, ptr, exists);
        fillWithX(new_ptr, sz, 0x42);
        //*((char*)new_ptr + sz) = 0x42;
      }
    }
  }
  cs0019_free(ptr, file, line);
  return new_ptr;
}

/// cs0019_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then cs0019_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void *cs0019_calloc(size_t nmemb, size_t sz, const char *file, int line) {
  (void)file, (void)line;
  void *ptr;
  if (nmemb >= (size_t)0x100000001UL || sz >= (size_t)0x100000002UL){
    s -> nfail++;
    s -> fail_size = nmemb;
    return ptr = NULL;
  }
  if (!sz){
    return ptr = NULL;
  }
  ptr = cs0019_malloc(nmemb * sz, file, line);
  if (ptr) {
    memset(ptr, 0, nmemb * sz);
  }
  return ptr;
}


void cs0019_getstatistics(struct cs0019_statistics *stat) {
    *stat = stats;
}

void cs0019_printstatistics(void) {
    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


void cs0019_printleakreport(void) {
struct node* list;
struct node* temp;
  for(int i = 0; i<10; i++){
    list = t->list[i];
    temp = list;
    while(temp){
      printf("LEAK CHECK: %s:%d: allocated object 0x%lx with size %ld\n", temp->file, temp->line, temp->key, temp->val);
      temp = temp->next;
    }
  }
}

/// cs0019_printheavyhitterreport()
///    Print a report of all the heavy hitters as described
///    in the coursework handout.

void cs0019_printheavyhitterreport(void) {
// Your code here.
}
