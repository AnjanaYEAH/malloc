#include "cs0019.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
// Calloc.

const char data[10] = "\0\0\0\0\0\0\0\0\0\0";

int main() {
  char *p = (char *)calloc(1, 10);
  assert(p != NULL);
  assert(memcmp(data, p, 10) == 0);
  cs0019_printstatistics();
}

//! malloc count: active          1   total          1   fail          0
//! malloc size:  active         10   total         10   fail          0
