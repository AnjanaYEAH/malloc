#include "cs0019.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
// Diabolical wild free #2.

int main() {
  char *a = (char *)malloc(200);
  char *b = (char *)malloc(50);
  char *c = (char *)malloc(200);
  char *p = (char *)malloc(3000);
  (void)a, (void)c;
  memcpy(p, b - 200, 450);
  free(b);
  memcpy(b - 200, p, 450);
  free(b);
  cs0019_printstatistics();
}

//! MEMORY BUG???: ??? free of pointer ???
//! ???
