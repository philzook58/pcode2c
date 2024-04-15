#include <assert.h>
#include <stdbool.h>
bool equal(int n, int a[], int b[]) {
  for (int i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

int main() {
  int a[10]; // = {42}; //calloc(10*sizeof(int));
  assert(equal(10, a, a));
}