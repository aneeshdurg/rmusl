#include "stdio_impl.h"
#include "unistd.h"

FILE *__ofl_add(FILE *f)
{
  write(1, "ofladd 0\n", 9);
	FILE **head = __ofl_lock();
  write(1, "ofladd 1\n", 9);
	f->next = *head;
  write(1, "ofladd 2\n", 9);
  printf("head %p\n", head);
  printf("*head %p\n", *head);
	if (*head) (*head)->prev = f;
  write(1, "ofladd 3\n", 9);
	*head = f;
  write(1, "ofladd 4\n", 9);
	__ofl_unlock();
  write(1, "ofladd 5\n", 9);
	return f;
}
