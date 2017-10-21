#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#define N_THREADS 5

static void *test(void *unused)
{
    uintptr_t ret;
    asm volatile("mov %%rbp, %0" : "=r"(ret));
    printf("Ready to be patched.  PID: %d (%p)\n", getpid(), ret+8);
    sleep(15);
}

int main(void)
{
    pthread_t threads[N_THREADS] = {0};

    for (;;) {
      for (int i=0; i<N_THREADS; ++i)
        pthread_create(&threads[i], NULL, test, NULL);

      // The threads should be sleeping.  Hopefully
      // the POC (main.c) can be used to patch the memory
      // of this process before the threads return.  
      //
      // When the threads return, a SEGV should occur 
      // becuase the patch'd address should be a faulty
      // address, like 0xdeadbeef;
      for (int i=0; i<N_THREADS; ++i)
        pthread_join(threads[i], NULL);
    }

    return 0;
}
