APP    = homingcanary
CC     = gcc
CFLAGS = -g3 -O0 -Wall
LDLIBS = -lm
SRCS   = main.c
OBJS   = $(SRCS:.c=.o)

all: $(APP)

$(APP): $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDLIBS)

.PHONY: test
test: test.c
	$(CC) $^ -o $@ -pthread

clean:
	$(RM) $(APP) $(OBJS) test
