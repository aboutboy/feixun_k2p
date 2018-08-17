EXE:=jy_black_list
CC:=gcc
#EXTRA_CFLAGS += -O2 -Wall -g $(CFLAGS)
EXTRA_CFLAGS += -Wall -g


OBJS = jy_black_list.o

all: $(EXE) 

$(EXE): $(OBJS)
	$(CC)  $(EXTRA_CFLAGS) -o $@ $(OBJS)

clean:
	-@rm -f *~ *.o $(EXE) *.d

$(OBJS): %.o : %.c
	$(CC) $(EXTRA_CFLAGS) -c $< -o $@

