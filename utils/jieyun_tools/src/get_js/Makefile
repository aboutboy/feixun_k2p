EXE:=get_js
#EXTRA_CFLAGS += -O2 -Wall -g $(CFLAGS)
EXTRA_CFLAGS += -Wall -g


OBJS = get_js.o md5.o

all: $(EXE) 

$(EXE): $(OBJS)
	$(CC) $(EXTRA_CFLAGS) -o $@ $(OBJS) -lcurl
$(OBJS): %.o : %.c
	$(CC) $(EXTRA_CFLAGS) -c  $< -o $@ 
clean:
	-@rm -f *~ *.o $(EXE) *.d

