SRCS = $(wildcard *.c ../public_fun/*.c)
OBJS = $(SRCS:.c = .o)
CC = gcc
INCLUDE = -I. -I../public_fun
LIBS = -lcurl -lpthread -L.
CCFLAGS = -g -Wall
EXE = day_statis

all : $(EXE)

$(EXE) : $(OBJS)
	$(CC) $^ -o $@ $(INCLUDE) $(LIBS)
%.o : %.c
	$(CC) -c $< $(CCFLAGS)

clean :
	rm -rf *.out *.o $(EXE)

.PHONY : clean
