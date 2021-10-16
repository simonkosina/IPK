CC=g++
CFLAGS=-g -Wall -pedantic -std=c++11
LFLAGS=-lpcap
PROJ=ipk-sniffer

all:
	$(CC) $(FLAGS) -o $(PROJ) $(PROJ).cpp $(LFLAGS)

clean:
	rm *.o $(PROJ)
