LDLIBS += -lpcap

all: tcp-block

tcp-block: main.o src/arphdr.o src/ethhdr.o src/ip.o src/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: tcp-block.h main.cpp

clean:
	rm -f tcp-block
	rm -f *.o
	rm -f tcp-block src/*.o
