TARGETS=websockify

all: $(TARGETS)

websockify: websockify.o websocket.o
	$(CC) $(LDFLAGS) $^ -o $@

websocket.o: websocket.c websocket.h
websockify.o: websockify.c websocket.h

clean:
	rm -f websockify *.o
