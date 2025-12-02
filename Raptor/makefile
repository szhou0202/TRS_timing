CC = gcc
CFLAGS = -O3 -std=c99
OPENSSL_PREFIX = /opt/homebrew/opt/openssl@3

INCLUDES = -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto -lm

# SOURCES = test.c raptor.c linkable_raptor.c poly.c print.c \
#           falcon/falcon.c falcon/fft.c falcon/codec.c falcon/common.c \
#           rng/rng.c rng/aes.c
SOURCES = test.c raptor.c linkable_raptor.c poly.c print.c falcon/*.c rng/*.c
TARGET = raptor_test

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(INCLUDES) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o falcon/*.o rng/*.o
