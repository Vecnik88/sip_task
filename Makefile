CC = gcc
CFLAGS =
LDFLAGS =
SOURCES = parse_sip.c
EXECUTABLE = parse_sip

.PHONY: all clean build

all: clean build

build:
	@$(CC) $(SOURCES) -o $(EXECUTABLE) -lpcap
clean:
	@rm -f $(EXECUTABLE)
