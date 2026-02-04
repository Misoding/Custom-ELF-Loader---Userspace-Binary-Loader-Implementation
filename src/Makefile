CFLAGS= -g -static-pie -o

all: elf-loader

elf-loader: elf-loader.c
	gcc $(CFLAGS) $@ $<

pack: clean
	zip -r ../src.zip *

clean:
	-rm -f *.o elf-loader
