CC = x86_64-w64-mingw32-gcc

# Build flags
CFLAGS := -Wall -Wno-unknown-pragmas -s -m64 -ffunction-sections -fno-asynchronous-unwind-tables \
			-nostdlib -fno-ident -O2 -c -Wl,-Tlinker.ld,--no-seh -mwindows -fno-ident \
			-Wl,--build-id=none -pipe -Wno-int-conversion -Wl,--gc-sections

shellcode:
	$(info ######  Compiling stack adjustment assembly  ######)
	@nasm -f win64 adjust-stack.asm -o adjust-stack.o

	$(info ######  Compiling C shellcode to object      ######)
	python3 formatter.py > temp.c
	@$(CC) $(CFLAGS) temp.c -o run.o
	rm temp.c
	
	$(info ######  Linking stack assembly and C code    ######)
	@x86_64-w64-mingw32-ld -s adjust-stack.o run.o -o run.exe
	
	$(info ######  Extracting .text section shellcode   ######)
	@objcopy -O binary --only-section=.text run.exe sleep.bin
	@rm run.exe
	@rm run.o
