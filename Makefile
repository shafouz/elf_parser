CC = clang 

CFLAGS=-g -O0 -fsanitize=address,undefined -I/usr/include

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

EXEC = elf_parser

# Default target
all: $(EXEC)

# Link object files to create executable
$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJ) $(EXEC)

