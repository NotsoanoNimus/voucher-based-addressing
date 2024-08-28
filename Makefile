# Compiler
CC = g++
# Compiler flags
#   Optimization level can be tweaked if over-optimization occurs.
CFLAGS = -O3 -Wall -fpermissive
LDLIBS = -lssl -lcrypto -largon2 -lscrypt 
#-lscrypt-kdf

# Get all .c and .cpp files in the current directory
SRCS = $(wildcard *.c)
# Generate object files from source files
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = vba-tests

# Default target
all: $(TARGET)

# Compile source files
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# Generate object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up object files
clean:
	rm -f *.o

# Clean up object files and compiled binary
cleanall: clean
	rm -f $(TARGET)
