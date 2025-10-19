# Compilers
CXX = g++
CC = gcc

# Compiler flags
CXXFLAGS = -Wall -g -std=c++17
CFLAGS = -Wall -g

# Linker flags for OpenSSL
LDFLAGS = -lssl -lcrypto

# Target executable name
TARGET = file_encrypter

# Source and object files
# C++ sources
CXX_SRCS = main.cpp encryption.cpp
# C sources
C_SRCS = applink.c

# Generate object file names from source file names
OBJS = $(CXX_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

# Default rule
all: $(TARGET)

# Rule to link the final executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Rule to compile C++ source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to compile C source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up
clean:
	rm -f $(OBJS) $(TARGET) *.enc *.dec *.key *.iv *.pem
