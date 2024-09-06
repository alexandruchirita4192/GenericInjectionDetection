# Define the compiler
CXX := g++

# Define the executable name
EXECUTABLE := injection_detector

# Source files
SOURCES := main.cpp
HEADERS :=

# Detect platform and set platform-specific variables
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
    # Linux-specific files and flags
    HEADERS += linux_injection_detector.h
    LDFLAGS := -lssl -lcrypto  # Link OpenSSL for checksum verification on Linux
else
    # Windows-specific files and flags
    HEADERS += windows_injection_detector.h
    # Link WinTrust for DLL signature verification on Windows; Link with most static libraries because they were not found
    LDFLAGS := -lwintrust -lcrypt32 -static-libgcc -static-libstdc++ --static

endif

# Object files
OBJECTS := $(SOURCES:.cpp=.o)

# Compiler flags
CXXFLAGS := -Wall -g

# Default target
all: $(EXECUTABLE)

# Compile and link the executable
$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS) $(HEADERS) $(LDFLAGS)

# Clean up object files and executables
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
