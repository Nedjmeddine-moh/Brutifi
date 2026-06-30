# Brutifi - Unified Security Testing Framework
# Author: Nedjmeddine

CXX = g++
CXXFLAGS = -O3 -std=c++17 -Wall -Wextra -pthread
TARGET = brutifi
SRC = brutifi.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: all clean install
