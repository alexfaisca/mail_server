CC = g++
CFLAGS = -Wall -Wextra -std=c++17
CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lseccomp
TARGET = containerize
SRC = containerize.cpp
OBJ = $(SRC:.cpp=.o)

all: $(TARGET) object_files

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

object_files:
	rm -f $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)
