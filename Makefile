CXX = clang++

# path
INCLUDES= -I include/ -I /usr/local/include
LIBS	= -lcryptopp
CXXFLAGS= $(INCLUDES) $(LIBS) -std=c++11 -Wall -Wextra -g
AR	= ar

.SUFFIXES: .cpp .o

# Create a list of source files.
SOURCES = $(shell ls src/*.cpp)
# Create a list of object files from the same source file lists
OBJECTS = ${SOURCES:.cpp=.o}
# Create a list of targets
TARGETS = bin/totp

default: all

# Build all targets by default
all:	$(TARGETS)

# A rule to build .o file out of a .cpp file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

$(TARGETS): $(OBJECTS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $^ -o $(TARGETS)

# A rule to clean all the intermediates and targets
clean:
	rm -rf $(TARGETS) $(OBJECTS) *.out *.stackdump
