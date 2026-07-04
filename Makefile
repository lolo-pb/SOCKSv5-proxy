include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c) $(wildcard src/client/ui/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/server
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client
SOCKS_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks_test
CHECK_LIBS=-lcheck -lsubunit -lrt -lm
CLIENT_LIBS=-lncursesw

all: client server
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
test: $(SOCKS_TEST_OUTPUT_FILE)
	$(SOCKS_TEST_OUTPUT_FILE)

$(SOCKS_TEST_OUTPUT_FILE): tests/socks_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include $< -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE) $(CLIENT_LIBS)

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/client/ui
	mkdir -p $(OBJECTS_FOLDER)/shared
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include -I src/client/include -c $< -o $@

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client test clean
