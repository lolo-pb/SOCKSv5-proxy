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
BUFFER_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/buffer_test
SELECTOR_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/selector_test
STM_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/stm_test
PARSER_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/parser_test
NETUTILS_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/netutils_test
USER_TABLE_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/user_table_test
METRICS_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/metrics_test
ACCESS_LOG_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/access_log_test
MON_CLIENT_TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/mon_client_test
CHECK_LIBS=$(shell pkg-config --libs check 2>/dev/null || echo -lcheck -lsubunit) -lrt -lm
CLIENT_LIBS=-lncursesw

TEST_BINS=$(SOCKS_TEST_OUTPUT_FILE) \
          $(BUFFER_TEST_OUTPUT_FILE) \
          $(SELECTOR_TEST_OUTPUT_FILE) \
          $(STM_TEST_OUTPUT_FILE) \
          $(PARSER_TEST_OUTPUT_FILE) \
          $(NETUTILS_TEST_OUTPUT_FILE) \
          $(USER_TABLE_TEST_OUTPUT_FILE) \
          $(METRICS_TEST_OUTPUT_FILE) \
          $(ACCESS_LOG_TEST_OUTPUT_FILE) \
          $(MON_CLIENT_TEST_OUTPUT_FILE)

all: client server
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "--- $$t ---"; $$t || exit 1; done

$(SOCKS_TEST_OUTPUT_FILE): tests/socks_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include $< -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(BUFFER_TEST_OUTPUT_FILE): tests/buffer_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/shared $< -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(SELECTOR_TEST_OUTPUT_FILE): tests/selector_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/shared $< -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(STM_TEST_OUTPUT_FILE): tests/stm_test.c src/shared/stm.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include $^ -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(PARSER_TEST_OUTPUT_FILE): tests/parser_test.c src/shared/parser.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include $^ -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(NETUTILS_TEST_OUTPUT_FILE): tests/netutils_test.c src/shared/netutils.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include $^ -o $@ $(CHECK_LIBS) $(LD_FLAGS)

$(USER_TABLE_TEST_OUTPUT_FILE): tests/user_table_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include -I src/server $< -o $@ $(LD_FLAGS)

$(METRICS_TEST_OUTPUT_FILE): tests/metrics_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include -I src/server $< -o $@ $(LD_FLAGS)

$(ACCESS_LOG_TEST_OUTPUT_FILE): tests/access_log_test.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include -I src/server $< -o $@ $(LD_FLAGS)

$(MON_CLIENT_TEST_OUTPUT_FILE): tests/mon_client_test.c src/shared/buffer.c src/shared/selector.c src/shared/stm.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -I src/shared/include -I src/server/include -I src/client/include -I src/client -I src/shared $^ -o $@ $(LD_FLAGS)

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
