PROJ=ascon_bza
SRC_DIR=src
DOC_DIR=doc
BUILD_DIR=build

CC=gcc
CFLAGS=-Wall -Wextra -O2 -MMD -Werror -Wpedantic -g
DEBUG_FLAG=-DDEBUG_F
# LDFLAGS=

SRCS=$(wildcard $(SRC_DIR)/*.c)
OBJS=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.d,$(SRCS))
DEBUG_OBJS=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%-debug.o,$(SRCS))

# remove the main.o of the main program
TEST_OBJS=$(subst $(BUILD_DIR)/main.o,,$(OBJS))
TEST_DEBUG_OBJS=$(subst $(BUILD_DIR)/main-debug.o,,$(DEBUG_OBJS))

DOCS=$(wildcard $(DOC_DIR)/*.typ)

$(PROJ): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

debug: $(DEBUG_OBJS)
	$(CC) $(DEBUG_FLAG) $(CFLAGS) -o $(PROJ) $^

test: test/main.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test $^ && \
	./$(BUILD_DIR)/test -v

test_debug: test/main.c $(TEST_DEBUG_OBJS)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test $^ && \
	./$(BUILD_DIR)/test -v

doc: doc/documentation.typ
	typst c doc/documentation.typ documentation.pdf

pack: doc
	zip -r xnguye27.zip src/ test/ Makefile documentation.pdf

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%-debug.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(DEBUG_FLAG) $(CFLAGS) -c $< -o $@

-include $(DEPS)

.PHONY: clean doc
clean:
	rm -rf $(BUILD_DIR) $(PROJ)
