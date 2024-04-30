WORKING_DIRS=tmp
SRC=$(shell find . -name "*.go")
BIN=tmp/$(shell basename $(CURDIR))
TESTBIN=tmp/$(shell basename $(CURDIR))-test
FMT=tmp/fmt
TEST=tmp/test

.PHONY: all clean

all: $(WORKING_DIRS) $(FMT) $(BIN) $(TEST)

clean:
	rm -rf $(WORKING_DIRS)

$(WORKING_DIRS):
	mkdir -p $(WORKING_DIRS)

$(FMT): $(SRC)
	go fmt ./... > $(FMT) 2>&1 || true

$(BIN): $(SRC)
	go build -o $(BIN)

$(TEST): $(BIN)
	go test -v -tags=mock -cover -coverprofile=tmp/cover ./... > $(TEST) 2>&1; \
  cat $(TEST); \
  grep "0$$" tmp/cover || true
