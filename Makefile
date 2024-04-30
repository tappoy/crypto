WORKING_DIRS=tmp
SRC=$(shell find . -name "*.go")
BIN=tmp/$(shell basename $(CURDIR))
FMT=tmp/fmt
TEST=tmp/cover

.PHONY: all clean cover

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
	go test -v -tags=mock -cover -coverprofile=$(TEST) ./...

cover: $(TEST)
	grep "0$$" $(TEST) || true
