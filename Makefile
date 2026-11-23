.PHONY: build test clean

TARGET = anonymisationtool

build:
	go build -o $(TARGET) ./cmd/

run:
	./anonymisationtool

test:
	go test

clean:
	rm -f $(TARGET)
