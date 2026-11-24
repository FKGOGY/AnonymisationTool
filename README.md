# AnonymisationTool

## About
CLI tool for anonymisation of industrial protocols IEC104, GOOSE, MMS and DLMS

## Requirements
* **Go 1.21+**

## Build & Run
Currently, will change later
```bash
make build
./anonymisationtool filename
```
Does not alter input file, create new one and should skip all protocols that are not IEC104, GOOSE, MMS or DLMS.
