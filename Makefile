BUILD_COMMAND := GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -trimpath=true -buildvcs=false

default:
	cd shellcode && make shellcode
	CGO_ENABLED=1 $(BUILD_COMMAND) -o main.exe .
