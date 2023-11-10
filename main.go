//go:build windows

package main

//void runFunction(void* Function, int x, void* cInteger) {
//    ((void(*)())Function)(x, cInteger);
//}
import "C"
import (
	_ "embed"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"
)

//go:embed shellcode/sleep.bin
var sc []byte

var addr uintptr

func SleepEnc(d time.Duration) {
	log.Printf("Start Encrypted Sleep for %d\n", d.Milliseconds())
	C.runFunction(unsafe.Pointer(addr), C.int(d.Milliseconds()), cInteger)
	log.Println("End Encrypted Sleep")
}

type MyStruct struct {
	data int
}

var cInteger unsafe.Pointer

func init() {
	// this is probably a very stupid way to get the current heap start but as the heap is not fix, i dont know how else to do it
	myStruct := MyStruct{data: 42}
	cInteger = unsafe.Pointer(&myStruct)

	// now lets initialize our sleep shellcode
	var (
		kernel32       = syscall.NewLazyDLL("kernel32.dll")
		VirtualAlloc   = kernel32.NewProc("VirtualAlloc")
		VirtualProtect = kernel32.NewProc("VirtualProtect")
	)

	addr, _, _ = VirtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x04)
	for i := uintptr(0); i < uintptr(len(sc)); i++ {
		*(*byte)(unsafe.Pointer(addr + i)) = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&sc[0])) + i))
	}
	oldProtect := 0x04
	VirtualProtect.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&oldProtect)))

	log.Printf("Shellcode address: %#x\n", uintptr(addr))
}

func main() {
	fmt.Println("Press enter to sleep")
	fmt.Scanln()
	SleepEnc(40 * time.Second)
	fmt.Println("Press enter to close this window")
	fmt.Scanln()
}
