# GoSleepyCrypt

Sleep and heap encryption for a Go application through a shellcode function.

The basic concept and a lot of the code is taken from [here](https://github.com/SolomonSklash/SleepyCrypt), so all the credits go to Solomon Sklash.

I ran into a few issues when porting this to Go, I suspect its because of some internal multithreading. I solved it by suspending all threads of the process. Additionally I added an awkward heap encryption.

Feel free to use this code but it is not field tested yet.

![](/screenshot/screen.png?raw=true "")

## Build
make