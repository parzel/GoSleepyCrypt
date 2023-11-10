#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "function-resolution.h"

// Message box function pointer.
typedef int (*fpMessageBoxA)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

// VirtualProtect function pointer.
typedef BOOL (*fpVirtualProtect)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

// Sleep function pointer.
typedef void (*fpSleep)(
  DWORD dwMilliseconds
);

typedef SIZE_T (*fpVirtualQuery)(
  LPCVOID                   lpAddress,
  PMEMORY_BASIC_INFORMATION lpBuffer,
  SIZE_T                    dwLength
);

typedef int (*fpPrintf)(
   const char *format,
   ...
);

typedef HMODULE (*fpGetModuleHandleA)(
  LPCSTR lpModuleName
);

typedef void (*fpGetSystemTime)(
  LPSYSTEMTIME lpSystemTime
);

typedef BOOL (*fpSystemTimeToFileTime)(
  const SYSTEMTIME *lpSystemTime,
  LPFILETIME       lpFileTime
);

typedef DWORD (*fpGetCurrentThreadId) (void);
typedef HANDLE (*fpCreateToolhelp32Snapshot)(DWORD,DWORD);
typedef BOOL (*fpThread32First)(HANDLE,LPTHREADENTRY32);
typedef HANDLE (*fpOpenThread) (DWORD, BOOL, DWORD);
typedef DWORD (*fpSuspendThread) (HANDLE);
typedef BOOL (*fpCloseHandle) (HANDLE);
typedef BOOL (*fpThread32Next)(HANDLE,LPTHREADENTRY32);
typedef DWORD (*fpGetCurrentProcessId) (void);
typedef DWORD (*fpResumeThread) (HANDLE);
typedef BOOL (*fpAttachConsole)(DWORD);




// djb2 hashes for dynamic function resolution.
// djb2 = lambda x: functools.reduce(lambda x,c: 0xFFFFFFFF & (x*33 + c), x, 8191)
// hex(djb2(b'MessageBoxA'))
#define VirtualProtect_HASH   0xc25aaa07
#define KERNEL32DLL_HASH1     0xa709e74f /// Hash of KERNEL32.DLL
#define KERNEL32DLL_HASH2     0xa96f406f /// Hash of kernel32.dll
#define KERNEL32DLL_HASH3     0x8b03944f /// Hash of Kernel32.dll
#define Sleep_HASH            0xa8d9dd38
#define USER32DLL_HASH1       0x36095f6d /// Hash of user32.dll
#define USER32DLL_HASH2       0xb4b73b4d /// Hash of User32.dll
#define USER32DLL_HASH3       0xfda65a8d /// Hash of USER32.dll
#define MessageBoxA_HASH      0x879e0f6e
#define VirtualQuery_HASH     0x7280bbbc
#define WriteConsole_HASH     0x6ef242fd
#define MSVCRTDLL_HASH        0xdb09bae8
#define Printf_HASH           0x82a0a32
#define GetModuleHandleA_HASH 0x45affe52
#define GetSystemTime_HASH    0xe20774f3
#define SystemTimeToFileTime_HASH    0x64cf6c45
#define GetCurrentThreadId_HASH 0xfe4a807
#define CreateToolhelp32Snapshot_HASH 0x69842b8f
#define Thread32First_HASH 0xf1fd2b84
#define OpenThread_HASH 0x5c0a4309
#define SuspendThread_HASH 0xeaefe399
#define CloseHandle_HASH 0x87bfc4c1
#define Thread32Next_HASH 0xa2805bdb
#define GetCurrentProcessId_HASH 0x89d2796e
#define ResumeThread_HASH 0xad447c68
#define AttachConsole_HASH 0x4eaeefa7


// XOR a buffer with a single byte key.
VOID XORSingle( CHAR szInput[], SIZE_T nLength, BYTE cKey );

// Round a value to the nearest multiple. For rounding to the nearest 4k page.
ULONGLONG RoundUp( ULONGLONG numToRound, ULONGLONG multiple);

// XOR encrypt a section.
BOOL EncryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect );

// XOR decrypt a section.
BOOL DecryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect );
