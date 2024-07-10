#include <Windows.h>
#include <cstdint>

enum IOCTLFlag
{
    read,
    write,
    alloc,
    release,
};
struct SharedMemory
{
    void* funcAddress;
    HANDLE targetHandle;
    int32_t flag;
    void* address;
    // Max possible size on my pc.
    uint8_t buffer[1024];
    size_t bufSize;
};
HINSTANCE instance;
HANDLE hMapFile;
SharedMemory* sharedMemory;

void IOCTLFunc()
{
    // I dont like checks, but in this case i dont want blue screen.
    if (!hMapFile) return;
    if (!sharedMemory) return;
    if (sharedMemory->flag == -1)
    {
        UnmapViewOfFile(sharedMemory);
        CloseHandle(hMapFile);
        FreeLibraryAndExitThread(instance, NULL);
    }
    else if (sharedMemory->flag == IOCTLFlag::read)
        ReadProcessMemory(sharedMemory->targetHandle, sharedMemory->address, sharedMemory->buffer, sharedMemory->bufSize, nullptr);
    else if (sharedMemory->flag == IOCTLFlag::write)
        WriteProcessMemory(sharedMemory->targetHandle, sharedMemory->address, sharedMemory->buffer, sharedMemory->bufSize, nullptr);
    else if (sharedMemory->flag == IOCTLFlag::alloc)
        sharedMemory->address = VirtualAllocEx(sharedMemory->targetHandle, nullptr, 
            sharedMemory->bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    else if (sharedMemory->flag == IOCTLFlag::release)
        VirtualFreeEx(sharedMemory->targetHandle, sharedMemory->address,
            sharedMemory->bufSize, MEM_RELEASE);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        instance = hinstDLL;
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "Global\\IOCTLProcess");
        auto a = GetLastError();
        sharedMemory =
            reinterpret_cast<SharedMemory*>(MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemory)));
        sharedMemory->funcAddress = IOCTLFunc;
    }
    return TRUE;
}