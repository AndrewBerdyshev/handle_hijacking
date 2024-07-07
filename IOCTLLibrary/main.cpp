#include <Windows.h>
#include <cstdint>

enum ioctlCodes
{
    read,
    write,
    close
};
struct SharedMemory
{
    void* ioctlFuncAddress;
    HANDLE targetHandle;
    ioctlCodes flag;
    void* address;
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
    if (sharedMemory->flag == ioctlCodes::close)
    {
        UnmapViewOfFile(sharedMemory);
        CloseHandle(hMapFile);
        FreeLibraryAndExitThread(instance, NULL);
    }
    if (sharedMemory->flag == ioctlCodes::read)
        ReadProcessMemory(sharedMemory->targetHandle, sharedMemory->address, sharedMemory->buffer, sharedMemory->bufSize, nullptr);
    if (sharedMemory->flag == ioctlCodes::write)
        WriteProcessMemory(sharedMemory->targetHandle, sharedMemory->address, sharedMemory->buffer, sharedMemory->bufSize, nullptr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        instance = hinstDLL;
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "Global\\MySharedMemory");
        auto a = GetLastError();
        sharedMemory =
            reinterpret_cast<SharedMemory*>(MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemory)));
        sharedMemory->ioctlFuncAddress = IOCTLFunc;
    }
    return TRUE;
}