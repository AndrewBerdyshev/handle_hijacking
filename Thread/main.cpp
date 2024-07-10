#include <Windows.h>
#include <cstdint>
#include <mylib.h>

enum ThreadFlag
{
    getThreadId,
    openThread,
    suspendThread,
    getThreadContext,
    setThreadContext,
    resumeThread,
    closeHandle,
    getThreadContext64,
    changeRip,
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

void ThreadFunc()
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
    else if (sharedMemory->flag == ThreadFlag::getThreadId)
        *reinterpret_cast<DWORD*>(sharedMemory->buffer) = mylib::GetThreadID(GetProcessId(sharedMemory->targetHandle));
    else if (sharedMemory->flag == ThreadFlag::openThread)
        *reinterpret_cast<HANDLE*>(sharedMemory->buffer) =
        OpenThread(THREAD_ALL_ACCESS, FALSE, *reinterpret_cast<DWORD*>(sharedMemory->buffer));
    else if (sharedMemory->flag == ThreadFlag::suspendThread)
        SuspendThread(*reinterpret_cast<HANDLE*>(sharedMemory->buffer));
    else if (sharedMemory->flag == ThreadFlag::resumeThread)
        ResumeThread(*reinterpret_cast<HANDLE*>(sharedMemory->buffer));
    else if (sharedMemory->flag == ThreadFlag::closeHandle)
        CloseHandle(*reinterpret_cast<HANDLE*>(sharedMemory->buffer));
    else if (sharedMemory->flag == ThreadFlag::changeRip)
    {
        CONTEXT context;
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(*reinterpret_cast<HANDLE*>(sharedMemory->buffer), &context);
        const auto ripTemp = context.Rip;
        context.Rip = *reinterpret_cast<uint64_t*>(sharedMemory->buffer + sizeof(HANDLE));
        SetThreadContext(*reinterpret_cast<HANDLE*>(sharedMemory->buffer), &context);
        *reinterpret_cast<uint64_t*>(sharedMemory->buffer) = ripTemp;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        instance = hinstDLL;
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "Global\\ThreadProcess");
        auto a = GetLastError();
        sharedMemory =
            reinterpret_cast<SharedMemory*>(MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemory)));
        sharedMemory->funcAddress = ThreadFunc;
    }
    return TRUE;
}