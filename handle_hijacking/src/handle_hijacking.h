#pragma once
#include <cstdint>
#include <Windows.h>
#include "api.h"
#include <string>
#include <mylib.h>

struct ProcessWithHandle
{
	DWORD processId;
	HANDLE handle;
};
ProcessWithHandle HandleHijacking(const char* targetProcess, uint32_t handleMinValue);

namespace handle_hijacking
{
	inline auto NtQuerySystemInformation = 
		reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	// Finds a process with required preferences.
	ProcessWithHandle FindProcess(const char* targetProcess, uint32_t handleMinValue);

	// For data exchanging between processes.
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
	enum IOCTLFlag
	{
		read,
		write,
		alloc,
		release,
	};
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
}

class IntermediateProcessClass
{
public:
	IntermediateProcessClass(DWORD processId, HANDLE targetHandlem, const char* name);
	~IntermediateProcessClass();
protected:
	HANDLE intermediateProcess;
	handle_hijacking::SharedMemory* sharedMemory;
	HANDLE hMapFile;
	void CallIntermediateFunc();
};

// Process interface to read/write target's process memory.
class IOCTLProcess : public IntermediateProcessClass
{
public:
	IOCTLProcess(ProcessWithHandle process);
	void Write(void* address, uint8_t* buffer, size_t bufferSize);
	void Read(void* address, uint8_t* buffer, size_t bufferSize);
	void* Alloc(size_t bufferSize);
	void Free(void* address, size_t bufferSize);
	~IOCTLProcess();
};

// Process interface to control target's threads.
class ThreadProcess : public IntermediateProcessClass
{
public:
	ThreadProcess(ProcessWithHandle process);
	DWORD GetThreadId();
	HANDLE OpenThread(DWORD pid);
	void SuspendThread(HANDLE thread);
	void GetThreadContext(HANDLE thread, CONTEXT* context); // dont work.
	void SetThreadContext(HANDLE thread, const CONTEXT* context); // dont work.
	void ResumeThread(HANDLE thread);
	void CloseHandle(HANDLE thread);
	void GetThreadContext64(HANDLE thread, WOW64_CONTEXT* context); // dont work.
	void ChangeRip(HANDLE thread, uint64_t* rip);
	~ThreadProcess();
};