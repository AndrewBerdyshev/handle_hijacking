#pragma once
#include <cstdint>
#include <Windows.h>
#include "api.h"
#include <mylib.h>

class IOCTLProcess;
IOCTLProcess* HandleHijacking(const char* targetProcess, uint32_t handleMinValue);

namespace handle_hijacking
{
	inline auto NtQuerySystemInformation = 
		reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

	struct ProcessWithHandle
	{
		DWORD processId;
		HANDLE handle;
	};
	// Finds a process with required preferences.
	ProcessWithHandle FindProcess(const char* targetProcess, uint32_t handleMinValue);

	// For data exchanging between processes.
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
}

// Process interface to read/write target's process memory.
class IOCTLProcess
{
private:
	HANDLE intermediateProcess;
	handle_hijacking::SharedMemory* sharedMemory;
	HANDLE hMapFile;
	void UnloadHelpLibrary();
public:
	IOCTLProcess(DWORD processId, HANDLE targetHandle);
	void Write(void* address, uint8_t* buffer, size_t bufferSize);
	void Read(void* address, uint8_t* buffer, size_t bufferSize);
	~IOCTLProcess();
};