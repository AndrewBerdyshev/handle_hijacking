#include "handle_hijacking.h"

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

ProcessWithHandle HandleHijacking(const char* targetProcess, uint32_t handleMinValue)
{
	// Enable working with system processes.
	EnableDebugPriv();
	const auto intermediateProcess = handle_hijacking::FindProcess(targetProcess, handleMinValue);
	if (!intermediateProcess.handle) return ProcessWithHandle{0};
	return intermediateProcess;
}

ProcessWithHandle handle_hijacking::FindProcess(const char* targetProcess, uint32_t handleMinValue)
{
	ProcessWithHandle result{ 0, nullptr };

	// I use svchost as it opens handle for all um processes, as I know :/
	// To not open a handle to it during searching process, xd. Idk about better way to know process name :/
	const auto targetProcessID = mylib::GetProcessID(targetProcess);

	// Just get a number of handles to alloc memory.
	auto systemInformation = new uint8_t[sizeof(SYSTEM_HANDLE_INFORMATION)];
	NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, 
		systemInformation, sizeof(SYSTEM_HANDLE_INFORMATION), nullptr);
	const auto handlesCount = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(systemInformation)->NumberOfHandles;
	delete[] systemInformation;

	// Get info properly.
	const auto allocSize = sizeof(ULONG) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * handlesCount;
	systemInformation = new uint8_t[allocSize];
	NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, 
		systemInformation, allocSize, nullptr);

	// Loop through table.
	HANDLE tempHandle;
	HANDLE tempTargetHandle;
	const auto currentProcess = GetCurrentProcess();
	for (size_t i = 0; i < handlesCount; i++)
	{
		const auto handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(systemInformation)->Handles[i];
		// Check for min access value.
		if (handleInfo.ObjectTypeIndex != 0x7) continue; // Is process handle.
		if ((handleInfo.GrantedAccess & handleMinValue) < handleMinValue) continue;
		if (handleInfo.UniqueProcessId == targetProcessID) continue;
		// Check the id.
		tempHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.UniqueProcessId);
		if (!tempHandle)
		{
			continue;
		}
		if (!DuplicateHandle(tempHandle, reinterpret_cast<HANDLE>(handleInfo.HandleValue), currentProcess,
			&tempTargetHandle, NULL, FALSE, DUPLICATE_SAME_ACCESS)) 
			// Note: avoid DuplicateHandle. I will not use this handle more, so, I guess, it's ud.
		{
			CloseHandle(tempHandle);
			continue;
		}
		if (GetProcessId(tempTargetHandle) == targetProcessID)
		{
			result.handle = reinterpret_cast<HANDLE>(handleInfo.HandleValue);
			result.processId = handleInfo.UniqueProcessId;
			CloseHandle(tempTargetHandle);
			CloseHandle(tempHandle);
			delete[] systemInformation;
			return result;
		}
		CloseHandle(tempTargetHandle);
		CloseHandle(tempHandle);
	}
	delete[] systemInformation;
	return result;
}

IOCTLProcess::IOCTLProcess(ProcessWithHandle process) :
	IntermediateProcessClass(process.processId, process.handle, __func__)
{
	
}

void IOCTLProcess::Write(void* address, uint8_t* buffer, size_t bufferSize)
{
	size_t offset = 0;
	while (bufferSize > sizeof(sharedMemory->buffer))
	{
		this->sharedMemory->flag = handle_hijacking::IOCTLFlag::write;
		this->sharedMemory->bufSize = sizeof(sharedMemory->buffer);
		this->sharedMemory->address = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address)+offset);
		memcpy(this->sharedMemory->buffer, buffer+offset, sizeof(sharedMemory->buffer));
		this->CallIntermediateFunc();
		bufferSize -= sizeof(sharedMemory->buffer);
		offset += sizeof(sharedMemory->buffer);
	}
	if (bufferSize)
	{
		this->sharedMemory->flag = handle_hijacking::IOCTLFlag::write;
		this->sharedMemory->bufSize = bufferSize;
		this->sharedMemory->address = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address) + offset);
		memcpy(this->sharedMemory->buffer, buffer+offset, bufferSize);
		this->CallIntermediateFunc();
	}
}

void IOCTLProcess::Read(void* address, uint8_t* buffer, size_t bufferSize)
{
	size_t offset = 0;
	while (bufferSize > sizeof(sharedMemory->buffer))
	{
		this->sharedMemory->flag = handle_hijacking::IOCTLFlag::read;
		this->sharedMemory->bufSize = sizeof(sharedMemory->buffer);
		this->sharedMemory->address = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address) + offset);
		this->CallIntermediateFunc();
		memcpy(buffer+offset, this->sharedMemory->buffer, sizeof(sharedMemory->buffer));
		bufferSize -= sizeof(sharedMemory->buffer);
		offset += sizeof(sharedMemory->buffer);
	}
	if (bufferSize)
	{
		this->sharedMemory->flag = handle_hijacking::IOCTLFlag::read;
		this->sharedMemory->bufSize = bufferSize;
		this->sharedMemory->address = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address) + offset);
		this->CallIntermediateFunc();
		memcpy(buffer + offset, this->sharedMemory->buffer, sizeof(sharedMemory->buffer));
	}
}

void* IOCTLProcess::Alloc(size_t bufferSize)
{
	this->sharedMemory->flag = handle_hijacking::IOCTLFlag::alloc;
	this->sharedMemory->bufSize = bufferSize;
	this->sharedMemory->address = nullptr;
	this->CallIntermediateFunc();
	return this->sharedMemory->address;
}

void IOCTLProcess::Free(void* address, size_t bufferSize)
{
	this->sharedMemory->flag = handle_hijacking::IOCTLFlag::release;
	this->sharedMemory->bufSize = bufferSize;
	this->sharedMemory->address = address;
	this->CallIntermediateFunc();
}

IOCTLProcess::~IOCTLProcess()
{

}

IntermediateProcessClass::IntermediateProcessClass(DWORD processId, HANDLE targetHandle, const char* name)
{
	this->intermediateProcess = OpenProcess(
		// CreateRemoteThread
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, processId);

	if (!this->intermediateProcess) return;

	this->hMapFile = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		sizeof(handle_hijacking::SharedMemory),
		(std::string("Global\\") + name).c_str()); // Fix it. Should be random string. Allows several ioctl pipes :)

	if (!this->hMapFile) return;
	this->sharedMemory = reinterpret_cast<handle_hijacking::SharedMemory*>
		(MapViewOfFile(this->hMapFile, FILE_MAP_WRITE, 0, 0, sizeof(handle_hijacking::SharedMemory)));

	if (!this->sharedMemory) return;

	this->sharedMemory->targetHandle = targetHandle;

	// Inject dll with func which will help implement a data pipe.
	char fullPath[MAX_PATH];
	if (!GetFullPathNameA((std::string(name) + ".dll").c_str(), MAX_PATH, fullPath, nullptr)) return;
	const auto alloc = VirtualAllocEx(this->intermediateProcess, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc) return;
	if (!WriteProcessMemory(this->intermediateProcess, alloc, fullPath, MAX_PATH, nullptr)) return;
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), alloc, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

IntermediateProcessClass::~IntermediateProcessClass()
{
	// Reserved close flag.
	this->sharedMemory->flag = -1;
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(sharedMemory->funcAddress), nullptr, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	UnmapViewOfFile(this->sharedMemory);
	CloseHandle(this->hMapFile);
	CloseHandle(this->intermediateProcess);
}

void IntermediateProcessClass::CallIntermediateFunc()
{
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(this->sharedMemory->funcAddress), nullptr, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

ThreadProcess::ThreadProcess(ProcessWithHandle process) :
	IntermediateProcessClass(process.processId, process.handle, __func__)
{
}

DWORD ThreadProcess::GetThreadId()
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::getThreadId;
	this->CallIntermediateFunc();
	return *reinterpret_cast<DWORD*>(this->sharedMemory->buffer);
}

HANDLE ThreadProcess::OpenThread(DWORD pid)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::openThread;
	*reinterpret_cast<DWORD*>(this->sharedMemory->buffer) = pid;
	this->CallIntermediateFunc();
	return *reinterpret_cast<HANDLE*>(this->sharedMemory->buffer);
}

void ThreadProcess::SuspendThread(HANDLE thread)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::suspendThread;
	*reinterpret_cast<HANDLE*>(sharedMemory->buffer) = thread;
	this->CallIntermediateFunc();
}

void ThreadProcess::GetThreadContext(HANDLE thread, CONTEXT* context)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::getThreadContext;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	*reinterpret_cast<CONTEXT*>(this->sharedMemory->buffer+sizeof(HANDLE)) = *context;
	this->CallIntermediateFunc();
	*context = *reinterpret_cast<CONTEXT*>(this->sharedMemory->buffer);
}

void ThreadProcess::SetThreadContext(HANDLE thread, const CONTEXT* context)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::setThreadContext;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	*reinterpret_cast<CONTEXT*>(this->sharedMemory->buffer+sizeof(HANDLE)) = *context;
	this->CallIntermediateFunc();
}

void ThreadProcess::ResumeThread(HANDLE thread)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::resumeThread;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	this->CallIntermediateFunc();
}

void ThreadProcess::CloseHandle(HANDLE thread)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::closeHandle;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	this->CallIntermediateFunc();
}

void ThreadProcess::GetThreadContext64(HANDLE thread, WOW64_CONTEXT* context)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::getThreadContext64;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	*reinterpret_cast<WOW64_CONTEXT*>(this->sharedMemory->buffer + sizeof(HANDLE)) = *context;
	this->CallIntermediateFunc();
	*context = *reinterpret_cast<WOW64_CONTEXT*>(this->sharedMemory->buffer);
}

void ThreadProcess::ChangeRip(HANDLE thread, uint64_t* rip)
{
	this->sharedMemory->flag = handle_hijacking::ThreadFlag::changeRip;
	*reinterpret_cast<HANDLE*>(this->sharedMemory->buffer) = thread;
	*reinterpret_cast<uint64_t*>(this->sharedMemory->buffer + sizeof(HANDLE)) = *rip;
	this->CallIntermediateFunc();
	*rip = *reinterpret_cast<uint64_t*>(this->sharedMemory->buffer);
}

ThreadProcess::~ThreadProcess()
{
}
