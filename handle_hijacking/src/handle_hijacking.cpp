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

IOCTLProcess* HandleHijacking(const char* targetProcess, uint32_t handleMinValue)
{
	// Enable working with system processes.
	EnableDebugPriv();
	const auto intermediateProcess = handle_hijacking::FindProcess(targetProcess, handleMinValue);
	if (!intermediateProcess.handle) return nullptr;
	return new IOCTLProcess(intermediateProcess.processId, intermediateProcess.handle);
}

handle_hijacking::ProcessWithHandle handle_hijacking::FindProcess(const char* targetProcess, uint32_t handleMinValue)
{
	handle_hijacking::ProcessWithHandle result{ 0, nullptr };

	// I use svchost as it opens handle for all um processes, as I know :/
	// To not open a handle to it, xd. Idk about better way to know process name :/
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
			&tempTargetHandle, NULL, FALSE, DUPLICATE_SAME_ACCESS)) // Note: avoid DuplicateHandle.
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

void IOCTLProcess::UnloadHelpLibrary()
{
	this->sharedMemory->flag = handle_hijacking::ioctlCodes::close;
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(sharedMemory->ioctlFuncAddress), nullptr, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

IOCTLProcess::IOCTLProcess(DWORD processId, HANDLE targetHandle)
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
		"Global\\MySharedMemory"); // Fix it. Should be random string. Allows several ioctl pipes :)

	if (!this->hMapFile) return;
	this->sharedMemory = reinterpret_cast<handle_hijacking::SharedMemory*>
		(MapViewOfFile(this->hMapFile, FILE_MAP_WRITE, 0, 0, sizeof(handle_hijacking::SharedMemory)));

	if (!this->sharedMemory) return;

	this->sharedMemory->targetHandle = targetHandle;

	// Inject dll with func which will help implement a data pipe.
	char fullPath[MAX_PATH];
	if (!GetFullPathNameA("IOCTLLibrary.dll", MAX_PATH, fullPath, nullptr)) return;
	const auto alloc = VirtualAllocEx(this->intermediateProcess, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc) return;
	if(!WriteProcessMemory(this->intermediateProcess, alloc, fullPath, MAX_PATH, nullptr)) return;
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), alloc, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

void IOCTLProcess::Write(void* address, uint8_t* buffer, size_t bufferSize)
{
	this->sharedMemory->flag = handle_hijacking::ioctlCodes::write;
	this->sharedMemory->bufSize = bufferSize;
	this->sharedMemory->address = address;
	memcpy(this->sharedMemory->buffer, buffer, bufferSize);
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(this->sharedMemory->ioctlFuncAddress), nullptr, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

void IOCTLProcess::Read(void* address, uint8_t* buffer, size_t bufferSize)
{
	this->sharedMemory->flag = handle_hijacking::ioctlCodes::read;
	this->sharedMemory->bufSize = bufferSize;
	this->sharedMemory->address = address;
	const auto thread = CreateRemoteThread(this->intermediateProcess, nullptr, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(this->sharedMemory->ioctlFuncAddress), (void*)0x23164850C14, NULL, nullptr);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	memcpy(buffer, this->sharedMemory->buffer, bufferSize);
}

IOCTLProcess::~IOCTLProcess()
{
	this->UnloadHelpLibrary();
	UnmapViewOfFile(this->sharedMemory);
	CloseHandle(this->hMapFile);
	CloseHandle(this->intermediateProcess);
}
