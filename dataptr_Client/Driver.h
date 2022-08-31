#pragma once

#include <Windows.h>
#include <stdint.h>

#define EXIT_ID         0x4000
#define BASE_ID         0x4001
#define READ_ID         0x4002
#define WRITE_ID        0x4003
#define READSTR_ID      0x4004
#define WRITESTR_ID     0x4005
#define WRITETOREAD_ID  0x4006

#define FunctionToHook 129

typedef NTSTATUS(NTAPI* NtUserCallTwoParam)(uint64_t, uint64_t, uint32_t);

namespace Driver
{
	uint64_t MAGIC_COMM = 0xABCD1234;
	NtUserCallTwoParam func;

	typedef struct _COMM
	{
		uint32_t id;
		PVOID address;
		PVOID output;
		PVOID bufferAddress;
		uint64_t size;
		uint32_t pid;
		uint32_t pidOfSource;
		uint64_t baseAddress;
		const char* moduleName;
		uint32_t ret;
	}COMM;

	static uint32_t pid = 0;
	static uint64_t base = 0;

	bool Init()
	{
		const auto module = LoadLibrary("win32u.dll");
		
		func = reinterpret_cast<NtUserCallTwoParam>(GetProcAddress(module, "NtUserCallTwoParam"));

		if (!(uint64_t)func) return false;

		return true;
	}

	uint32_t CallHook(const PVOID arg)
	{
		func((uint64_t)arg, MAGIC_COMM, FunctionToHook);
		return static_cast<COMM*>(arg)->ret;
	}

	void Exit(uint64_t value)
	{
		COMM comm = { 0 };
		comm.id = EXIT_ID;
		comm.address = (PVOID)value;

		CallHook(&comm);
	}

	uint32_t GetProcId(const std::string& process_name)
	{
		PROCESSENTRY32 process_info;
		process_info.dwSize = sizeof(process_info);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		Process32First(snapshot, &process_info);
		if (!process_name.compare(process_info.szExeFile))
		{
			CloseHandle(snapshot);
			pid = (uint32_t)process_info.th32ProcessID;
			return pid;
		}

		while (Process32Next(snapshot, &process_info))
		{
			if (!process_name.compare(process_info.szExeFile))
			{
				CloseHandle(snapshot);
				pid = (uint32_t)process_info.th32ProcessID;
				return pid;
			}
		}

		CloseHandle(snapshot);
		return 0;
	}

	uint64_t GetModuleBaseAddress(const char* moduleName)
	{
		if (!pid) return 0x0;

		COMM comm = { 0 };
		comm.pid = pid;
		comm.id = BASE_ID;
		comm.moduleName = moduleName;
		CallHook(&comm);

		base = comm.baseAddress;
		return base;
	}

	template <typename T>
	T Read(uint64_t address)
	{
		T response{};

		COMM comm = { 0 };
		comm.id = READ_ID;
		comm.pid = pid;
		comm.pidOfSource = GetCurrentProcessId();
		comm.size = sizeof(T);
		comm.address = (PVOID)address;
		comm.bufferAddress = &response;
		CallHook(&comm);

		return response;
	}

	void WriteVirtualMemoryRaw(uint64_t WriteAddress, uint64_t SourceAddress, SIZE_T size);

	template<typename S>
	void Write(uint64_t address, const S& value)
	{
		WriteVirtualMemoryRaw(address, (uint64_t)&value, sizeof(S));
	}

	void WriteVirtualMemoryRaw(uint64_t WriteAddress, uint64_t SourceAddress, SIZE_T size)
	{
		COMM comm = { 0 };
		comm.id = WRITE_ID;
		comm.pid = pid;
		comm.address = (PVOID)WriteAddress;
		comm.bufferAddress = (PVOID)SourceAddress;
		comm.size = size;
		CallHook(&comm);
	}

	void ReadStr(uint64_t address, PVOID buffer, SIZE_T size)
	{
		COMM comm = { 0 };
		comm.id = READSTR_ID;
		comm.pid = pid;
		comm.address = (PVOID)address;
		comm.bufferAddress = buffer;
		comm.size = size;
		CallHook(&comm);
	}

	void WriteStr(uint64_t address, PVOID buffer, SIZE_T size)
	{
		COMM comm = { 0 };
		comm.id = WRITESTR_ID;
		comm.pid = pid;
		comm.address = (PVOID)address;
		comm.bufferAddress = buffer;
		comm.size = size;
		CallHook(&comm);
	}

	void WriteToRead(uint64_t address, const PVOID& value, SIZE_T size)
	{
		COMM comm = { 0 };
		comm.id = WRITETOREAD_ID;
		comm.pid = pid;
		comm.address = (PVOID)address;
		comm.bufferAddress = value;
		comm.size = size;
		CallHook(&comm);
	}
}