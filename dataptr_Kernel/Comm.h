#pragma once
#include "Imports.h"
#include "Utils.h"
#include "Memory.h"

#define EXIT_ID         0x4000
#define BASE_ID         0x4001
#define READ_ID         0x4002
#define WRITE_ID        0x4003
#define READSTR_ID      0x4004
#define WRITESTR_ID     0x4005
#define WRITETOREAD_ID  0x4006

#define FunctionToHook 129

#define ResolveRelativeAddress(a,b,c)[&]() { \
INT_PTR Instr = (INT_PTR)a;\
INT RipOffset = *(PULONG)(Instr + b);\
PVOID ResolvedAddr = (PVOID)(Instr + c + RipOffset);\
return ResolvedAddr;\
}()

namespace Comm
{
	uint64_t origFuncPtr;
	bool exit = false;
	bool init = false;
	uint64_t MAGIC_COMM = 0xABCD1234;

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

	uint64_t FindFunctionPtr()
	{
		uint64_t moduleStart;
		size_t moduleSize;

		if (!NT_SUCCESS(Memory::FindKernelModuleByName("win32kfull.sys", &moduleStart, &moduleSize)))
		{
			print("FindKernelModuleByName: FAILED\n");

			return 0;
		}

		uint64_t NtUserCallTwoParam = 0;
		if (!NT_SUCCESS(Memory::FindModuleExportByName(moduleStart, "NtUserCallTwoParam", &NtUserCallTwoParam)))
		{
			print("NtUserCallTwoParam: FAILED\n");

			return 0;
		}

		print("NtUserCallTwoParam: 0x%llX\n", NtUserCallTwoParam);

		uint64_t funcPtr = Memory::GhettoScan((uint8_t*)NtUserCallTwoParam, 0x100, "\x48\x8D\x0D\x01\x01\x01\x01\x48\x8B\xD7", "xxx????xxx");

		if (!funcPtr)
		{
			print("FuncPtr: FAILED\n");

			return 0;
		}

		print("FunctionPtr: 0x%llX\n", funcPtr);

		return funcPtr;
	}

	bool DismantleComm()
	{
		PEPROCESS process = (PEPROCESS)Memory::FindProcessByName("explorer.exe");
		KAPC_STATE apc;
		KeStackAttachProcess(process, &apc);


		uint64_t instrAddr = (uint64_t)FindFunctionPtr();

		instrAddr += 0x3;
		uint64_t funcAddr = instrAddr + *reinterpret_cast<int32_t*>(instrAddr) + sizeof(int32_t);

		const auto mdl = IoAllocateMdl(reinterpret_cast<PVOID>(funcAddr + FunctionToHook * 8), sizeof(PVOID), false, false, nullptr);

		if (!mdl)
		{
			KeUnstackDetachProcess(&apc);
			return FALSE;
		}

		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		const auto mapped = reinterpret_cast<uint64_t*>(MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, false, HighPagePriority));

		if (!mapped)
		{
			KeUnstackDetachProcess(&apc);
			return FALSE;
		}

		uint64_t old = *mapped;
		*mapped = origFuncPtr;

		print("Function changed from %llX to %llX\n", old, *mapped);

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		KeUnstackDetachProcess(&apc);

		init = false;

		return TRUE;
	}

	NTSTATUS Handler(uint64_t a1, uint64_t a2)
	{
		UNREFERENCED_PARAMETER(a1);
		UNREFERENCED_PARAMETER(a2);
		print("Called Hook: 0x%llX, 0x%llX\n", a1, a2);

		if (a2 == MAGIC_COMM)
		{
			const auto data = reinterpret_cast<COMM*>(a1);

			switch (data->id)
			{
			case EXIT_ID:
			{
				print("Exit\n");
				if (DismantleComm())
				{
					print("Comm Dismantle SUCCESS\n");
					exit = true;
				}
				else
				{
					print("Comm Dismantle FAILED\n");
				}

				break;
			}

			case BASE_ID:
			{

				print("Base\n");
				ANSI_STRING AS;
				UNICODE_STRING ModuleName;
				uint64_t baseAddress;
				KAPC_STATE apcState;

				RtlInitAnsiString(&AS, data->moduleName);
				RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

				PEPROCESS process;
				PsLookupProcessByProcessId((HANDLE)data->pid, &process);
				BOOLEAN isWow64;
				isWow64 = (PsGetProcessWow64Process(process) != NULL) ? TRUE : FALSE;

				KeStackAttachProcess(process, &apcState);
				baseAddress = Memory::GetUserModule(process, &ModuleName, isWow64);
				KeUnstackDetachProcess(&apcState);
				data->baseAddress = baseAddress;
				RtlFreeUnicodeString(&ModuleName);
				break;
			}

			case READ_ID:
			{
				print("Read\n");
				Memory::ReadKernelMemory((HANDLE)data->pidOfSource, (HANDLE)data->pid, data->address, data->bufferAddress, data->size);
				break;
			}

			case WRITE_ID:
			{
				print("Write\n");
				PVOID buffer1;
				buffer1 = ExAllocatePool(NonPagedPool, data->size);

				if (!buffer1)
					return 0x0;

				if (!memcpy(buffer1, data->bufferAddress, data->size))
					return 0x0;

				Memory::WriteKernelMemory((HANDLE)data->pid, data->address, buffer1, data->size);
				ExFreePool(buffer1);
				break;
			}

			case READSTR_ID:
			{
				print("ReadStr\n");
				PVOID buffer2;
				buffer2 = ExAllocatePool(NonPagedPool, data->size);

				if (!buffer2)
					return 0x0;


				if (!memcpy(buffer2, data->bufferAddress, data->size))
					return 0x0;

				Memory::ReadKernelMemory((HANDLE)data->pid, (HANDLE)IoGetCurrentProcess, data->address, buffer2, data->size);

				RtlZeroMemory(data->bufferAddress, data->size);

				if (!memcpy(data->bufferAddress, buffer2, data->size))
					return 0x0;

				ExFreePool(buffer2);
				break;
			}

			case WRITESTR_ID:
			{
				print("WriteStr\n");
				PVOID buffer3;
				buffer3 = ExAllocatePool(NonPagedPool, data->size);

				if (!buffer3)
					return 0x0;

				if (!memcpy(buffer3, data->bufferAddress, data->size))
					return 0x0;

				Memory::WriteKernelMemory((HANDLE)data->pid, data->address, buffer3, data->size);

				ExFreePool(buffer3);
				break;
			}

			case WRITETOREAD_ID:
			{
				print("WriteToRead\n");
				PVOID buffer4;
				buffer4 = ExAllocatePool(NonPagedPool, data->size);

				if (!buffer4)
					return 0x0;

				if (!memcpy(buffer4, data->bufferAddress, data->size))
					return 0x0;

				Memory::WriteToReadOnly((HANDLE)data->pid, data->address, buffer4, data->size);
				ExFreePool(buffer4);
				break;
			}
			}

			return 0x0;
		}

		return reinterpret_cast<NTSTATUS(*)(uint64_t, uint64_t)>(origFuncPtr)(a1, a2);
	}

	bool SetupComm()//
	{
		PEPROCESS process = (PEPROCESS)Memory::FindProcessByName("explorer.exe");
		KAPC_STATE apc;
		KeStackAttachProcess(process, &apc);

		uint64_t instrAddr = (uint64_t)FindFunctionPtr();

		instrAddr += 0x3;
		uint64_t funcAddr = instrAddr + *reinterpret_cast<int32_t*>(instrAddr + sizeof(int32_t));
		const auto mdl = IoAllocateMdl(reinterpret_cast<PVOID>(funcAddr + FunctionToHook * 8), sizeof(PVOID), false, false, nullptr);

		if (!mdl)
		{
			KeUnstackDetachProcess(&apc);
			return false;
		}
		// lock allocated pages
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		const auto mapped = reinterpret_cast<uint64_t*>(MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, false, HighPagePriority));

		if (!mapped)
		{
			KeUnstackDetachProcess(&apc);
			return FALSE;
		}

		origFuncPtr = *mapped;
		*mapped = (uint64_t)Handler;

		print("Function changed from %llX to %llX\n", origFuncPtr, *mapped);

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		KeUnstackDetachProcess(&apc);

		init = true;

		return true;
	}
}