#pragma once

#include <ntstrsafe.h>
#include "Imports.h"

namespace Memory
{
	PVOID g_KernelBase = NULL;
	ULONG g_KernelSize = 0;

	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

		return ResolvedAddr;
	}

	uint64_t Dereference(uint64_t address, unsigned int offset)
	{
		if (address == 0)
			return 0;

		return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
	}

	PVOID GetKernelBase(OUT PULONG pSize)
	{
		NTSTATUS status = STATUS_SUCCESS;
		ULONG bytes = 0;
		PRTL_PROCESS_MODULES pMods = NULL;
		PVOID checkPtr = NULL;
		UNICODE_STRING routineName;

		// Already found
		if (g_KernelBase != NULL)
		{
			if (pSize)
				*pSize = g_KernelSize;
			return g_KernelBase;
		}

		RtlUnicodeStringInit(&routineName, L"NtOpenFile");

		checkPtr = MmGetSystemRoutineAddress(&routineName);
		if (checkPtr == NULL)
			return NULL;


		status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

		if (bytes == 0)
			return NULL;

		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'
		RtlZeroMemory(pMods, bytes);

		status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

		if (NT_SUCCESS(status))
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				// System routine is inside module
				if (checkPtr >= pMod[i].ImageBase &&
					checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
				{
					g_KernelBase = pMod[i].ImageBase;
					g_KernelSize = pMod[i].ImageSize;
					if (pSize)
						*pSize = g_KernelSize;
					break;
				}
			}
		}

		if (pMods)
			ExFreePoolWithTag(pMods, 0x454E4F45); // 'ENON'

		return g_KernelBase;
	}

	uint64_t GhettoScan(uint8_t* base, const size_t size, char* pattern, char* mask)
	{
		const auto patternSize = strlen(mask);

		for (size_t i = {}; i < size - patternSize; i++)
		{
			for (size_t j = {}; j < patternSize; j++)
			{
				if (mask[j] != '?' && *reinterpret_cast<uint8_t*>(base + i + j) != static_cast<uint8_t>(pattern[j]))
					break;

				if (j == patternSize - 1)
					return reinterpret_cast<uint64_t>(base) + i;
			}
		}

		return {};
	}

	NTSTATUS PatternScan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
	{
		ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
		if (ppFound == NULL || pattern == NULL || base == NULL)
			return STATUS_INVALID_PARAMETER;

		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	NTSTATUS ScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN bool relative, OUT PVOID* ppFound)
	{
		ASSERT(ppFound != NULL);
		if (ppFound == NULL)
			return STATUS_INVALID_PARAMETER;

		PVOID base = GetKernelBase(NULL);
		if (!base)
			return STATUS_NOT_FOUND;


		PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
		if (!pHdr)
			return STATUS_INVALID_IMAGE_FORMAT;

		PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
		for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
		{
			ANSI_STRING s1, s2;
			RtlInitAnsiString(&s1, section);
			RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
			if (RtlCompareString(&s1, &s2, TRUE) == 0)
			{
				PVOID ptr = NULL;
				NTSTATUS status = PatternScan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
				if (NT_SUCCESS(status))
				{
					if (relative)
						*(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
					else
						*(PULONGLONG)ppFound = (ULONGLONG)ptr;
				}

				return status;
			}
		}

		return STATUS_NOT_FOUND;
	}

	uint64_t GetUserModule(IN PEPROCESS pProcess, IN UNICODE_STRING* ModuleName, IN BOOLEAN isWow64)
	{
		ASSERT(pProcess != NULL);
		if (pProcess == NULL)
		{
			return NULL;
		}

		// Protect from UserMode AV
		__try
		{
			LARGE_INTEGER time = { 0 };
			time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

			// Wow64 process
			if (isWow64)
			{
				PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
				if (pPeb32 == NULL)
				{
					return NULL;
				}

				// Wait for loader a bit
				for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
				{
					KeDelayExecutionThread(KernelMode, TRUE, &time);
				}

				// Still no loader
				if (!pPeb32->Ldr)
				{
					return NULL;
				}

				// Search in InLoadOrderModuleList
				for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
					pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
					pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
				{
					UNICODE_STRING ustr;
					PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

					RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					{
						return (uint64_t)pEntry->DllBase;
					}
				}
			}
			// Native process
			else
			{
				PPEB pPeb = PsGetProcessPeb(pProcess);
				if (!pPeb)
				{
					return NULL;
				}


				for (INT i = 0; !pPeb->Ldr && i < 10; i++)
				{
					KeDelayExecutionThread(KernelMode, TRUE, &time);
				}

				if (!pPeb->Ldr)
				{
					return NULL;
				}

				// Search in InLoadOrderModuleList
				for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
					pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
					pListEntry = pListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					{
						return (uint64_t)pEntry->DllBase;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		return NULL;
	}

	bool ReadKernelMemory(HANDLE srcPid, HANDLE tgtPid, PVOID address, PVOID buffer, SIZE_T size)
	{
		if (!address || !buffer || !size)
			return false;
		SIZE_T bytes = 0;
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS srcProcess;
		PsLookupProcessByProcessId((HANDLE)srcPid, &srcProcess);
		PEPROCESS tgtProcess;
		PsLookupProcessByProcessId((HANDLE)tgtPid, &tgtProcess);

		status = MmCopyVirtualMemory(tgtProcess, address, srcProcess, buffer, size, KernelMode, &bytes);
		if (!NT_SUCCESS(status))
			return false;
		else
			return true;
	}

	bool WriteKernelMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size)
	{
		if (!address || !buffer || !size)
			return false;

		NTSTATUS Status = STATUS_SUCCESS;
		PEPROCESS process;
		PsLookupProcessByProcessId(pid, &process);

		KAPC_STATE state;
		KeStackAttachProcess((PKPROCESS)process, &state);

		MEMORY_BASIC_INFORMATION info;

		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), address, MemoryBasicInformation, &info, sizeof(info), NULL);
		if (!NT_SUCCESS(Status))
		{
			KeUnstackDetachProcess(&state);
			return false;
		}

		if (((uint64_t)info.BaseAddress + info.RegionSize) < ((uint64_t)address + size))
		{
			KeUnstackDetachProcess(&state);
			return false;
		}

		if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
		{
			KeUnstackDetachProcess(&state);
			return false;
		}

		if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) || (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
		{
			RtlCopyMemory((PVOID)address, buffer, size);
		}

		KeUnstackDetachProcess(&state);
		return true;
	}

	void WriteToReadOnly(HANDLE pid, PVOID address, PVOID value, SIZE_T size)
	{
		if (!address || !value || !size)
			return;

		KAPC_STATE apc;
		PEPROCESS process;
		PsLookupProcessByProcessId(pid, &process);
		KeStackAttachProcess(process, &apc);
		PVOID mapped = 0;
		PMDL mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);

		if (!mdl)
			return;

		__try
		{
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
			mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);

			if (!mapped)
			{
				KeUnstackDetachProcess(&apc);
				return;
			}

			auto status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&apc);
				return;
			}

			if (!RtlCopyMemory(mapped, value, size))
			{
				KeUnstackDetachProcess(&apc);
				return;
			}

			MmUnmapLockedPages(mapped, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);

			KeUnstackDetachProcess(&apc);
			return;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KeUnstackDetachProcess(&apc);
			MmUnmapLockedPages(mapped, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return;
		}
	}

	HANDLE GetProcHandle(UNICODE_STRING name)
	{
		NTSTATUS status = STATUS_SUCCESS;
		PVOID buffer;


		buffer = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, 'enoN');

		if (!buffer)
		{
			return 0;
		}

		PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)buffer;

		status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(buffer, 'enoN');
			return 0;
		}

		if (NT_SUCCESS(status))
		{
			for (;;)
			{
				if (RtlEqualUnicodeString(&pInfo->ImageName, &name, TRUE))
				{
					ExFreePoolWithTag(buffer, 'enoN');
					return pInfo->ProcessId;
				}
				else if (pInfo->NextEntryOffset)
					pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
				else
					break;
			}
		}

		ExFreePoolWithTag(buffer, 'enoN');
		return 0;
	}

	NTSTATUS FindKernelModuleByName(const char* moduleName, uint64_t* moduleStart, size_t* moduleSize)
	{
		size_t size{};

		ZwQuerySystemInformation(SystemModuleInformation, nullptr, (ULONG)size, reinterpret_cast<PULONG>(&size));

		const auto listHeader = ExAllocatePool(NonPagedPool, size);
		if (!listHeader)
			return STATUS_MEMORY_NOT_ALLOCATED;

		if (const auto status = ZwQuerySystemInformation(SystemModuleInformation, listHeader, (ULONG)size, reinterpret_cast<PULONG>(&size)))
			return status;

		auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Modules;
		for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->ulModuleCount; ++i, ++currentModule)
		{
			const auto currentModuleName = reinterpret_cast<const char*>(currentModule->ImageName + currentModule->ModuleNameOffset);
			if (!strcmp(moduleName, currentModuleName))
			{
				*moduleStart = reinterpret_cast<uint64_t>(currentModule->Base);
				*moduleSize = currentModule->Size;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	uint64_t FindProcessByName(const char* process_name)
	{
		auto currentEntry = reinterpret_cast<uint64_t>(PsInitialSystemProcess);

		do
		{
			if (strstr(reinterpret_cast<char*>(currentEntry) + 0x5a8, process_name))
			{
				const auto activeThreads = *reinterpret_cast<uint32_t*>(currentEntry + 0x5f0);
				if (activeThreads > 0)
				{
					return currentEntry;
				}
			}

			const auto list = reinterpret_cast<PLIST_ENTRY>(currentEntry + 0x448);
			currentEntry = reinterpret_cast<uint64_t>(list->Flink);
			currentEntry = currentEntry - 0x448;

		} while (currentEntry != reinterpret_cast<uint64_t>(PsInitialSystemProcess));

		return NULL;
	}

	NTSTATUS FindModuleExportByName(const uint64_t imageBase, const char* exportName, uint64_t* functionPointer)
	{
		if (!imageBase)
			return STATUS_INVALID_PARAMETER_1;

		if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
			return STATUS_INVALID_IMAGE_NOT_MZ;

		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
		const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
		if (!exportDirectory)
			STATUS_INVALID_IMAGE_FORMAT;

		const auto exportedFunctions = reinterpret_cast<uint32_t*>(imageBase + exportDirectory->AddressOfFunctions);
		const auto exportedNames = reinterpret_cast<uint32_t*>(imageBase + exportDirectory->AddressOfNames);
		const auto exportedNameOrdinals = reinterpret_cast<uint16_t*>(imageBase + exportDirectory->AddressOfNameOrdinals);

		for (size_t i{}; i < exportDirectory->NumberOfNames; ++i)
		{
			const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
			if (!strcmp(exportName, functionName))
			{
				*functionPointer = imageBase + exportedFunctions[exportedNameOrdinals[i]];
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}
}