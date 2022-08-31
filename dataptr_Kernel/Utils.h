#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include "Imports.h"

namespace Utils
{
	void Sleep(LONG milliseconds)
	{
		LARGE_INTEGER interval;
		interval.QuadPart = -(10000ll * milliseconds);

		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	HANDLE CreateSystemThread(void Routine())
	{

		HANDLE buffer;

		PsCreateSystemThread(&buffer,
			THREAD_ALL_ACCESS,
			NULL, NULL, NULL,
			(PKSTART_ROUTINE)Routine,
			NULL);

		return buffer;
	}

	void SpoofThread(__KTHREAD* current_thread)
	{
		current_thread->SystemThread = 0;
	}
}