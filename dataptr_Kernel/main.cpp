#include "Comm.h"

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (!Comm::exit && Comm::init)
	{
		if (Comm::DismantleComm())
		{
			print("Comm Dismantle SUCCESS\n");
		}
		else
		{
			print("Comm Dismantle FAILED\n");
		}
		Comm::exit = true;
	}

	print("Driver Unload\n");

	return;
}

NTSTATUS DriverEntry(const PDRIVER_OBJECT pDriverObject, const PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	print("Driver Start\n");

	pDriverObject->DriverUnload = DriverUnload;

	if(Comm::SetupComm())
	{
		print("Comm Setup SUCCESS\n");
	}
	else
	{
		print("Comm Setup FAILED\n");
	}

	return STATUS_SUCCESS;
}