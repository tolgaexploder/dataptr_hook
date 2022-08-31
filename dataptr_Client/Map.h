#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include "Utils.h"
#include "RawDrv.h"
#include "loader.h"

NTSTATUS Map(const WCHAR* driver_name)
{
	//Make driver file
	std::ofstream driver;
	DeleteFileA("gdrv.sys");
	driver.open("gdrv.sys", std::ios::binary);
	driver.write((char*)&gdrvRaw, sizeof(gdrvRaw));
	driver.close();

	Sleep(1000);

	//Loading driver
	NTSTATUS status;
	const WCHAR* vulnName = L"gdrv.sys";

	status = WindLoadDriver((PWCHAR)vulnName, (PWCHAR)driver_name, FALSE);

	return status;
}

NTSTATUS UnMap(const WCHAR* driver_name)
{
	NTSTATUS status;

	status = WindUnloadDriver((PWCHAR)driver_name, FALSE);

	Sleep(100);

	DeleteFileA("gdrv.sys");

	return status;
}