#include <Windows.h>
#include <iostream>
#include "Utils.h"
#include "Map.h"
#include "Driver.h"

int main()
{
    SetConsoleTitle("ExClient");

    if(!Driver::Init()) // Initialize driver communication
    {
        std::cout << Utils::Red << "[+] Failed to initialize comm\n";
        std::cout << " [-] Press SPACE to exit...\n";
        Utils::WaitForKeypress(VK_SPACE);
        return 2;
    }

    std::cout << Utils::White << "[" << Utils::Blue << "+" << Utils::White << "]" << " Driver communication initialized\n";

    Driver::GetProcId("notepad.exe"); // Example of getting process id
    if (!Driver::pid)
    {
        std::cout << Utils::Red << "[+] Failed to find pid\n";
        std::cout << " [-] Press SPACE to exit...\n";
        Utils::WaitForKeypress(VK_SPACE);
        return 3;
    }

    Driver::GetModuleBaseAddress("notepad.exe"); // Example of getting module base
    if (!Driver::base)
    {
        std::cout << Utils::Red << "[+] Failed to find base\n";
        std::cout << " [-] Press SPACE to exit...\n";
        Utils::WaitForKeypress(VK_SPACE);
        return 4;
    }

    uint16_t mz = Driver::Read<uint16_t>(Driver::base); // Example of reading memory

    std::cout << Utils::White << "[" << Utils::Blue << "+" << Utils::White << "]" << Utils::Blue << " Notepad.exe" << Utils::White << " found. ["
        << Utils::Blue << Driver::pid << Utils::White << "][" << Utils::Blue << "0x" << std::hex << Driver::base << std::dec << Utils::White << "]\n";

    std::cout << Utils::White << "[" << Utils::Blue << "+" << Utils::White << "] Press" << Utils::Blue << " END " << Utils::White << "to exit...\n";
    Utils::WaitForKeypress(VK_END);

    Driver::Exit(0x1337); // Dismantle comm

    std::cout << Utils::White << "[" << Utils::Blue << "+" << Utils::White << "] Driver unmapped\n";

    Sleep(1000);

    return 1;
}
