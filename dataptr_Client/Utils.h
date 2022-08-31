#pragma once

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <locale>
#include <codecvt>
#include "Driver.h"


namespace Utils
{
    void WaitForKeypress(int vKey)
    {
        while (true)
        {
            if (GetAsyncKeyState(vKey) & 1)
                break;
        }
    }

    void Backspace(int iterations)
    {
        for (int i = 0; i < iterations; i++)
        {
            std::cout << "\b \b";
        }
    }

    inline std::ostream& Red(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout,
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& Green(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout,
            FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& Blue(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE
            | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& Yellow(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout,
            FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& Purple(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout,
            FOREGROUND_RED | FOREGROUND_BLUE);
        return s;
    }

    inline std::ostream& White(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return s;
    }

    struct Color
    {
        Color(WORD attribute) :m_color(attribute) {};
        WORD m_color;
    };
}