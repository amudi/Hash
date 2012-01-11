//
//
//  @ Project : Untitled
//  @ File Name : StopWatch.cpp
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#include "StopWatch.h"

void StopWatch::Start()
{
    // cpu instructions
    #define rdtsc __asm __emit 0Fh __asm __emit 031h
    #define cpuid __asm __emit 0Fh __asm __emit 0A2h

    __int64 ts = 0; //working variable

    __asm push EAX
    __asm push EDX
    //cpuid  //other info
    rdtsc    //read time stamp register

    __asm mov dword ptr ts, EAX //low bits
    __asm and EDX, 07fffffffh //63 bit int, sign removed
    __asm mov dword ptr ts+4,EDX //high bits

    __asm pop EDX
    __asm pop EAX

    #undef rdtsc
    #undef cpuid
    jtimer[dx] = ts;
}
