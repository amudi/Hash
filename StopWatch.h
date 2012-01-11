//
//
//  @ Project : Untitled
//  @ File Name : StopWatch.h
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#if !defined(_STOPWATCH_H)
#define _STOPWATCH_H

#define mhz 1000000 //one million hertz
#define machine_speed 1866*mhz //your speed here!!
#define __int64 unsigned long long

class StopWatch
{
private:
    __int64 jtimer[5]; 
    
public:
    inline void Start();
    inline void Stop();
    inline void Reset();
    inline void GetCurrentValue();    
};

#endif  //_STOPWATCH_H
