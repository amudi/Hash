//
//
//  @ Project : Untitled
//  @ File Name : IHash.h
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#if !defined(_IHASH_H)
#define _IHASH_H

#include <string.h>

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

// makro konversi tipe data
#define UNPACK32(x, str)                       \
{                                              \
    *((str) + 3) = (unsigned char) ((x)      );      \
    *((str) + 2) = (unsigned char) ((x) >>  8);      \
    *((str) + 1) = (unsigned char) ((x) >> 16);      \
    *((str) + 0) = (unsigned char) ((x) >> 24);      \
}

#define PACK32(str, x)                         \
{                                              \
    *(x) = ((unsigned int) *((str) + 3)      )     \
         | ((unsigned int) *((str) + 2) <<  8)     \
         | ((unsigned int) *((str) + 1) << 16)     \
         | ((unsigned int) *((str) + 0) << 24);    \
}

#define UNPACK64(x, str)                       \
{                                              \
    *((str) + 7) = (unsigned char) ((x)      );      \
    *((str) + 6) = (unsigned char) ((x) >>  8);      \
    *((str) + 5) = (unsigned char) ((x) >> 16);      \
    *((str) + 4) = (unsigned char) ((x) >> 24);      \
    *((str) + 3) = (unsigned char) ((x) >> 32);      \
    *((str) + 2) = (unsigned char) ((x) >> 40);      \
    *((str) + 1) = (unsigned char) ((x) >> 48);      \
    *((str) + 0) = (unsigned char) ((x) >> 56);      \
}

#define PACK64(str, x)                         \
{                                              \
    *(x) = ((unsigned long long) *((str) + 7)      )     \
         | ((unsigned long long) *((str) + 6) <<  8)     \
         | ((unsigned long long) *((str) + 5) << 16)     \
         | ((unsigned long long) *((str) + 4) << 24)     \
         | ((unsigned long long) *((str) + 3) << 32)     \
         | ((unsigned long long) *((str) + 2) << 40)     \
         | ((unsigned long long) *((str) + 1) << 48)     \
         | ((unsigned long long) *((str) + 0) << 56);    \
}


class IHash
{
public:
	virtual void Init() = 0;
	virtual void Update(unsigned char* p_Message, unsigned int p_Length) = 0;
	virtual void Final(unsigned char* p_MessageDigest) = 0;
protected:
    virtual void Transform(unsigned char* p_Message, unsigned int p_BlockNum) = 0;
    unsigned char* m_Block;
	unsigned int m_TotalLength;
	unsigned char m_Length;
};

#endif  //_IHASH_H
