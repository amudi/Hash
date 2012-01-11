//
//
//  @ Project : Untitled
//  @ File Name : SHA512.h
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#if !defined(_SHA512_H)
#define _SHA512_H

#include "IHash.h"

#define SHA512_BLOCK_SIZE (1024 / 8)
#define SHA512_DIGEST_SIZE (512 / 8)

class SHA512 : public IHash
{
public:
    SHA512();
    virtual ~SHA512();
	void Init();
	void Update(unsigned char* p_Message, unsigned int p_Length);
	void Final(unsigned char* p_MessageDigest);
protected:
    void Transform(unsigned char* p_Message, unsigned int p_BlockNum);
private:
	unsigned long long m_H[8];
	unsigned long long m_H0[8];
    unsigned long long m_K[80];
};

#endif  //_SHA512_H
