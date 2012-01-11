//
//
//  @ Project : Untitled
//  @ File Name : SHA256.h
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#if !defined(_SHA256_H)
#define _SHA256_H

#include "IHash.h"

#define SHA256_BLOCK_SIZE (512 / 8)
#define SHA256_DIGEST_SIZE (256 / 8)

class SHA256 : public IHash
{
public:
    SHA256();
    virtual ~SHA256();
	void Init();
	void Update(unsigned char* p_Message, unsigned int p_Length);
	void Final(unsigned char* p_MessageDigest);
protected:
    void Transform(unsigned char* p_Message, unsigned int p_BlockNum);
private:
	unsigned int m_H[8];
	unsigned int m_H0[8];
    unsigned int m_K[64];
};

#endif  //_SHA256_H
