//
//
//  @ Project : Untitled
//  @ File Name : SHA256.cpp
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#include "SHA256.h"

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

SHA256::SHA256()
{
    m_Block = new unsigned char[SHA256_BLOCK_SIZE];
    // inisiasi H
    m_H0[0] = 0x6a09e667;m_H0[1] = 0xbb67ae85;m_H0[2] = 0x3c6ef372;m_H0[3] = 0xa54ff53a;
    m_H0[4] = 0x510e527f;m_H0[5] = 0x9b05688c;m_H0[6] = 0x1f83d9ab;m_H0[7] = 0x5be0cd19;
    
    // inisiasi K
    m_K[0] = 0x428a2f98;m_K[1] = 0x71374491;m_K[2] = 0xb5c0fbcf;m_K[3] = 0xe9b5dba5;
    m_K[4] = 0x3956c25b;m_K[5] = 0x59f111f1;m_K[6] = 0x923f82a4;m_K[7] = 0xab1c5ed5;
    m_K[8] = 0xd807aa98;m_K[9] = 0x12835b01;m_K[10] = 0x243185be;m_K[11] = 0x550c7dc3;
    m_K[12] = 0x72be5d74;m_K[13] = 0x80deb1fe;m_K[14] = 0x9bdc06a7;m_K[15] = 0xc19bf174;
    m_K[16] = 0xe49b69c1;m_K[17] = 0xefbe4786;m_K[18] = 0x0fc19dc6;m_K[19] = 0x240ca1cc;
    
    m_K[20] = 0x2de92c6f;m_K[21] = 0x4a7484aa;m_K[22] = 0x5cb0a9dc;m_K[23] = 0x76f988da;
    m_K[24] = 0x983e5152;m_K[25] = 0xa831c66d;m_K[26] = 0xb00327c8;m_K[27] = 0xbf597fc7;
    m_K[28] = 0xc6e00bf3;m_K[29] = 0xd5a79147;m_K[30] = 0x06ca6351;m_K[31] = 0x14292967;
    m_K[32] = 0x27b70a85;m_K[33] = 0x2e1b2138;m_K[34] = 0x4d2c6dfc;m_K[35] = 0x53380d13;
    m_K[36] = 0x650a7354;m_K[37] = 0x766a0abb;m_K[38] = 0x81c2c92e;m_K[39] = 0x92722c85;
    
    m_K[40] = 0xa2bfe8a1;m_K[41] = 0xa81a664b;m_K[42] = 0xc24b8b70;m_K[43] = 0xc76c51a3;
    m_K[44] = 0xd192e819;m_K[45] = 0xd6990624;m_K[46] = 0xf40e3585;m_K[47] = 0x106aa070;
    m_K[48] = 0x19a4c116;m_K[49] = 0x1e376c08;m_K[50] = 0x2748774c;m_K[51] = 0x34b0bcb5;
    m_K[52] = 0x391c0cb3;m_K[53] = 0x4ed8aa4a;m_K[54] = 0x5b9cca4f;m_K[55] = 0x682e6ff3;
    m_K[56] = 0x748f82ee;m_K[57] = 0x78a5636f;m_K[58] = 0x84c87814;m_K[59] = 0x8cc70208;
    
    m_K[60] = 0x90befffa;m_K[61] = 0xa4506ceb;m_K[62] = 0xbef9a3f7;m_K[63] = 0xc67178f2;
}

SHA256::~SHA256()
{
    delete m_Block;
}

void SHA256::Init()
{
    // inisiasi variabel H
    for (int i = 0; i < 8; i++)
    {
        m_H[i] = m_H0[i];
    }
    
    m_Length = 0;
    m_TotalLength = 0;
}

void SHA256::Update(unsigned char* p_Message, unsigned int p_Length)
{
    unsigned int t_RemLength = SHA256_BLOCK_SIZE - m_Length;
    memcpy(&m_Block[m_Length], p_Message, t_RemLength);
    
    if ((m_Length + p_Length) < SHA256_BLOCK_SIZE)
    {
        m_Length += p_Length;
        return;
    }
    
    unsigned int t_NewLength = p_Length - t_RemLength;
    unsigned int t_BlockNum = t_NewLength / SHA256_BLOCK_SIZE;
    
    unsigned char* t_ShiftedMsg = p_Message + t_RemLength;
    
    Transform(m_Block, 1);
    Transform(t_ShiftedMsg, t_BlockNum);
    
    t_RemLength = t_NewLength % SHA256_BLOCK_SIZE;
    
    memcpy(&m_Block, &t_ShiftedMsg[t_BlockNum << 6], t_RemLength);
    
    m_Length = t_RemLength;
    m_TotalLength += ((t_BlockNum + 1) << 6);
}

void SHA256::Final(unsigned char* p_MessageDigest)
{
    unsigned int t_BlockNum = (1 + ((SHA256_BLOCK_SIZE - 9) < (m_Length % SHA256_BLOCK_SIZE)));
    
    unsigned int t_LengthBlock = (m_TotalLength + m_Length) << 3;
    unsigned int t_PMLength = t_BlockNum << 6;
    
    memset((m_Block + m_Length), 0, (t_PMLength - m_Length));
    m_Block[m_Length] = 0x80;
    UNPACK32(t_LengthBlock, m_Block + t_PMLength - 4);
    
    Transform(m_Block, t_BlockNum);
    
    for (int i = 0; i < 8; i++)
    {
        UNPACK32(m_H[i], &p_MessageDigest[i << 2]);
    }
}

void SHA256::Transform(unsigned char* p_Message, unsigned int p_BlockNum)
{
    unsigned int t_W[64];
    unsigned int t_WV[8];
    unsigned char* t_SubBlock;

    for (unsigned int i = 1; i <= p_BlockNum; i++)
    {
        t_SubBlock = p_Message + ((i - 1) << 6);

        for (int j = 0; j < 16; j++)
        {
            PACK32(&t_SubBlock[j << 2], &t_W[j]);
        }

        for (int j = 16; j < 64; j++)
        {
            t_W[j] =  SHA256_F4(t_W[j - 2]) + t_W[j - 7] + SHA256_F3(t_W[j - 15]) + t_W[j - 16];	
        }

        for (int j = 0; j < 8; j++)
        {
            t_WV[j] = m_H[j];	
        }

        for (int j = 0; j < 64; j++)
        {
            unsigned int t_Temp1 = t_WV[7] + SHA256_F2(t_WV[4]) + CH(t_WV[4], t_WV[5], t_WV[6]) + m_K[j] + t_W[j];
            unsigned int t_Temp2 = SHA256_F1(t_WV[0]) + MAJ(t_WV[0], t_WV[1], t_WV[2]);
            t_WV[7] = t_WV[6];
            t_WV[6] = t_WV[5];
            t_WV[5] = t_WV[4];
            t_WV[4] = t_WV[3] + t_Temp1;
            t_WV[3] = t_WV[2];
            t_WV[2] = t_WV[1];
            t_WV[1] = t_WV[0];
            t_WV[0] = t_Temp1 + t_Temp2;
        }

        for (int j = 0; j < 8; j++)
        {
            m_H[j] += t_WV[j];
        }
    }
}
