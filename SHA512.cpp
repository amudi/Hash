//
//
//  @ Project : Untitled
//  @ File Name : SHA512.cpp
//  @ Date : 12/7/2006
//  @ Author : 
//
//


#include "SHA512.h"

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x,  1) ^ ROTR(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x,  6))

SHA512::SHA512()
{
    m_Block = new unsigned char[SHA512_BLOCK_SIZE];
    // inisiasi H
    m_H0[0] = 0x6a09e667f3bcc908ULL;m_H0[1] = 0xbb67ae8584caa73bULL;
    m_H0[2] = 0x3c6ef372fe94f82bULL;m_H0[3] = 0xa54ff53a5f1d36f1ULL;
    m_H0[4] = 0x510e527fade682d1ULL;m_H0[5] = 0x9b05688c2b3e6c1fULL;
    m_H0[6] = 0x1f83d9abfb41bd6bULL;m_H0[7] = 0x5be0cd19137e2179ULL;
    
    // inisiasi K
    m_K[0] = 0x428a2f98d728ae22ULL;m_K[1] = 0x7137449123ef65cdULL;
    m_K[2] = 0xb5c0fbcfec4d3b2fULL;m_K[3] = 0xe9b5dba58189dbbcULL;
    m_K[4] = 0x3956c25bf348b538ULL;m_K[5] = 0x59f111f1b605d019ULL;
    m_K[6] = 0x923f82a4af194f9bULL;m_K[7] = 0xab1c5ed5da6d8118ULL;
    m_K[8] = 0xd807aa98a3030242ULL;m_K[9] = 0x12835b0145706fbeULL;
    m_K[10] = 0x243185be4ee4b28cULL;m_K[11] = 0x550c7dc3d5ffb4e2ULL;
    m_K[12] = 0x72be5d74f27b896fULL;m_K[13] = 0x80deb1fe3b1696b1ULL;
    m_K[14] = 0x9bdc06a725c71235ULL;m_K[15] = 0xc19bf174cf692694ULL;
    m_K[16] = 0xe49b69c19ef14ad2ULL;m_K[17] = 0xefbe4786384f25e3ULL;
    m_K[18] = 0x0fc19dc68b8cd5b5ULL;m_K[19] = 0x240ca1cc77ac9c65ULL;
    
    m_K[20] = 0x2de92c6f592b0275ULL;m_K[21] = 0x4a7484aa6ea6e483ULL;
    m_K[22] = 0x5cb0a9dcbd41fbd4ULL;m_K[23] = 0x76f988da831153b5ULL;
    m_K[24] = 0x983e5152ee66dfabULL;m_K[25] = 0xa831c66d2db43210ULL;
    m_K[26] = 0xb00327c898fb213fULL;m_K[27] = 0xbf597fc7beef0ee4ULL;
    m_K[28] = 0xc6e00bf33da88fc2ULL;m_K[29] = 0xd5a79147930aa725ULL;
    m_K[30] = 0x06ca6351e003826fULL;m_K[31] = 0x142929670a0e6e70ULL;
    m_K[32] = 0x27b70a8546d22ffcULL;m_K[33] = 0x2e1b21385c26c926ULL;
    m_K[34] = 0x4d2c6dfc5ac42aedULL;m_K[35] = 0x53380d139d95b3dfULL;
    m_K[36] = 0x650a73548baf63deULL;m_K[37] = 0x766a0abb3c77b2a8ULL;
    m_K[38] = 0x81c2c92e47edaee6ULL;m_K[39] = 0x92722c851482353bULL;
    
    m_K[40] = 0xa2bfe8a14cf10364ULL;m_K[41] = 0xa81a664bbc423001ULL;
    m_K[42] = 0xc24b8b70d0f89791ULL;m_K[43] = 0xc76c51a30654be30ULL;
    m_K[44] = 0xd192e819d6ef5218ULL;m_K[45] = 0xd69906245565a910ULL;
    m_K[46] = 0xf40e35855771202aULL;m_K[47] = 0x106aa07032bbd1b8ULL;
    m_K[48] = 0x19a4c116b8d2d0c8ULL;m_K[49] = 0x1e376c085141ab53ULL;
    m_K[50] = 0x2748774cdf8eeb99ULL;m_K[51] = 0x34b0bcb5e19b48a8ULL;
    m_K[52] = 0x391c0cb3c5c95a63ULL;m_K[53] = 0x4ed8aa4ae3418acbULL;
    m_K[54] = 0x5b9cca4f7763e373ULL;m_K[55] = 0x682e6ff3d6b2b8a3ULL;
    m_K[56] = 0x748f82ee5defb2fcULL;m_K[57] = 0x78a5636f43172f60ULL;
    m_K[58] = 0x84c87814a1f0ab72ULL;m_K[59] = 0x8cc702081a6439ecULL;

    m_K[60] = 0x90befffa23631e28ULL;m_K[61] = 0xa4506cebde82bde9ULL;
    m_K[62] = 0xbef9a3f7b2c67915ULL;m_K[63] = 0xc67178f2e372532bULL;
    m_K[64] = 0xca273eceea26619cULL;m_K[65] = 0xd186b8c721c0c207ULL;
    m_K[66] = 0xeada7dd6cde0eb1eULL;m_K[67] = 0xf57d4f7fee6ed178ULL;
    m_K[68] = 0x06f067aa72176fbaULL;m_K[69] = 0x0a637dc5a2c898a6ULL;
    m_K[70] = 0x113f9804bef90daeULL;m_K[71] = 0x1b710b35131c471bULL;
    m_K[72] = 0x28db77f523047d84ULL;m_K[73] = 0x32caab7b40c72493ULL;
    m_K[74] = 0x3c9ebe0a15c9bebcULL;m_K[75] = 0x431d67c49c100d4cULL;
    m_K[76] = 0x4cc5d4becb3e42b6ULL;m_K[77] = 0x597f299cfc657e2aULL;
    m_K[78] = 0x5fcb6fab3ad6faecULL;m_K[79] = 0x6c44198c4a475817ULL;
}

SHA512::~SHA512()
{
    delete m_Block;
}

void SHA512::Init()
{
    // inisiasi variabel H
    for (int i = 0; i < 8; i++)
    {
        m_H[i] = m_H0[i];
    }
    
    m_Length = 0;
    m_TotalLength = 0;
}

void SHA512::Update(unsigned char* p_Message, unsigned int p_Length)
{
    unsigned int t_RemLength = SHA512_BLOCK_SIZE - m_Length;
    memcpy(&m_Block[m_Length], p_Message, t_RemLength);
    
    if ((m_Length + p_Length) < SHA512_BLOCK_SIZE)
    {
        m_Length += p_Length;
        return;
    }
    
    unsigned int t_NewLength = p_Length - t_RemLength;
    unsigned int t_BlockNum = t_NewLength / SHA512_BLOCK_SIZE;
    
    unsigned char* t_ShiftedMsg = p_Message + t_RemLength;
    
    Transform(m_Block, 1);
    Transform(t_ShiftedMsg, t_BlockNum);
    
    t_RemLength = t_NewLength % SHA512_BLOCK_SIZE;
    
    memcpy(&m_Block, &t_ShiftedMsg[t_BlockNum << 7], t_RemLength);
    
    m_Length = t_RemLength;
    m_TotalLength += ((t_BlockNum + 1) << 7);
}

void SHA512::Final(unsigned char* p_MessageDigest)
{
    unsigned int t_BlockNum = (1 + ((SHA512_BLOCK_SIZE - 17) < (m_Length % SHA512_BLOCK_SIZE)));
    
    unsigned int t_LengthBlock = (m_TotalLength + m_Length) << 3;
    unsigned int t_PMLength = t_BlockNum << 7;
    
    memset((m_Block + m_Length), 0, (t_PMLength - m_Length));
    m_Block[m_Length] = 0x80;
    UNPACK32(t_LengthBlock, m_Block + t_PMLength - 4);
    
    Transform(m_Block, t_BlockNum);
    
    for (int i = 0; i < 8; i++)
    {
        UNPACK64(m_H[i], &p_MessageDigest[i << 3]);
    }
}

void SHA512::Transform(unsigned char* p_Message, unsigned int p_BlockNum)
{
    unsigned long long t_W[80];
    unsigned long long t_WV[8];
    unsigned char* t_SubBlock;
    
    for (unsigned int i = 1; i <= p_BlockNum; i++)
    {
        t_SubBlock = p_Message + ((i - 1) << 7);
        
        for (int j = 0; j < 16; j++)
        {
            PACK64(&t_SubBlock[j << 3], &t_W[j]);
        }
        
        for (int j = 16; j < 80; j++)
        {
            t_W[j] =  SHA512_F4(t_W[j - 2]) + t_W[j - 7] + SHA512_F3(t_W[j - 15]) + t_W[j - 16]; 
        }
        
        for (int j = 0; j < 8; j++)
        {
            t_WV[j] = m_H[j];
        }
        
        for (int j = 0; j < 80; j++)
        {
            unsigned long long t_Temp1 = t_WV[7] + SHA512_F2(t_WV[4]) + CH(t_WV[4], t_WV[5], t_WV[6]) + m_K[j] + t_W[j];
            unsigned long long t_Temp2 = SHA512_F1(t_WV[0]) + MAJ(t_WV[0], t_WV[1], t_WV[2]);
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
