//
//
//  @ Project : Untitled
//  @ File Name : SHA1.h
//  @ Date : 12/20/2006
//  @ Author : 
//
//

#if !defined(_SHA1_H)
#define _SHA1_H

#define SHA1_BLOCK_SIZE (512 / 8)
#define SHA1_DIGEST_SIZE (160 / 32)

using namespace std;

class SHA1
{
public:
	SHA1();
	virtual ~SHA1();
	void Reset();
	bool Result(unsigned* p_MessageDigestArray);
	void Input(const unsigned char* p_MessageArray, unsigned p_Length);

private:
	void ProcessMessageBlock();
	void PadMessage();
	inline unsigned CircularShift(int p_Bits, unsigned p_Word);

	unsigned* m_H;						/// message digest buffer
	unsigned m_LengthLow;				/// message length dalam bits (32 bit pertama / low bits)
	unsigned m_LengthHigh;				/// message length dalam bits (32 bit terakhir / high bits)

	unsigned char* m_MessageBlock;		/// 512 bit block message
	int m_MessageBlockIndex;			/// index message block array

	bool m_Computed;					/// apakah digest telah dihitung?
	bool m_Corrupted;					/// apakah digest corrupt?

public:
};

#endif  //_SHA1_H
