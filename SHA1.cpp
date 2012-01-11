
#include <string>
#include <iostream>
#include "SHA1.h"

using namespace std;


SHA1::SHA1()
{
	m_H = new unsigned[5];
	m_MessageBlock = new unsigned char[64];
	Reset();
}

SHA1::~SHA1()
{
	// do nothing
	delete m_H;
	delete m_MessageBlock;
}

void SHA1::Reset()
{
	// set length message
	m_LengthLow = 0;
	m_LengthHigh = 0;
	m_MessageBlockIndex = 0;

	// inisiasi 
	m_H[0]		= 0x67452301;
	m_H[1]		= 0xEFCDAB89;
	m_H[2]		= 0x98BADCFE;
	m_H[3]		= 0x10325476;
	m_H[4]		= 0xC3D2E1F0;

	// reset state
	m_Computed = false;
	m_Corrupted = false;
}

bool SHA1::Result(unsigned* p_MessageDigestArray)
{
	if (m_Corrupted)	// corrupted, tidak bisa mengambil result
		return false;

	if (!m_Computed) {	// tambahkan padding dan kalkulasi jika belum
		PadMessage();
		m_Computed = true;
	}

	// output hasil
	for (int i = 0; i < 5; i++)
		p_MessageDigestArray[i] = m_H[i];
	
	return true;
}

void SHA1::Input(const unsigned char* p_MessageArray, unsigned p_Length)
{
	if (!p_Length)
		return;

	if (m_Computed || m_Corrupted) {	// jika corrupt atau sudah diambil resultnya, harus reset dulu
		m_Corrupted = true;
		return;
	}

	while (p_Length-- && !m_Corrupted) {
		m_MessageBlock[m_MessageBlockIndex++] = (*p_MessageArray & 0xFF);

		m_LengthLow += 8;
		m_LengthLow &= 0xFFFFFFFF;		// ubah jadi 32 bit
		if (m_LengthLow == 0) {
			m_LengthHigh++;
			m_LengthHigh &= 0xFFFFFFFF;	// ubah jadi 32 bit
			if (m_LengthHigh == 0)
				m_Corrupted = true;		// message terlalu panjang
		}

		if (m_MessageBlockIndex == 64)	// proses block
			ProcessMessageBlock();

		p_MessageArray++;
	}
}

void SHA1::ProcessMessageBlock()
{
	const unsigned t_K[] = {	// definisi konstanta untuk SHA1
							0x5A827999,
							0x6ED9EBA1,
							0x8F1BBCDC,
							0xCA62C1D6
						   };
	int t_LoopCounter;
	unsigned t_Temp;
	unsigned t_W[80];					// sekuens word
	unsigned t_A, t_B, t_C, t_D, t_E;	// buffer word

	// inisiasi 16 word pertama dalam array t_W
	for (t_LoopCounter = 0; t_LoopCounter < 16; t_LoopCounter++) {
		t_W[t_LoopCounter] = ((unsigned)m_MessageBlock[t_LoopCounter * 4]) << 24;
		t_W[t_LoopCounter] |= ((unsigned)m_MessageBlock[t_LoopCounter * 4 + 1]) << 16;
		t_W[t_LoopCounter] |= ((unsigned)m_MessageBlock[t_LoopCounter * 4 + 2]) << 8;
		t_W[t_LoopCounter] |= ((unsigned)m_MessageBlock[t_LoopCounter * 4 + 3]);
	}

	for (t_LoopCounter = 16; t_LoopCounter < 80; t_LoopCounter++)
		t_W[t_LoopCounter] = CircularShift(1, t_W[t_LoopCounter - 3] ^ t_W[t_LoopCounter - 8] ^ t_W[t_LoopCounter - 14] ^ t_W[t_LoopCounter - 16]);

	// inisiasi variabel hash
	t_A = m_H[0]; t_B = m_H[1]; t_C = m_H[2]; t_D = m_H[3]; t_E = m_H[4];

	// 0-19
	for (t_LoopCounter = 0; t_LoopCounter < 20; t_LoopCounter++) {
		t_Temp = CircularShift(5, t_A) + ((t_B & t_C) | ((~t_B) & t_D)) + t_E + t_W[t_LoopCounter] + t_K[0];
		t_Temp &= 0xFFFFFFFF;	// buat jadi 32 bit
		t_E = t_D;
		t_D = t_C;
		t_C = CircularShift(30, t_B);
		t_B = t_A;
		t_A = t_Temp;
	}

	// 20-39
	for (t_LoopCounter = 20; t_LoopCounter < 40; t_LoopCounter++) {
		t_Temp = CircularShift(5, t_A) + (t_B ^ t_C ^ t_D) + t_E + t_W[t_LoopCounter] + t_K[1];
		t_Temp &= 0xFFFFFFFF;
		t_E = t_D;
		t_D = t_C;
		t_C = CircularShift(30, t_B);
		t_B = t_A;
		t_A = t_Temp;
	}
	
	// 40-59
	for (t_LoopCounter = 40; t_LoopCounter < 60; t_LoopCounter++) {
		t_Temp = CircularShift(5, t_A) + ((t_B & t_C) | (t_B & t_D) | (t_C & t_D)) + t_E + t_W[t_LoopCounter] + t_K[2];
		t_Temp &= 0xFFFFFFFF;
		t_E = t_D;
		t_D = t_C;
		t_C = CircularShift(30, t_B);
		t_B = t_A;
		t_A = t_Temp;
	}

	// 60-79
	for (t_LoopCounter = 60; t_LoopCounter < 80; t_LoopCounter++) {
		t_Temp = CircularShift(5, t_A) + (t_B ^ t_C ^ t_D) + t_E + t_W[t_LoopCounter] + t_K[3];
		t_Temp &= 0xFFFFFFFF;
		t_E = t_D;
		t_D = t_C;
		t_C = CircularShift(30, t_B);
		t_B = t_A;
		t_A = t_Temp;
	}

	m_H[0] = (m_H[0] + t_A) & 0xFFFFFFFF;
	m_H[1] = (m_H[1] + t_B) & 0xFFFFFFFF;
	m_H[2] = (m_H[2] + t_C) & 0xFFFFFFFF;
	m_H[3] = (m_H[3] + t_D) & 0xFFFFFFFF;
	m_H[4] = (m_H[4] + t_E) & 0xFFFFFFFF;

	m_MessageBlockIndex = 0;	// done
}

void SHA1::PadMessage()
{
	// cek apakah message block saat ini terlalu kecil untuk menyimpan
	// padding bits dan 64 bit panjang message.
	// Jika ya, tambahkan padding, proses block ini, dan lanjutkan padding ke block kedua
	if (m_MessageBlockIndex > 55) {
		m_MessageBlock[m_MessageBlockIndex++] = 0x80;	// tambahkan bit 1 di depan diikuti nol
		while (m_MessageBlockIndex < 64)
			m_MessageBlock[m_MessageBlockIndex++] = 0;

		ProcessMessageBlock();							// proses block ini

		while (m_MessageBlockIndex < 56)
			m_MessageBlock[m_MessageBlockIndex++] = 0;
	}
	else {
		m_MessageBlock[m_MessageBlockIndex++] = 0x80;	// tambahkan bit 1 di depan diikuti nol
		while (m_MessageBlockIndex < 56)
			m_MessageBlock[m_MessageBlockIndex++] = 0;
	}

	// simpan panjang message dalam 8 byte terakhir
	m_MessageBlock[56] = (m_LengthHigh >> 24) & 0xFF;
	m_MessageBlock[57] = (m_LengthHigh >> 16) & 0xFF;
	m_MessageBlock[58] = (m_LengthHigh >> 8) & 0xFF;
	m_MessageBlock[59] = (m_LengthHigh) & 0xFF;
	m_MessageBlock[60] = (m_LengthLow >> 24) & 0xFF;
	m_MessageBlock[61] = (m_LengthLow >> 16) & 0xFF;
	m_MessageBlock[62] = (m_LengthLow >> 8) & 0xFF;
	m_MessageBlock[63] = (m_LengthLow) & 0xFF;

	ProcessMessageBlock();	// proses block ini
}

unsigned SHA1::CircularShift(int p_Bits, unsigned p_Word)
{
    return ((p_Word << p_Bits) & 0xFFFFFFFF) | ((p_Word & 0xFFFFFFFF) >> (32 - p_Bits));
}
