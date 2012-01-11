//
//
//  @ Project : Untitled
//  @ File Name : main.cpp
//  @ Date : 12/7/2006
//  @ Author : 
//
//

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include "SHA256.h"
#include "SHA512.h"
#include "SHA1.h"

using namespace std;

// deklarasi prototype
void Tes256();
void Tes512();
void TesSHA1();

// lain-lain
unsigned int GCDR(unsigned int num1, unsigned int num2);
unsigned int GCDB(unsigned int num1, unsigned int num2);

// main
int main(int argc, char* args[])
{
    Tes512();
    Tes256();
    TesSHA1();
    cout << "selesai" << endl;
    return 0;
}

// implementasi
void Tes512()
{
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                                TES SHA 512                                   " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << endl << endl;
    unsigned char t_HasilBenar[] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    unsigned char t_Message[] = "abc";
    cout << "Input: " << t_Message << endl;
    
    unsigned char t_MD[SHA512_DIGEST_SIZE];
    
    IHash* tes = new SHA512();
    if (tes == NULL)
    {
        // alokasi gagal
        cout << "alokasi gagal" << endl;
        exit(1);
    }
    tes->Init();
    tes->Update(t_Message, strlen((char*)t_Message));
    tes->Final(t_MD);
        
    unsigned char t_Output[SHA512_DIGEST_SIZE + 1];
    
    t_Output[SHA512_DIGEST_SIZE] = '\0';
    
    for (int i = 0; i < SHA512_DIGEST_SIZE; i++)
    {
        sprintf((char*)t_Output + 2 * i, "%02x", t_MD[i]);
    }
    
    cout << "Hasil     : " << t_Output << endl;
    cout << "HasilBenar: " << t_HasilBenar << endl;
    cout << endl << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                               TES SHA512 SELESAI                             " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    delete tes;
}

void Tes256()
{
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                                TES SHA 256                                   " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << endl << endl;
    unsigned char t_HasilBenar[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    unsigned char t_Message[] = "abc";
    cout << "Input: " << t_Message << endl;
    
    unsigned char t_MD[SHA256_DIGEST_SIZE];
    
    IHash* tes = new SHA256();
    if (tes == NULL)
    {
        // alokasi gagal
        cout << "alokasi gagal" << endl;
        exit(1);
    }
    tes->Init();
    tes->Update(t_Message, strlen((char*)t_Message));
    tes->Final(t_MD);
    
    unsigned char t_Output[SHA256_DIGEST_SIZE + 1];
    
    t_Output[SHA256_DIGEST_SIZE] = '\0';
    
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        sprintf((char*)t_Output + 2 * i, "%02x", t_MD[i]);
    }
    
    cout << "Hasil     : " << t_Output << endl;
    cout << "HasilBenar: " << t_HasilBenar << endl;
    cout << endl << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                               TES SHA256 SELESAI                             " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    delete tes;
}

void TesSHA1()
{
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                                TES SHA 1                                     " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << endl << endl;
    unsigned char t_HasilBenar[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
    unsigned char t_Message[] = "abc";
    cout << "Input: " << t_Message << endl;
    
    unsigned int t_MD[SHA1_DIGEST_SIZE];
    
    SHA1* tes = new SHA1();
    if (tes == NULL)
    {
        // alokasi gagal
        cout << "alokasi gagal" << endl;
        exit(1);
    }
    tes->Input(t_Message, strlen((char*)t_Message));
    tes->Result(t_MD);
    
    string t_Result;
	std::ostringstream t_Stm;

	// set flag ostringstream menjadi hex
	std::ios_base::fmtflags t_Flags =  t_Stm.setf(std::ios_base::hex, std::ios_base::basefield);

	for (int i = 0; i < (SHA1_DIGEST_SIZE); i++)
		t_Stm << t_MD[i];
	
	t_Result = t_Stm.str();
    
    cout << "Hasil     : " << t_Result << endl;
    cout << "HasilBenar: " << t_HasilBenar << endl;
    cout << endl << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    cout << "                               TES SHA1   SELESAI                             " << endl;
    cout << "------------------------------------------------------------------------------" << endl;
    delete tes;
}

// lain-lain


// GCD rekursif
unsigned int GCDR(unsigned int num1, unsigned int num2)
{
    // basis
    if (num1 == 0)
	{
		return num2;
	}
	if (num2 == 0)
	{
		return num1;
	}
   	// rekurens
    return (GCDR(num2, num1 % num2));
}

// GCD binary
unsigned int GCDB(unsigned int num1, unsigned int num2)
{
    // kasus nol
    if (num1 == 0 || num2 == 0)
	{
        return num1 | num2;
    }
    // bagi dua sampai salah-satu ganjil
    int shift = 0;
    for (shift = 0; ((num1 | num2) & 1) == 0; ++shift)
	{
        num1 >>= 1;
        num2 >>= 1;
    }
    // bagi dua sampai ganjil
    while ((num1 & 1) == 0)
	{
        num1 >>= 1;
    }
    do {
        // bagi dua sampai ganjil
        while ((num2 & 1) == 0)
		{
            num2 >>= 1;
        }
        // ganjil kurang ganjil = genap
        if (num1 < num2)
		{
            num2 -= num1;
        }
		else
		{
            int diff = num1 - num2;
            num1 = num2;
            num2 = diff;
        }
        // bagi dua lagi
        num2 >>= 1;
    } while (num2 != 0);
    
	// hasil gcd = a x 2^n
    return num1 << shift;
}

