#include "BlowFish.h"
#include <string.h>
#include<stdio.h>

bool BlowFishInit(BLOWFISH_CTX* blowCtx, unsigned char* key, unsigned int keylen)
{
    //���ô����CTX�е�SBOXֵ
    for (int Row = 0; Row < 4; Row++)
    {
        for (int Col = 0; Col < 256; Col++)
        {
            blowCtx->sbox[Row][Col] = ORIG_S[Row][Col];
        }
    }

    /*
    ����pbox
    1.ѭ��18��
    2.ÿ�ֶ�����ctx.pboxֵ��data ^
    3.data = *(DWORD*)key[0] key[1].....
    */
    int KeyIndex = 0;
    for (int index = 0; index < N + 2; index++)
    {
        unsigned int data = 0;
        //���data ��key���ַ����õ�data����
        for (int k = 0; k < 4; k++)
        {
            //ͨ����λ����ÿ���ַ�
            data = (data << 8) | key[KeyIndex];
            KeyIndex++;
            //���������key���� ��ôkeyҪ�ӿ�ʼ
            if (KeyIndex >= keylen)
                KeyIndex = 0;
        }
        //��������
        blowCtx->pbox[index] = ORIG_P[index] ^ data;
    }

    //��һ��64λ0 ���м��ܡ����ܽ����������õ�pbox[i]��pbox[i+1]��
    unsigned int Data1 = 0;
    unsigned int Data2 = 0;
    for (int i = 0; i < N + 2; i += 2)
    {
        BlowFish_Encry(blowCtx, &Data1, &Data2);
        blowCtx->pbox[i] = Data1;
        blowCtx->pbox[i + 1] = Data2;
    }
    //��ʼ��Sbox
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 256; j += 2)
        {
            BlowFish_Encry(blowCtx, &Data1, &Data2);
            blowCtx->sbox[i][j] = Data1;
            blowCtx->sbox[i][j + 1] = Data2;
        }
    }
    return true;
}

//unsigned int F(PBLOWFISH_CTX blowCtx, unsigned int Data)
//{
//
//    unsigned int a, b, c, d;
//    /*
//    ����λ���� ȡ���±�ֵ
//    */
//    
//   a = (Data  >> 24) & 0xFF;
//   b = (Data >> 16) & 0xFF;
//   c = (Data >> 8) & 0xFf;
//   d = Data & 0xFF;
//   
//
//    int TempValue = blowCtx->sbox[0][a] + blowCtx->sbox[1][b];
//    TempValue = TempValue ^ blowCtx->sbox[2][c];
//    TempValue = TempValue + blowCtx->sbox[3][d];
//    //��ʽ ((a+b)^c)+d
//    return TempValue;
//}
static unsigned long F(BLOWFISH_CTX* ctx, unsigned long x) {
    unsigned short a, b, c, d;
    unsigned long  y;

    /* d = (unsigned short)(x & 0xFF);
     x >>= 8;
     c = (unsigned short)(x & 0xFF);
     x >>= 8;
     b = (unsigned short)(x & 0xFF);
     x >>= 8;
     a = (unsigned short)(x & 0xFF);

     //������ʹ��
     */
    a = (x >> 24) & 0xFF;
    b = (x >> 16) & 0xFF;
    c = (x >> 8) & 0xFf;
    d = x & 0xFF;

    y = ctx->sbox[0][a] + ctx->sbox[1][b];
    y = y ^ ctx->sbox[2][c];
    y = y + ctx->sbox[3][d];

    return y;
}

void BlowFish_Encry(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right)
{
    unsigned long  Xl;
    unsigned long  Xr;
    unsigned long  temp;
    short       i;

    //���ܲ������Ƚ����Ϊleft��right���顣 ÿһ��ֱ�32λ
    Xl = *left;
    Xr = *right;

    for (i = 0; i < N; ++i) {
        Xl = Xl ^ blowCtx->pbox[i];
        Xr = F(blowCtx, Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;						//�������ҵ�ֵ�� l = R r= l ������һ��ѭ�����ܹ�16��
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;                          //16�����֮�󽻻�����
    Xr = temp;

    Xr = Xr ^ blowCtx->pbox[N];              //������һ���ɻ�
    Xl = Xl ^ blowCtx->pbox[N + 1];

    *left = Xl;
    *right = Xr;


}

void BlowFish_Decrypt(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right)
{
    unsigned int Xl = *left;
    unsigned int Xr = *right;

    //����ѭ��
    for (int i = N + 1; i > 1; --i)
    {
        Xl = Xl ^ blowCtx->pbox[i];
        Xr = Xr ^ F(blowCtx, Xl);

        //�������ҽ���
        unsigned int temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    //���һ�ּ�������
    unsigned int temp = Xl;
    Xl = Xr;
    Xr = temp;

    //����ԭ
    Xr = Xr ^ blowCtx->pbox[1];
    Xl = Xl ^ blowCtx->pbox[0];

    //���ñ�������
    *left = Xl;
    *right = Xr;
}



