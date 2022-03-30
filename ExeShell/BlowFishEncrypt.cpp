#include "BlowFish.h"
#include <string.h>
#include<stdio.h>

bool BlowFishInit(BLOWFISH_CTX* blowCtx, unsigned char* key, unsigned int keylen)
{
    //设置传入的CTX中的SBOX值
    for (int Row = 0; Row < 4; Row++)
    {
        for (int Col = 0; Col < 256; Col++)
        {
            blowCtx->sbox[Row][Col] = ORIG_S[Row][Col];
        }
    }

    /*
    设置pbox
    1.循环18轮
    2.每轮都设置ctx.pbox值与data ^
    3.data = *(DWORD*)key[0] key[1].....
    */
    int KeyIndex = 0;
    for (int index = 0; index < N + 2; index++)
    {
        unsigned int data = 0;
        //填充data 将key的字符设置到data当中
        for (int k = 0; k < 4; k++)
        {
            //通过移位设置每个字符
            data = (data << 8) | key[KeyIndex];
            KeyIndex++;
            //如果超出了key长度 那么key要从开始
            if (KeyIndex >= keylen)
                KeyIndex = 0;
        }
        //否则不满足
        blowCtx->pbox[index] = ORIG_P[index] ^ data;
    }

    //对一个64位0 进行加密。加密结果的输出设置到pbox[i]与pbox[i+1]中
    unsigned int Data1 = 0;
    unsigned int Data2 = 0;
    for (int i = 0; i < N + 2; i += 2)
    {
        BlowFish_Encry(blowCtx, &Data1, &Data2);
        blowCtx->pbox[i] = Data1;
        blowCtx->pbox[i + 1] = Data2;
    }
    //初始化Sbox
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
//    利用位运算 取出下标值
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
//    //公式 ((a+b)^c)+d
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

     //都可以使用
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

    //加密部分首先将其分为left跟right两组。 每一组分别32位
    Xl = *left;
    Xr = *right;

    for (i = 0; i < N; ++i) {
        Xl = Xl ^ blowCtx->pbox[i];
        Xr = F(blowCtx, Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;						//交换左右的值。 l = R r= l 继续下一轮循环。总共16轮
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;                          //16轮完毕之后交换变量
    Xr = temp;

    Xr = Xr ^ blowCtx->pbox[N];              //最后进行一次疑或
    Xl = Xl ^ blowCtx->pbox[N + 1];

    *left = Xl;
    *right = Xr;


}

void BlowFish_Decrypt(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right)
{
    unsigned int Xl = *left;
    unsigned int Xr = *right;

    //倒着循环
    for (int i = N + 1; i > 1; --i)
    {
        Xl = Xl ^ blowCtx->pbox[i];
        Xr = Xr ^ F(blowCtx, Xl);

        //继续左右交换
        unsigned int temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    //最后一轮继续交换
    unsigned int temp = Xl;
    Xl = Xr;
    Xr = temp;

    //返还原
    Xr = Xr ^ blowCtx->pbox[1];
    Xl = Xl ^ blowCtx->pbox[0];

    //设置变量返回
    *left = Xl;
    *right = Xr;
}



