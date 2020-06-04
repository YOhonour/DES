#include "stdio.h"  
#include "memory.h"  
#include "time.h"  
#include "stdlib.h"  
#include"myDES.h"
#include <iostream> 

/*
字节序：
	本程序高位在低地址
	左半部分指低地址
*/
//字符转化为Byte
void CharToBit(char ch,char* bits) {
	for (size_t i = 0; i < 8; i++)
	{
		//高位在低地址
		//bits[i] = (ch >> (7-i)) & 1;
		//高位在高地址
		bits[i] = (ch >> i) & 1;
	}
}
void BitToChar(char* bit, char* ch) {
	int cnt;
	//高位在高地址
	for (cnt = 0; cnt < 8; cnt++) {
		*ch |= *(bit + cnt) << cnt;
	}
}
//将长度为8的字符串转为二进制位串  
int Char8ToBit64(char ch[8], char bit[64]) {
	int cnt;
	for (cnt = 0; cnt < 8; cnt++) {
		CharToBit(*(ch + cnt), bit + (cnt << 3));
	}
	return 0;
}

//将二进制位串转为长度为8的字符串  
int Bit64ToChar8(char bit[64], char ch[8]) {
	int cnt;
	memset(ch, 0, 8);
	for (cnt = 0; cnt < 8; cnt++) {
		BitToChar(bit + (cnt << 3), ch + cnt);
	}
	return 0;
}
//左循环移位
void letf_shift(char* sourse,const int size,int moveSteps) {
	char* temp = (char*)malloc(sizeof(char)*size);
	memcpy(temp, sourse + moveSteps, size - moveSteps);
	memcpy(temp + (size - moveSteps), sourse, moveSteps);
	memcpy(sourse, temp, size);
	free(temp);
}
//右循环移位
void right_shift(char* sourse, const int size, int moveSteps) {
	char* temp = (char*)malloc(sizeof(char) * size);
	memcpy(temp + moveSteps, sourse, size - moveSteps);
	memcpy(temp, sourse + (size - moveSteps), moveSteps);
	memcpy(sourse, temp, size);
	free(temp);
}
//模2加
void Mode2Add(char *parameter1, char *parameter2,char *result,int length) {
	for (int i = 0; i < length; i++)
	{
		result[i] = (parameter1[i] ^ parameter2[i]);
	}
}
/*
选择置换
*/
void ChioseSwitch(int* choiseTable, char* sourse, char* result, int size) {
	for (int i = 0; i < size; i++) {
		*(result + i) = *(sourse + choiseTable[i]);
	}
}
//生成子密钥 rowKey 16字节原始密钥 roundKeys[16][48] 生成的16个48位轮密钥
void generateRoundKey(char rowKey[64],char roundKeys[16][48]) {
	//选择置换
	//char ** roundKeys = (char**)malloc(sizeof(char)*16*48);
	memset(roundKeys, 2, 16 * 48);
	char temp[56];
	ChioseSwitch(PC_1, rowKey, temp, 56);
	for (int i = 0; i < 16; i++)
	{
		letf_shift(temp, 28, MOVE_TIMES[i]);
		letf_shift(temp + 28, 28, MOVE_TIMES[i]);
		ChioseSwitch(PC_2, temp, roundKeys[i],48);
	}
	return ;
}
void S_Box_part(char in[6], char out[4] ,char currSBox[4][16]) {
	int row = (in[0] * 2) + in[5];
	int clumn = in[1]*8 + in[2]*4 + in[3]*2 + in[4];
	char ch = currSBox[row][clumn];
	for (size_t i = 0; i < 4; i++)
	{
		out[i] = (ch >> i) & 1;
	}
}
void SBOX(char data[48],char out[32]) {
	for (size_t i = 0; i < 8; i++)
	{
		S_Box_part(data+i*8,out+i*8,S[i]);
	}
}
//f函数
int Function_F(char R[32],char correntRoundKey[48],char result[32]) {
	char expanded_R[48],modeResult[48],afterP[32];
	ChioseSwitch(E_Table,R,expanded_R,48);
	Mode2Add(expanded_R, correntRoundKey, modeResult, 48);
	char afterSBox[300];
	SBOX(R, afterSBox);
	ChioseSwitch(P_Table, afterSBox, afterP, 32);
	memcpy(result, afterP, 32);
	return 0;
}
int DES_Encrypt(char* soursePath, char* keyPath, char* desPath) {
	FILE *sourse,*KEY,*DES;
	if ((sourse = fopen(soursePath, "rb+")) == NULL || 
		(KEY = fopen(keyPath, "rb+")) == NULL ||
		(DES = fopen(desPath, "wb+")) == NULL)
	{
		printf("FILE OPEN ERROR");
		exit(0); 
	}
	char sourseBuffer[8];//8个字节，64位
	char sourseBit[64];
	char switchedSourseBit[64];
	char keyBuffer[8];//8个字节，64位
	char keyBit[64];
	char roundKeys[16][48];

	fread(keyBuffer,sizeof(char),8,KEY);
	Char8ToBit64(keyBuffer, keyBit);
	generateRoundKey(keyBit, roundKeys);
	int sourceReaded;
	//fseek(sourse,0L, SEEK_END);
	//printf("%d", ftell(sourse));
	while (1)
	{
		sourceReaded = fread(sourseBuffer, sizeof(char), 8, sourse);
		if (sourceReaded < 8 && sourceReaded != 0){
			memset(sourseBuffer + sourceReaded, 0, 8 - sourceReaded);
		}else if (sourceReaded == 0){
			break;
		}
		
		Char8ToBit64(sourseBuffer, sourseBit);
		ChioseSwitch(IP_Table, sourseBit, switchedSourseBit,64);//初始置换
		char* L = switchedSourseBit, * R = switchedSourseBit + 32;
		
		for (int i = 0; i < 16; i++)
		{
			char TEMP[32],TEMP_F[32];
			memcpy(TEMP, R, 32);
			Function_F(R, roundKeys[i], TEMP_F);
			Mode2Add(TEMP_F, L, R, 32);
			memcpy(L, TEMP, 32);
		}
		/*memcpy(temp_buffer, L, 32);
		memcpy(L, R, 32); 
		memcpy(R, temp_buffer, 32);*/
		char TEMP[64];
		ChioseSwitch(IP_1_Table, switchedSourseBit,TEMP,64);
		char tempChars[8];
		Bit64ToChar8(TEMP, tempChars);
		fwrite(tempChars, sizeof(tempChars), 1, DES);
	}
	fclose(sourse);
	fclose(KEY);
	fclose(DES);
	return 0;
}
int DES_Decrypt(char* soursePath, char* keyPath, char* desPath) {
	FILE* sourse, * KEY, * DES;
	if ((sourse = fopen(soursePath, "rb+")) == NULL ||
		(KEY = fopen(keyPath, "rb+")) == NULL ||
		(DES = fopen(desPath, "wb+")) == NULL)
	{
		printf("FILE OPEN ERROR");
		exit(0);
	}
	char sourseBuffer[8];//8个字节，64位
	char sourseBit[64];
	
	char keyBuffer[8];//8个字节，64位
	char keyBit[64];//key的二进制
	char roundKeys[16][48];

	fread(keyBuffer, sizeof(char), 8, KEY);//读取Key
	Char8ToBit64(keyBuffer, keyBit);//转换为二进制
	generateRoundKey(keyBit, roundKeys);//生成子密钥
	int sourceReaded;

	while (1) {
		char switchedSourseBit[64];
		sourceReaded = fread(sourseBuffer, sizeof(char), 8, sourse);//读取8个字节
		if (sourceReaded < 8 && sourceReaded != 0) {
			memset(sourseBuffer + sourceReaded, 0, 8 - sourceReaded);//不足8字节填充0
		}
		else if (sourceReaded == 0) {
			break;
		}
		Char8ToBit64(sourseBuffer, sourseBit);
		ChioseSwitch(IP_Table, sourseBit, switchedSourseBit, 64);//初始置换
		char *L = switchedSourseBit, *R = switchedSourseBit + 32, temp_buffer[32];
		for (size_t i = 0; i < 16; i++)
		{
			memcpy(temp_buffer, L, 32);
			char F_result[32];
			Function_F(temp_buffer, roundKeys[i], F_result);
			
			Mode2Add(F_result,R,L,32);
			memcpy(R, temp_buffer, 32);
		}
		char reultCode[64];
		ChioseSwitch(IP_1_Table, switchedSourseBit, reultCode, 64);//逆初始置换
		char tempChars[8];
		Bit64ToChar8(reultCode, tempChars);
		fwrite(tempChars, sizeof(tempChars), 1, DES);
	}
	fclose(sourse);
	fclose(KEY);
	fclose(DES);
	return 0;
}
int test();
int test2() {
	char l[] = "I love network security";
	return 1;
}
int main() {
	char soursePath[] = "C:\\Users\\Lenovo\\Desktop\\2.txt";
	char keyPath[] = "C:\\Users\\Lenovo\\Desktop\\key.txt";
	char encryptted[] = "C:\\Users\\Lenovo\\Desktop\\my.txt";
	char myresult[] = "C:\\Users\\Lenovo\\Desktop\\myresult.txt";
	/*char testResourse[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	char TestKey[] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
	FILE* res, * key;
	if ((res = fopen(soursePath, "rb+")) == NULL ||
		(key = fopen(keyPath, "rb+")) == NULL)
	{
		printf("FILE OPEN ERROR");
		exit(0);
	}
	fwrite(testResourse, sizeof(char), 8, res);
	fwrite(TestKey, sizeof(char), 8, key);
	fclose(res);
	fclose(key);*/
	//test();
	//clock_t a, b;
	//a = clock();
	printf("源文本路径：%s\n", soursePath);
	printf("初始密钥路径：%s\n", keyPath);

	printf("开始加密...\n");
	DES_Encrypt(soursePath, keyPath, encryptted);
	printf("加密完成！\n");
	printf("密文路径：%s\n", encryptted);
	printf("开始解密...\n");
	DES_Decrypt(encryptted, keyPath, myresult);
	printf("解密完成！\n");
	printf("解密文本路径：%s\n", myresult);
	//b = clock();
	//printf("消耗%d毫秒\n", b - a);
	//char rowKey[64];
	//for (int i = 0; i < 64; i++)
	//{
		//rowKey[i] = i;
	//}
	//char roundKeys[16][48];
	//generateRoundKey(rowKey, roundKeys);
	
	//char ch = 0x3a;
	//char bits[8] = { 1, '2', '3', '4', '5', 1, '7', '8',};
	//right_shift(bits, 8, 3);
	//CharToBit(ch, bits);
	//char in[6] = { 0,1,1,0,0,1 }, out[4];
	//S_Box(in, out,S[0]);
	return 1;
}
void rrr(char* r,char *d,int len) {
	for (size_t i = 0; i < len; i++)
	{
		d[i] = r[i] + '0';
	}
}
//生成子密钥 rowKey 16字节原始密钥 roundKeys[16][48] 生成的16个48位轮密钥
void generateRoundKeyWithTest(char rowKey[64], char roundKeys[16][48],FILE * roundKeyFile) {
	//选择置换
	//char ** roundKeys = (char**)malloc(sizeof(char)*16*48);
	memset(roundKeys, 2, 16 * 48);
	char temp[56];
	ChioseSwitch(PC_1, rowKey, temp, 56);
	char rsOC1[56];
	rrr(temp, rsOC1,56);
	fwrite("PC_1置换后：", sizeof("PC_1置换后："), 1, roundKeyFile);
	fwrite("\n", sizeof("\n"), 1, roundKeyFile);
	fwrite(rsOC1, sizeof(rsOC1), 1, roundKeyFile);
	for (int i = 0; i < 16; i++)
	{
		letf_shift(temp, 28, MOVE_TIMES[i]);
		letf_shift(temp + 28, 28, MOVE_TIMES[i]);
		ChioseSwitch(PC_2, temp, roundKeys[i], 48);

		char tempChar[56],rKC[48];
		rrr(temp, tempChar, 56);
		rrr(roundKeys[i], rKC, 48);
		char c[] = "  C:",D[]="  D ";
		fwrite("循环次数：", sizeof("循环次数："), 1, roundKeyFile);
		char t = '1' + i;
		fwrite(&t, sizeof(char), 1, roundKeyFile);
		fwrite("  位移位数：", sizeof("  位移位数："), 1, roundKeyFile);
		fwrite(MOVE_TIMES + i, sizeof(int), 1, roundKeyFile);
		fwrite("\n", sizeof("\n"), 1, roundKeyFile);
		fwrite(c, sizeof(c), 1, roundKeyFile);
		fwrite(tempChar, sizeof(char), 28, roundKeyFile);
		fwrite(D, sizeof(D), 1, roundKeyFile);
		fwrite(tempChar +28, sizeof(char), 28, roundKeyFile);
		fwrite("\n", sizeof("\n"), 1, roundKeyFile);
		fwrite("PC_2置换后：", sizeof("PC_2置换后："), 1, roundKeyFile);
		fwrite(rKC, sizeof(char), 48, roundKeyFile);
		fwrite("\n", sizeof("\n"), 1, roundKeyFile); fwrite("\n", sizeof("\n"), 1, roundKeyFile);
	}
	return;
}
int test() {
	char keyPath[] = "C:\\Users\\Lenovo\\Desktop\\key.txt", desPath[] = "C:\\Users\\Lenovo\\Desktop\\roundKey.txt";
	FILE* key,* roundKeyFile;
	if ((key = fopen(keyPath, "rb+")) == NULL || (roundKeyFile = fopen(desPath, "wb+")) == NULL)
	{
		exit(-1);
	}
	char rowKey[64], roundKey[16][48],buf[16];
	fread(buf, sizeof(char), 16, key);
	char nbf[] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
	Char8ToBit64(nbf, rowKey);
	//写原始密钥
	fwrite(buf, sizeof(buf), 1, roundKeyFile);
	fwrite("\n", sizeof(char), 1, roundKeyFile);
	//写原始密钥二进制
	char ks[64];
	rrr(rowKey, ks, 64);
	fwrite(rowKey,sizeof(rowKey),1, roundKeyFile);
	fwrite("\n", sizeof(char), 1, roundKeyFile);
	
	generateRoundKeyWithTest(rowKey, roundKey, roundKeyFile);
	
	return 0;
}