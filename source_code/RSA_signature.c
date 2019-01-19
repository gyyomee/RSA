#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<Windows.h>

/* ��� ���� */
#define m 1024 //���� n�� ��Ʈ ��
#define mp 512 //��� �Ҽ� p�� ��Ʈ ��
#define mq 512 //��� �Ҽ� q�� ��Ʈ ��
#define HASH 128
#define LEN_PS 91 //�е� ��Ʈ���� ũ��
#define DATA_LEN 53
#define HASH_LEN 34
#define DHEX 32
#define OCT 8
#define Char_NUM 8
#define B_S 64
#define mb m/DHEX
#define hmb mb/2
#define mpb mp/DHEX
#define mqb mq/DHEX

#define rdx 0x100000000

/* Ÿ�� ���� */
typedef unsigned long int ULINT;
typedef unsigned _int64 INT64;
typedef unsigned _int32 INT32;

/* �Լ� ���� */
void RSA_Signature(); //RSA ���� �Լ�
void RSA_Verification(); //RSA ���� ���� �Լ�
int get_from_file(FILE* fptr, short *a, short mn); //���Ϸκ��� �����͸� �о� ���� ���·� �����ϴ� �Լ�
void put_to_file(FILE* fptr, short *a, short mn); //���� �����͸� ����Ʈ ���·� ��ȯ�Ͽ� ���Ͽ� �����ϴ� �Լ�
void put_to_message(unsigned char* msg, short *a, short mn); //���� �����͸� ����Ʈ ���·� ��ȯ�Ͽ� �޽��� ���ۿ� �����ϴ� �Լ�
void CONV_O_to_B(INT64 *A, short *B, short mn); //octet�� binary�� ��ȯ�ϴ� �Լ�
void CONV_B_to_O(short *A, INT64 *B, short mn); //binary�� octet�� ��ȯ�ϴ� �Լ�
void CONV_R_to_B(INT64 *A, short *B, short mn); //Radix�� binary�� ��ȯ�ϴ� �Լ�
void CONV_B_to_R(short *A, INT64 *B, short mn); //binary�� Radix�� ��ȯ�ϴ� �Լ�
void rand_g(short *out, short n); //���� ���� �����Ͽ� ���� ���·� �����ϴ� �Լ�
void Modular(INT64 *X, INT64 *N, short mn); //���� ������ �����ϴ� �Լ�
void Conv_mma(INT64 *A, INT64 *B, INT64 *C, INT64 *N, short mn); //�������� ���� ���� ������ �����ϴ� �Լ�
void LeftTORight_Pow(INT64 *A, INT64 *E, INT64 *C, INT64 *N, short mn); //Left to Right ����� �����ϴ� �Լ�

/* ���� ���� */
INT32 LAND = 0xFFFFFFFF;

//���� Ű �Ķ����
INT64 N[mb]; //���� n(=p*q)
INT64 E[mb]; //���� Ű e
INT64 D[mb]; //���Ű d

//����� ������ ���Ǵ� ����(����(binary) ����)
short s[m]; //���� ��
short h[HASH_LEN * 8]; //�ؽ� ��(����)
short v_h[m]; //�ؽ� ��(����)
short ps[LEN_PS * 8]; //�е� ��Ʈ��

//����� ������ ���Ǵ� ����(Radix�� octet ����)
INT64 S[mb]; //���� ��(����)
INT64 V_S[mb]; //���� ��(����)
INT64 H[mb]; //�ؽ� ��(Radix)
INT64 HDATA[HASH_LEN]; //�ؽ� ��(octet-����)
INT64 SB[mb * 4]; //������(8 bit -����)
INT64 SB1[mb]; //������(16bit)
INT64 V_SB[mb * 4]; //������(8 bit - ����)
INT64 V_HDATA[HASH_LEN]; //�ؽ� ��(octet - ����)
INT64 O_PS[LEN_PS * 8]; //�е� ��Ʈ��(octet)

//MD5�� ��Ÿ���� �ĺ� ��
unsigned char md6_num[18] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

/* rsa_std.c ������ �����Ѵ� */
#include "rsa_std.c"
#include "MD5_1.c"

void main(int argc, char* argv[])
{
	int select;

	//����� ���� ���� ����
	printf("*1. RSA ����    2. RSA �������\n");
	printf("- �����Ͻÿ� : ");
	scanf("%d", &select);

	//������ �׸� ����
	if (select == 1)
		RSA_Signature();
	else if (select == 2)
		RSA_Verification();
	else
		printf("* �߸� �Է��ϼ̽��ϴ� !\n");

	system("pause");
	system("pause");
}

//RSA����
void RSA_Signature()
{
	int i, j, cnt;
	BYTE hash_text[HASH_LEN] = { 0, };
	char file_name[32] = { 0, }, s_file_name[32] = { 0, };
	FILE *fptr;

	//���� ����� ���Ű ������ ����
	if ((fptr = fopen("secret_key.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}

	//���Ϸ� ���� ���Ű d�� ���� n�� �����Ѵ�
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &N[i]);
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &D[i]);

	fclose(fptr);

	//������ ���ϸ� �Է�
	printf("* ������ ���ϸ��� �Է��Ͻÿ� : ");
	scanf("%s", file_name);

	//���� ����
	if ((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	MD5(fptr, hash_text); //MD5 �ؽ�
	fclose(fptr);

	//MD5 �ĺ� ���� �ؽ� ���� �̾ �߰��Ѵ�
	for (i = 0; i < 18; i++)
		hash_text[i + 16] = md6_num[18 - i - 1];

	//�ؽ� �����͸� ���� ������ ��ȯ�Ѵ�
	cnt = HASH_LEN * 8 - 1;
	for (i = 0; i < HASH_LEN; i++) {
		for (j = 0; j < 8; j++) {
			h[cnt] = (hash_text[i] >> j) & 0x01;
			cnt--;
		}
	}

	CONV_B_to_O(h, HDATA, HASH_LEN); //���� �����͸� octet���� ��ȯ
	/* EMSA-PKCS #1-v1.5 �е� */
	//[00|01|PS|00|T] (T=�ؽ� �˰��� �ĺ��� +�ؽ� ��)
	for (i = 0; i < mb * 4; i++)
		SB[i] = 0xFF;

	SB[mb * 4 - 1] = 0x00;
	SB[mb * 4 - 2] = 0x01;
	SB[HASH_LEN] = 0x00;

	for (i = HASH_LEN - 1; i >= 0; i--)
		SB[i] = HDATA[i];

	for (i = mb * 4 - 1; i > 0; i = i - 4)
		SB1[i / 4] = (SB[i] << (DHEX - OCT)) + (SB[i - 1] << (OCT + OCT)) + (SB[i - 2] << OCT) + SB[i - 3];
	/* �е� ���� ���� */

	/*** c = h(m)^d mod n (m-bit)***/
	LeftTORight_Pow(SB1, D, S, N, mb); //���� �޽����� ������ �Ѵ�
	CONV_R_to_B(S, s, mb); //Radix�� ���� �����ͷ� ��ȯ

	//������ ������ ���� �̸� ����(�� : MONEY.txt -> MONEY.sgn)
	for (i = 0;; i++)
	{
		if (file_name[i] == '.')
		{
			s_file_name[i] = '\0';
			strcat(s_file_name, ".sgn");
			break;
		}

		s_file_name[i] = file_name[i];
	}
	
	//���� �����͸� ������ ���� ����
	if ((fptr = fopen(s_file_name, "wb")) == NULL)
	{
		printf("File open failed! \n");
		exit(1);
	}

	put_to_file(fptr, s, m / Char_NUM); //���� �����͸� ���Ϸ� ����

	printf("\n* The signature is completed. \n\n");
	fclose(fptr);
}

void RSA_Verification()
{
	int i;
	BYTE v_text[HASH_LEN] = { 0, };
	BYTE hash_text[16] = { 0, };
	char file_name[32] = { 0, }, s_file_name[32] = { 0, };
	FILE* fptr;

	//�������� ���� Ű ���� ����
	if ((fptr = fopen("public_key.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}

	//���Ϸκ��� ���� Ű e�� ���� n�� �����Ѵ�
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &N[i]);
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &E[i]);

	fclose(fptr);

	//������ ���ϸ� �Է�
	printf("* ������ ���ϸ��� �Է��Ͻÿ� : ");
	scanf("%s", file_name);

	//���� ����
	if ((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	MD5(fptr, hash_text); //MD5 �ؽ�

	fclose(fptr);

	//���� ���ϸ� �Է�
	printf("* ���� ���ϸ��� �Է��Ͻÿ�(.sgn) : ");
	scanf("%s", file_name);

	//���� ���� ����
	if ((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	get_from_file(fptr, s, m / Char_NUM); //���Ϸκ��� ���� �����͸� �о�´�

	CONV_B_to_R(s, V_S, mb); //���� �����͸� Radix�� ��ȯ

	LeftTORight_Pow(V_S, E, H, N, mb); //�������

	//������ ��ȯ(Radix -> Binary -> Octet)
	CONV_R_to_B(H, v_h, mb);
	CONV_B_to_O(v_h, V_SB, mb * 4);

	//�е� �κ��� �����ϰ� �ؽ� �����͸� �����Ѵ�
	for (i = HASH_LEN - 1; i >= 0; i--)
		V_HDATA[i] = V_SB[i];

	//MD5 �ĺ� ���� �����ϰ� �ؽ� ���� ���Ͽ�
	//������ ���� ���θ� Ȯ���Ѵ�
	for (i = 0; i < 16; i++)
	{
		if (V_HDATA[i] != hash_text[i])
		{
			printf("The Verification is failed!\n");
			return;
		}
	}
	
	printf("\n* The Verification is completed!\n");
	close(fptr);
}

//���Ϸκ��� �����͸� �о�� ���� ���·� ����
int get_from_file(FILE* fptr, short *a, short mn)
{
	int i, j;
	short flag = 1, cnt = 0, mm;
	unsigned char b[m / Char_NUM] = { 0, };

	mm = mn*Char_NUM;

	for (i = 0; i < mm; i++)
		a[i] = 0;

	//���Ͽ��� �� ����Ʈ�� �д´�
	for (i = 0; i < mn; i++)
	{
		if (fscanf(fptr, "%c", &b[i]) == EOF)
		{
			if (i == 0)
			{
				flag = -1;
				return(flag);
			}

			flag = 0;

			for (; i < mn; i++)
				b[i] = '\0';

			break;
		}
	}

	cnt = 0;
	//����Ʈ ������ �����͸� ���� ���·� ��ȯ
	for (i = mn - 1; i >= 0; i--)
	{
		for (j = 0; j < Char_NUM; j++)
		{
			a[cnt++] = (b[i] >> j) & 0x01;
		}
	}

	return(flag);
}

//���� ������ �����͸� ����Ʈ ������ ��ȯ�Ͽ� ���Ϸ� ����
void put_to_file(FILE* fptr, short *a, short mn)
{
	int i, j;
	short cnt = 0, mm;
	unsigned char b[m / Char_NUM] = { 0, };
	unsigned char mask[Char_NUM] = { 0x01, 0x02, 0x04, 0x08,
									0x10, 0x20, 0x40, 0x80 };

	mm = mn*Char_NUM;
	cnt = 0;
	//���� ������ �����͸� ����Ʈ ���·� ��ȯ�Ѵ�
	for (i = mn - 1; i >= 0; i--) {
		b[i] = 0x00;
		for (j = 0; j < Char_NUM; j++) {
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	//��ȯȯ �����͸� �޽��� ���ۿ� �����Ѵ�
	for (i = 0; i < mn; i++)
		fprintf(fptr, "%c", b[i]);
}

//���� ������ �����͸� ����Ʈ ������ ��ȯ�Ͽ� ����
void put_to_message(unsigned char * msg, short *a, short mn)
{
	register i, j;
	short cnt = 0, mm;
	unsigned char b[m / Char_NUM] = { 0, };
	unsigned char mask[Char_NUM] = { 0x01, 0x02, 0x04, 0x08,
									0x10, 0x20, 0x40, 0x80 };

	mm = mn*Char_NUM;
	cnt = 0;
	//���� ������ �����͸� ����Ʈ ���·� ��ȯ�Ѵ�
	for (i = mn - 1; i >= 0; i--) {
		b[i] = 0x00;
		for (j = 0; j < Char_NUM; j++) {
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	//��ȯ�� �����͸� �޽��� ���ۿ� �����Ѵ�
	for (i = mn - 1; i >= 0; i--)
		msg[i] = b[i];
}

