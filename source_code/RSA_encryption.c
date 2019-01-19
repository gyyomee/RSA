#include<stdio.h>
#include<stdlib.h>
#include<string.h>

/* ��� ���� */
#define m 1024 // ��ⷯ�Ǻ�Ʈ��
#define mp 512 // ��мҼ��Ǻ�Ʈ��
#define mq 512 // ��мҼ��Ǻ�Ʈ��
#define HASH 128
#define LEN_PS 8 // �е���Ʈ����ũ��
#define HASH_LEN 34
#define DHEX 32
#define OCT 8
#define Char_NUM 8
#define B_S m/Char_NUM
#define DATA_LEN (B_S-LEN_PS-3)
#define mb m/DHEX
#define hmb mb/2
#define mpb mp/DHEX
#define mqb mq/DHEX
#define E_LENGTH 16
#define rdx 0x100000000

/* Ÿ�� ���� */
typedef unsigned long int ULINT;
typedef unsigned _int64 INT64;
typedef unsigned _int32 INT32;

/* �Լ� ���� */
void RSA_Enc(unsigned char* p_text, unsigned char* result); //RSA ��ȣȭ �Լ�
void RSA_Dec(unsigned char* c_text, unsigned char* result); //RSA ��ȣȭ �Լ�
int get_from_message(unsigned char* msg, short *a, short mn); //�޽��� ���ۿ��� �����͸� �о ���� ���·� �����ϴ� �Լ�
void put_to_message(unsigned char* msg, short *a, short mn); //���� ������ �޽����� ���ۿ� �����ϴ� �Լ�
void CONV_O_to_B(INT64 *A, short *B, short mn); //octet�� binary�� ��ȯ�ϴ� �Լ�
void CONV_B_to_O(short *A, INT64 *B, short mn); //binary�� octet�� ��ȯ�ϴ� �Լ�
void CONV_R_to_B(INT64 *A, short *B, short mn); //Radix�� binary�� ��ȯ�ϴ� �Լ�
void CONV_B_to_R(short *A, INT64 *B, short mn); //binary�� Radix�� ��ȯ�ϴ� �Լ�
void rand_g(short *out, short n); //���� ���� �����ϴ� �Լ�
void Modular(INT64 *X, INT64 *N, short mn); //���� ������ �����ϴ� �Լ�
void Conv_mma(INT64 *A, INT64 *B, INT64 *C, INT64 *N, short mn); //�������� ���� ���� ������ �����ϴ� �Լ�
void LeftTORight_Pow(INT64 *A, INT64 *E, INT64 *C, INT64 *N, short mn); //Left to Right ����� �����ϴ� �Լ�

/* �������� */
INT32 LAND = 0xFFFFFFFF;

//���� Ű �Ķ����
INT64 N[mb]; //���� n(=p*q)
INT64 E[mb]; //���� Ű e
INT64 D[mb]; //���Ű d

			 //������ ������ ���Ǵ� ����(����(binary) ����)
short s[m]; //��ȣ��(��ȣ)
short h[DATA_LEN * 8]; //��
short v_h[m]; //��ȣ��(�е� ����)
short d_d[DATA_LEN * 8]; //��ȣ��(�е� ����)
short ps[LEN_PS * 8]; //�е� ��Ʈ��

					  //��ȣ�� ��ȣ�� ���Ǵ� ����(Radix�� octet����)
INT64 S[mb]; //��ȣ��
INT64 H[mb]; //��ȣ��(Radix)
INT64 DATA[DATA_LEN]; //��(octet)
INT64 EB[mb * 4]; //��ȣ�� ����(8 bit)
INT64 EB1[mb]; //��ȣ�� ����(16 bit)
INT64 D_EB[mb * 4]; //��ȣ�� ����(8 bit)
INT64 D_DATA[DATA_LEN]; //��ȣ ������(octet)
INT64 O_PS[OCT]; //�е� ��Ʈ��(octet)

#include "rsa_std.c"
#include "MD5_1.c"

void main()
{
	int i, count = 0;
	unsigned char p_text[512] = { 0, };
	unsigned char c_text[512] = { 0, }, d_text[512] = { 0, };

	// �� �Է�
	printf("* ���Է� : ");
	gets(p_text);
	printf("\n");

	RSA_Enc(p_text, c_text); //RSA ��ȣȭ

							 // ��ȣ�� ���
	printf("* ��ȣ�� *\n");
	for (i = 0; i < B_S; i++)
		printf("%c", c_text[i]);

	printf("\n\nThe encryption is completed.\n\n");

	RSA_Dec(c_text, d_text); //RSA ��ȣȭ

							 // ��ȣ�� ���
	printf("* ��ȣ�� *\n");
	for (i = 0; i < (int)strlen((char*)d_text); i++)
		printf("%c", d_text[i]);
	printf("\n");

	printf("\nThe decryption is completed.\n");
}

//RSA ��ȣȭ
void RSA_Enc(unsigned char* p_text, unsigned char* result)
{
	int i, count = 0;
	short check = 1;
	FILE* fptr;

	//�������� ���� Ű ������ ����
	if ((fptr = fopen("public_key2.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}

	//���Ϸκ��� ���� Ű e�� ���� n�� �����Ѵ�
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x", &N[i]);
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x", &E[i]);

	fclose(fptr);

	//���� ��� ��ȣȭ �� ������
	//117����Ʈ�� ��ȣ�� �����Ѵ�(11 ����Ʈ = �е�)
	while (check == 1)
	{
		//���� �о� ���� ���·� �����Ѵ�
		check = get_from_message(p_text + count*DATA_LEN, h, DATA_LEN);

		//��ȣȭ�� ���� �ִ� ���
		if (check != -1)
		{
			CONV_B_to_O(h, DATA, DATA_LEN); //���� ���� octet���� ��ȯ

											/* OAEP ��ȣ�� ���� �е�( [00|02|PS|00|DATA] ) */
			rand_g(ps, LEN_PS * 8); //�е� ��Ʈ������ ����� ���� �� ����
			CONV_B_to_O(ps, O_PS, LEN_PS); //������ ���� ���� ���� octet���� ��ȯ

			EB[mb * 4 - 1] = 0x00;
			EB[mb * 4 - 2] = 0x02;

			for (i = mb * 4 - 3; i > DATA_LEN; i--)
				EB[i] = O_PS[i - DATA_LEN - 1];

			EB[DATA_LEN] = 0x00;

			for (i = DATA_LEN - 1; i >= 0; i--)
				EB[i] = DATA[i];

			for (i = mb * 4 - 1; i > 0; i = i - 4)
				EB1[i / 4] = (EB[i] << (DHEX - OCT)) + (EB[i - 1] << (OCT + OCT)) + (EB[i - 2] << OCT) + EB[i - 3];
			/* ��ȣ�� ���� �е� ���� */


			/*** c = m^e mod n (m-bit) ***/
			LeftTORight_Pow(EB1, E, S, N, mb); //�������� ���� Ű�� ��ȣȭ

		 //Radix ������ ��ȣ���� ���� ���·� ��ȯ
			CONV_R_to_B(S, s, mb);

			//���� ������ ��ȣ���� ����Ʈ ���·� ��ȯ�Ͽ� ����
			put_to_message(result + count*B_S, s, B_S);

			count++;
		}
	}
}

//RSA ��ȣȭ
void RSA_Dec(unsigned char* c_text, unsigned char* result)
{
	int i, count = 0;
	short check = 1;
	FILE* fptr;

	//������� ���Ű ������ ����
	if ((fptr = fopen("secret_key2.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}

	//���Ϸκ��� ���� Ű d�� ���� n�� �����Ѵ�
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &N[i]);
	for (i = mb - 1; i >= 0; i--)	fscanf(fptr, "%I64x ", &D[i]);

	fclose(fptr);

	//��ȣ���� ��� ��ȣȭ �� ������
	//128 ����Ʈ�� ��ȣ�� �����Ѵ�(11����Ʈ = �е� ����)
	while (check == 1)
	{
		//��ȣ���� �о� ���� ���·� �����Ѵ�
		check = get_from_message(c_text + count*B_S, s, B_S);

		if (check != -1)
		{
			CONV_B_to_R(s, S, mb); //���� ������ ��ȣ���� Radix�� ��ȯ

								   /*** m= c^d mod n (m-bit) ***/
			LeftTORight_Pow(S, D, H, N, mb); //������� ���Ű�� ��ȣȭ


			CONV_R_to_B(H, v_h, mb); //��ȣȭ�� �����͸� ���� ���·� ��ȯ
			CONV_B_to_O(v_h, D_EB, mb * 4); //���������� �����͸� octet���� ��ȯ

											//�е��� ������ ��ȣ���� �����Ѵ�
			for (i = DATA_LEN - 1; i >= 0; i--)
				D_DATA[i] = D_EB[i];

			//������ ��ȣ���� ���� ���·� ��ȯ
			CONV_O_to_B(D_DATA, d_d, DATA_LEN);
			//���� ������ ��ȣ���� ����Ʈ ���·� �����Ѵ�
			put_to_message(result + count*DATA_LEN, d_d, DATA_LEN);

			count++;
		}
	}
}

//�޽����� �о� ���� ���·� ����
int get_from_message(unsigned char* msg, short *a, short mn)
{
	register int i, j;
	short flag = 1, cnt = 0, mm;
	unsigned char b[m / Char_NUM] = { 0, };

	mm = mn*Char_NUM;

	//�ʱ�ȭ
	for (i = 0; i < mm; i++)
		a[i] = 0;

	//�޽��� ���ۿ��� �� ����Ʈ�� �д´�
	for (i = 0; i < mn; i++)
	{
		if (msg[i] == '\0')
		{
			if (i == 0)
				return -1;

			if (mn < B_S)
			{
				flag = 0;
				break;
			}
		}

		b[i] = msg[i];
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

//���� ������ �����͸� ����Ʈ ���·� ����
void put_to_message(unsigned char* msg, short *a, short mn)
{
	register i, j;
	short cnt = 0;
	unsigned char b[m / Char_NUM] = { 0, };
	unsigned char mask[Char_NUM] = { 0x01,0x02,0x04,0x08,
		0x10,0x20,0x40,0x80 };
	
	cnt = 0;
	//���� ������ �����͸� ����Ʈ ���·� ��ȯ�Ѵ�
	for (i = mn - 1; i >= 0; i--)
	{
		for (j = 0; j < Char_NUM; j++)
		{
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	//��ȯ�� �����͸� �޽��� ���ۿ� �����Ѵ�
	for (i = 0; i < mn; i++)
		msg[i] = b[i];
}