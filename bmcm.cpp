#include <iostream>
#include <algorithm>
#include <string>
#include <bitset>
#include <time.h>
#include <Windows.h>
using namespace std;
#define SIZE 256
typedef unsigned char Byte;
using uint = unsigned int;
#pragma warning(disable:4996);
#define P_SIZE	320000000
#define P_SIZE1 110000000
double scanned = 0;
int nTime = 0;
clock_t tmAfter;
clock_t tmBefore;

typedef struct
{
	Byte cplen;
	unsigned short cpdist;
}CompressData;

typedef struct
{
	unsigned short inst;
	unsigned short cplen;
	unsigned short cpdist;
}InsertCopy;

int matched = 0;
//char patFile[] = "shakespeare.txt";
//char patFile[] = "snort.txt";

void CharToCompressData(unsigned char* tmp_cpData, CompressData* cpData, int length)
{
	int i;
	int k = 0;
	for (i = 0; i < length; i += 3)
	{
		cpData[k].cplen = tmp_cpData[i];
		cpData[k].cpdist = *(unsigned short*)&tmp_cpData[i + 1];
		k++;
	}
}
void memcpy1(unsigned char* dst, unsigned char* src, int size)
{
	int i = 0;
	while (i < size)
	{
		*dst = *src;
		dst++;
		src++;
		i++;
	}
}
void gbadchar(char* p, int m, int* badchar)
{
	int i;
	int ascii;
	for (i = 0; i < SIZE; i++)
		badchar[i] = -1;
	for (i = 0; i < m; i++)
	{
		ascii = int(p[i]);
		badchar[ascii] = i;
	}
}
void gbadcharh(char* p, int m, int* badchar)
{
	int i;
	for (i = 0; i < SIZE; i++)
		badchar[i] = m;
	for (i = 0; i < m - 1; i++) {
		badchar[p[i]] = m - i - 1;
	}
}
void gGS(char* p, int m, int* suffix, bool* prefix)
{
	int i, j;
	for (i = 0; i < m; i++)
	{
		suffix[i] = -1;
		prefix[i] = false;
	}
	for (i = 0; i < m - 1; i++)
	{
		for (j = 0; j < i + 1; j++)
		{
			if (p[i - j] == p[m - 1 - j])
				suffix[j + 1] = i - j;
			else
			{
				break;
			}
		}
		if (j == i + 1)
		{
			prefix[i + 1] = true;
		}
	}
}
int movebyGS(int j, int m, int* suffix, bool* prefix)
{
	int len = m - 1 - j;
	int r;
	if (suffix[len] != -1)
	{
		return(j + 1 - suffix[len]);
	}
	else
	{
		for (r = j + 2; r < m; r++)
		{
			if (prefix[m - r])
			{
				return r;
			}
		}
		return m;
	}
}
int match_bmh(int* badchar, unsigned char* buffer, char* p, int i, int m, unsigned char* idx)
{
	int movelen1, movelen2;
	int j, k;
	for (k = 0; k < m; k++)
	{
		if (buffer[i - k] != p[m - 1 - k])
		{
			break;
		}
	}
	idx[i] = k;
	if (k == m)
	{
		return 1;
	}
	movelen1 = badchar[buffer[i]];
	return movelen1;
}
int match_bm(bool* prefix, int* suffix, int* badchar, unsigned char* buffer, char* p, int i, int m, char* idx,int &flag)
{
	int movelen1, movelen2;
	int j, k;
	int shift;
	for (k = 0; k < m; k++)
	{
		if (buffer[i - k] != p[m - 1 - k])
		{
			scanned++;
			break;
		}
	}
	idx[i] = k;
	if (k == m)
	{
		flag = 1;
		matched++;
		return 1;
	}
	movelen1 = m - 1 - k - badchar[buffer[i - k]];
	movelen2 = 0;
	if (k > 0)
		movelen2 = movebyGS(m - 1 - k, m, suffix, prefix);
	shift = max(movelen1, movelen2);
	return shift;
}

int pre_scan(CompressData *cpData,int size,unsigned char *buffer,InsertCopy *iCopy)
{
	int i;
	int k = 0;//记录字符数量
	int countIc = 0;//记录InsertCopy数量
	unsigned short cpdist;
	unsigned short cplen;
	int countInsert = 0;//记录Insert数量

	for (i = 0; i < size; i++)
	{
		if (cpData[i].cpdist == 0)
		{
			buffer[k] = cpData[i].cplen;
			k++;
			countInsert++;
		}
		else
		{
			cplen = cpData[i].cplen + 3;
			cpdist = cpData[i].cpdist;
			memcpy1(buffer + k, buffer + k - cpdist, cplen);
			k = k + cplen;
			iCopy[countIc].inst = countInsert;
			iCopy[countIc].cplen = cplen;
			iCopy[countIc].cpdist = cpdist;
			countIc++;
			countInsert = 0;
		}
	}
	if (countInsert)
	{
		iCopy[countIc].inst = countInsert;
		iCopy[countIc].cplen = 0;
		iCopy[countIc].cpdist = 0;
	}
	return countIc;
}

void LoadPattern(char patList[][SIZE], char* strPatFile,int *patLength)
{
	FILE* pFile = fopen(strPatFile, "r");
	if (pFile == NULL)
	{
		printf("could not open pattern file\n");
		exit(0);
	}
	int i = 0;
	while (true)
	{
		if (fscanf(pFile, "%[^\n]\n", patList[i]) == -1)
			break;
		patLength[i] = strlen(patList[i]);
		i++;
	}
}

void str_bm(unsigned char *buffer,InsertCopy *iCopy,int icLength,char *pattern,int ptLength)
{
	int i;
	int j,k;
	int acc=0;//记录当前块其实位置
	int offset;
	int badchar[SIZE];
	char idx[P_SIZE];
	unsigned char shift[P_SIZE];
	memset(idx, -1, sizeof(idx));
	gbadchar(pattern, ptLength, badchar);
	int* suffix = new int[ptLength];
	bool* prefix = new bool[ptLength];
	unsigned short cpdist;
	unsigned short cplen;
	int cpbegin;
	int singleLength;
	int flag = 0;
	int jmpcnt = 0, cnt = 0;
	gGS(pattern, ptLength, suffix, prefix);
	j = ptLength - 1;
	tmBefore = GetTickCount();
	for (i = 0; i < icLength; i++)
	{
		offset = j - acc + 1;
		singleLength = iCopy[i].cplen + iCopy[i].inst;
		cplen = iCopy[i].cplen;
		cpdist = iCopy[i].cpdist;
		while (offset <= singleLength)
		{
			if (offset <= iCopy[i].inst)
			{
				shift[j] = match_bm(prefix, suffix, badchar, buffer, pattern, j, ptLength, idx,flag);
				j = j + shift[j];
			}
			else
			{
				/*if (j > 300000)
					printf("a");*/
				cnt++;
				if (idx[j - cpdist] == -1)
				{
					shift[j] = match_bm(prefix, suffix, badchar, buffer, pattern, j, ptLength, idx,flag);
					j = j + shift[j];
				}
				else
				{
					cpbegin = acc + iCopy[i].inst;
					if (j - idx[j - cpdist] >= cpbegin)
					{
						jmpcnt++;
						shift[j] = shift[j - cpdist];
						idx[j] = idx[j - cpdist];
						if (idx[j] == ptLength)
							matched++;
						if (j + shift[j] > singleLength||flag!=0)
						{
							j += shift[j];
						}
						else
						{
							j = acc + singleLength;
							break;
						}
					}
					else
					{
						shift[j] = match_bm(prefix, suffix, badchar, buffer, pattern, j, ptLength, idx,flag);
						j = j + shift[j];
						
					}
				}
			}
			offset = j - acc + 1;
		}
		acc = acc + singleLength;
	}
	//cout << jmpcnt * 1.0 / cnt<<endl;
	//printf("finish");
	tmAfter = GetTickCount();
	nTime += tmAfter - tmBefore;
	delete[]suffix;
	delete[]prefix;
}
int main()
{
	unsigned char tmp_cpData[P_SIZE];
	CompressData cpData[P_SIZE1];
	unsigned char buffer[P_SIZE];
	InsertCopy iCopy[P_SIZE1];
	int countIc;
	char p[100] = "father";//模式串
	char patList[250][SIZE];
	int patLength[250];
	clock_t start, stop;
	double duration1,duration2;
	int i;
	int set;
	int Pat_Num;
	double total;
	HANDLE hFile;
	LPCTSTR szFileName;
	char patFile[70];
	cin >> set;
	if (set == 1)
	{
		total = 112412800;
		szFileName = "Literature.lz";
		//szFileName = "middream.lz";
		Pat_Num = 226;
		strcpy(patFile, "snort.txt");
	}
	else if(set==2)
	{
		total = 74181025;
		szFileName = "acomtot.lz";
		Pat_Num = 226;
		strcpy(patFile, "snort.txt");
	}
	else if(set==3)
	{
		/*total = 1120484;
		szFileName = "acntot.lz";
		Pat_Num = 226;
		strcpy(patFile, "snort.txt");*/
		total = 113096549;
		szFileName = "Omicron.lz";
		Pat_Num = 100;
		strcpy(patFile, "rna2.txt");
	}
	else
	{
		total = 113096549;
		szFileName = "Omicron.lz";
		Pat_Num = 50;
		strcpy(patFile, "rna1.txt");
	}
	//LPCTSTR szFileName = "middream.lz";
	//LPCTSTR szFileName = "acomtot.lz";
	//int infoLength;
	uint dataLength;
	hFile = CreateFile(szFileName, GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	dataLength = GetFileSize(hFile, NULL);
	ReadFile(hFile, tmp_cpData, dataLength, NULL, NULL);
	CloseHandle(hFile);
	CharToCompressData(tmp_cpData, cpData, dataLength);
	LoadPattern(patList, patFile, patLength);
	start = clock();
	//nump = pre_scan(info, infoLength - 12, cploc);
	//str_bm(cpData, dataLength, p, 10, cploc, nump);
	countIc=pre_scan(cpData, dataLength / 3, buffer, iCopy);
	stop = clock();
	duration1= ((double)(stop - start)) / CLK_TCK;

	for (i = 0; i < Pat_Num; i++)
	{
		str_bm(buffer, iCopy, countIc, patList[i], patLength[i]);
		//cout <<matched << endl;
	}
	/*str_bm(buffer, iCopy, countIc, p, 6);*/
	/*for (i = 62; i < 63; i++)
	{
		str_bm(buffer, iCopy, countIc, patList[i], patLength[i]);
		cout << matched << endl;
	}*/

	cout << "matched=" << matched << endl;
	cout << "total=" << nTime<<endl;
	//dataLength= 34624044;
	cout << "Throughout=" << (double)dataLength*8*Pat_Num / (nTime)/1000<<"Mbps"<<endl;
	cout << "jmp ratio=" << 1 - scanned * 1.0 /(double) (total*Pat_Num);
	return 0;
}
//DNA:1150.01Mbps
//Literature:2245.52Mbps
