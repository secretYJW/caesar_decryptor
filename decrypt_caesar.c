#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAXCHAR 5000 + 1 // 문장이 들어갈 수 있는 최대 크기
#define MAXALPHA 26 	// 알파뱃의 갯수

// 문자별 가중치
const float valueOfChar[] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
		0.772, 4.025, 2.406, 6.749, 7.607, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360,
		0.150, 1.974, 0.074};

// 기준이 되는 문자와 최다 빈도 문자의 차로 복호화하여 문자마다의 가중치값의 
struct Weight_object
{
	char letter;	// 기준이 되는 문자
	float value;	// 문자별 가중치 값
	float score;		// 처리를 한 후의 가중치 총합
};

// 평문을 암호화하는 함수 - key값을 리턴
int Encrypt_text(char *text_buf, char *encrypt_buf, size_t length);
// 암호화된 문장을 복호화하는 함수
void Decrypt_text(const char *encrypt_text, char *decrypt_buf, int key, size_t length);
// 통계를 이용한 최다 빈도수 고려 통계 공격
void Brute_attack(const char *encrypt_text, size_t length);
// 가중치를 적용한 Brute_attack
void Weight_attack(const char *encrypt_text, size_t length);
// 문장 성분을 이용하여 그 문장이 정상적인 문장인지를 판별해줌
void CheckString(const char *text, size_t length);
// 문장에서 최다 빈도수의 단어 리턴(소문자로)
char GetMostLetter(const char *text, size_t length);
// Weight list를 생성해주는 함수
struct Weight_object *MakeWeightList();
// Weight_object의 문자와 최다 빈도 문자를 넣으면 그 값과 최다 빈도 문자와의 차를 키로하여 복호화 한다.
// 복호화된 문장에서 문자마다의 가중치값을 계산한 후 그 가중치값들의 총합을 리턴해준다.
float GetSumOfWeight(const char *encrypt_text, size_t length, char key_letter, char most_letter);
// 문자열에서 그 문자가 몇번 나오는지 구해서 리턴
int GetSumOfChar(const char *text, char letter);
// qsort를 위한 비교 함수
int compare(const void *arg1, const void *arg2);

int main(int argc, char **agv)
{
	int len = 0; // 문자열 길이
	int key;
	char input_str[MAXCHAR];
	char encrypt_str[MAXCHAR];
	char decrypt_buf[MAXCHAR];	// 복호화 된 문장이 들어갈 버퍼

	memset(input_str, '\0', MAXCHAR);
	memset(encrypt_str, '\0', MAXCHAR);
	memset(decrypt_buf, '\0', MAXCHAR);

	printf("Please input your text: ");
	scanf("%[^\n]", input_str);

	key = Encrypt_text(input_str, encrypt_str, strlen(input_str));
	len = strlen(encrypt_str);

	Decrypt_text(encrypt_str, decrypt_buf, key, len);

	//printf("plain: %s, most_letter: %c\n", input_str, GetMostLetter(input_str, len));
	//printf("encrypt: %s, len:%d key:%d, most_letter: %c\n", encrypt_str, len, key, GetMostLetter(encrypt_str, len));
	//printf("decrypt: %s\n", decrypt_buf);
	//Brute_attack(encrypt_str, len);
	Weight_attack(encrypt_str, len);

	return 0;
}

// 평문을 암호화하는 함수
int Encrypt_text(char *text_buf, char *encrypt_buf, size_t length)
{
	int i;
	char char_buf;
	int key, temp;

	srand((unsigned)time(NULL));
	key = rand() % 30; // key값 생성

	/* 배열을 순회하면서 문자열을 암호화 함 */
	for (i = 0; i < length; i++)
	{
		char_buf = text_buf[i];
		temp = key; // 연산을 위하여 temp로 key값을 옮김

		if (!isalpha(char_buf))		/* 알파벳이 아니므로 무시 */
		{
			encrypt_buf[i] = char_buf;
			continue;
		} 
		else if (islower(char_buf))	/* 소문자인 경우 */
		{
			temp = (char_buf - 'a' + key) % MAXALPHA; /* 알파벳이 26개 이므로 mod연산 */
			encrypt_buf[i] = temp + 'a';	/* 'a'만큼 뺐으므로 다시 더해준다 */
		}
		else if (isupper(char_buf)) /* 대문자인 경우 */
		{
			temp = (char_buf - 'A' + key) % MAXALPHA;
			encrypt_buf[i] = temp + 'A';
		}
	}

	return key;
}

// 암호화된 문장을 복호화하는 함수
void Decrypt_text(const char *encrypt_text, char *decrypt_buf, int key, size_t length)
{
	int i;
	int char_buf, temp;

	/* 배열을 순회하면서 문자열을 복호화 함 */
	for (i = 0; i < length; i++)
	{
		char_buf = encrypt_text[i];

		if (!isalpha(char_buf))		/* 알파벳이 아니므로 무시 */
		{
			decrypt_buf[i] = char_buf;
			continue;
		} 
		else if (islower(char_buf))	/* 소문자인 경우 */
		{
			temp = (char_buf - 'a' - key) % MAXALPHA;
			if (temp < 0)
				decrypt_buf[i] = 'z' + temp + 1; 
			else
				decrypt_buf[i] = temp + 'a';	/* 'a'만큼 뺐으므로 다시 더해준다 */
		}
		else if (isupper(char_buf)) /* 대문자인 경우 */
		{
			temp = (char_buf - 'A' - key) % MAXALPHA;
			if (temp < 0)
				decrypt_buf[i] = 'Z' + temp + 1;
			else
				decrypt_buf[i] = temp + 'A';
		}
	}
}

// 통계를 이용한 최다 빈도수 고려 통계 공격
void Brute_attack(const char *encrypt_text, size_t length)
{
	int i, gap;
	char flag;
	char pri_list[] = {'e', 't', 'a', 'o', 'i'};	// 영문장에서 나오는 문자 빈도의 우선순위
	char most_letter = GetMostLetter(encrypt_text, length); /* 최다 빈도수의 문자 리턴받음 */
	char decrypt_buf[MAXCHAR]; // 복호화 된 문장이 들어갈 버퍼

	memset(decrypt_buf, '\0', MAXCHAR);

	// 처리
	for (i = 0; i < sizeof(pri_list) / sizeof(char); i++)
	{
		gap = most_letter - pri_list[i]; 	// 최빈 문자와 리스트의 문자와의 차
		Decrypt_text(encrypt_text, decrypt_buf, gap, length);
		printf("%c로 복호화 한 결과 입니다.\n>>%s\n", pri_list[i], decrypt_buf);
		printf("\n> 의미있는 문장입니까?[Y/N]: ");
		while( getchar() != '\n' );  /* 버퍼를 비운다 */
		scanf("%c", &flag);
		if (flag == 'Y' || flag == 'y')
		{
			printf("> 종료합니다.\n");
			return;
		}
		else
			continue;
	}
	gap = most_letter - 't';
	Decrypt_text(encrypt_text, decrypt_buf, gap, length);
	printf("\n%s\n> 종료합니다.\n", decrypt_buf);
}

// 가중치를 적용한 Brute_attack
void Weight_attack(const char *encrypt_text, size_t length)
{
	int i;
	char flag;
	char most_letter = GetMostLetter(encrypt_text, length);	// 최다 빈도수의 문자 리턴 받음
	//float Weight_score_list[26];	// 문자별로 복호화된 문장의 가중치 점수를 가지고 있는 리스트
	struct Weight_object *Weight_list; // 가중치를 적용한 리스트
	char decrypt_buf[MAXCHAR]; // 복호화 된 문장이 들어갈 버퍼

	memset(decrypt_buf, '\0', MAXCHAR);

	Weight_list = MakeWeightList(); // 통계 자료를 이용해 문자별 가중치 리스트를 만들어줌

	/* 모든 문자를 이용하여 가중치 점수 리스트를 채움 */
	for (i = 0; i < MAXALPHA; i++)
		Weight_list[i].score = GetSumOfWeight(encrypt_text, length, Weight_list[i].letter, most_letter);

	/* 가중치를 적용한 리스트를 높은 점수순으로 정렬한다. */
	qsort(Weight_list, MAXALPHA, sizeof(struct Weight_object), compare);

	/*
	for (i = 0; i < MAXALPHA; i++)
	printf("letter: %c, value: %.2f, score: %.2f\n", Weight_list[i].letter, Weight_list[i].value, Weight_list[i].score);
	*/

	Decrypt_text(encrypt_text, decrypt_buf, most_letter - Weight_list[0].letter, length);

	printf("\n> 아마 당신이 찾는 것은 아래의 복호화된 문자열일겁니다. 맞습니까?[Y/N]\n");
	printf("%s\n>>> ", decrypt_buf);
	while( getchar() != '\n' );  /* 버퍼를 비운다 */
	scanf("%c", &flag);

	if (flag == 'Y' || flag == 'y')
	{
		printf("> 종료합니다.\n");
		exit(0);
	}
	else
	{
		printf("> 오, 아마 당신의 문장은 너무 짧거나, 의미를 가지지 않은 것 같습니다.\n");
		printf("> 다음의 작업으로 알 가능성이 적지만 한번 시도해봅시다.\n\n");
		Brute_attack(encrypt_text, length);
	}

	free(Weight_list);
}

// 문장 성분을 이용하여 그 문장이 정상적인 문장인지를 판별해줌
void CheckString(const char *text, size_t length)
{

}

// 문장에서 최다 빈도수의 단어 리턴(소문자로)
char GetMostLetter(const char *text, size_t length)
{
	int i, most, most_idx;
	char l_alpha[MAXALPHA] = {0, };
	char u_alpha[MAXALPHA] = {0, };

	for (i = 0; i < length; i++)
	{
		/* 소문자인 경우와 대문자인 경우 각각의 카운트를 늘려준다 */
		if (islower(text[i]))
			l_alpha[text[i] - 'a']++;
		else if (isupper(text[i]))
			u_alpha[text[i] - 'A']++;
	}

	most = most_idx = 0;
	for (i = 0; i < MAXALPHA; i ++)
	{
		if (l_alpha[i] + u_alpha[i] > most)
		{
			most = l_alpha[i] + u_alpha[i];
			most_idx = i;
		}
	}

	return most_idx + 'a'; /* 소문자로 리턴 */
}

// Weight list를 생성해주는 함수(소문자로 처리)
struct Weight_object *MakeWeightList()
{
	int i;
	struct Weight_object *Weight_list;

	/* 리스트에 메모리를 할당해줌 */
	Weight_list = (struct Weight_object *)malloc(sizeof(struct Weight_object) * MAXALPHA);

	/* 빈 리스트를 순회하면서 값들을 채워줌 */
	for (i = 0; i < MAXALPHA; i++)
	{
		Weight_list[i].letter = i + 'a';
		Weight_list[i].value  = valueOfChar[i];
		Weight_list[i].score  = 0;
	}

	return Weight_list;
}

// Weight_object의 문자와 최다 빈도 문자를 넣으면 그 값과 최다 빈도 문자와의 차를 키로하여 복호화 한다.
// 복호화된 문장에서 문자마다의 가중치값을 계산한 후 그 가중치값들의 총합을 리턴해준다.
float GetSumOfWeight(const char *encrypt_text, size_t length, char key_letter, char most_letter)
{
	int i, gap, temp;
	float sum = 0;
	char decrypt_buf[MAXCHAR]; 

	memset(decrypt_buf, '\0', MAXCHAR);

	gap = most_letter - key_letter;	// 문자와의 차를 구해서 키를 구함
	Decrypt_text(encrypt_text, decrypt_buf, gap, length);
	//printf("###%s\n", decrypt_buf);

	// 문장의 가중치 계산
	for (i = 0; i < MAXALPHA; i++)
	{
		temp = GetSumOfChar(decrypt_buf, i + 'a') + GetSumOfChar(decrypt_buf, i + 'A');
		sum += temp * valueOfChar[i];
	}

	return sum;
}

// 문자열에서 그 문자가 몇번 나오는지 구해서 리턴
int GetSumOfChar(const char *text, char letter)
{
	int i;
	int cnt = 0;

	for (i = 0; i < strlen(text); i++)
		if (text[i] == letter)
			cnt++;

	return cnt;
}

// qsort를 위한 비교 함수
int compare(const void *arg1, const void *arg2)
{
	float v1, v2;

	v1 = ((struct Weight_object*)arg1)->score;
	v2 = ((struct Weight_object*)arg2)->score;

	if (v1 > v2) return -1;
	else if (v1 == v2) return 0;
	else return 1;
}