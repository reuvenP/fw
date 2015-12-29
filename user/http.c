#include "http.h"

int search_str(unsigned char* buffer, char* str)
{
	int buf_len, str_len, i, j, offset;
	buf_len = strlen((char*)buffer);
	str_len = strlen(str);
	if (str_len > buf_len)
		return -1;
	for (i = 0, j = 0, offset = 0; (i < buf_len && j < str_len);)
	{
		if (buffer[i] == str[j])
		{
			if (j == 0)
				offset = i;
			if (j == str_len - 1)
				return offset;
			else
			{
				i++;
				j++;
			}
		}
		else
		{
			if (j != 0)
			{
				i = offset + 1;
				j = 0;
			}
			else
			{
				i++;
			}
		}
	}
	return -1;
}

int inspect_http(unsigned char* buffer, int len)
{
	int i, j;	
	if (!buffer)
		return NF_DROP;
	for (i = 0, j = -1; i < len; i++) 
			{
				if (j == 7)
				{
					printf("%s", " ");
					j++;
				}
				else if (j == 15)
				{
					printf("%s", "\n");
					j = 0;
				}
				else
					j++;
				if (buffer[i] < 16)
					printf("0%x ", buffer[i]);
				else	
					printf("%x ", buffer[i]);	
			}
			fputc('\n', stdout);	
	return NF_ACCEPT;	
}
