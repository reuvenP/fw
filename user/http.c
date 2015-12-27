#include "http.h"

int search_str(unsigned char* buffer, char* str)
{
	int buf_len, str_len, i, j, offset;
	buf_len = strlen(buffer);
	str_len = strlen(str);
	for (i = 0, j = 0; i < buf_len; i++)
	{
		if (buffer[i] == str[j])
		{
			
		}
	}
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
