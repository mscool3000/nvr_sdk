/*
字符"a"-"z","A"-"Z","0"-"9",".","-","*"和"_"都不会被编码，维持原值
空格" "被转换为"+"
其他每个字节都会被表示成"%xy"格式的由3个字符组成的字符串，编码为UTF-8
*/
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "nc_nvr_urlEncode.h"

static unsigned char hexchars[] = "0123456789ABCDEF";

static int nc_nvr_htoi(char *s)
{
    int value;
    int c;

    c = ((unsigned char *)s)[0];
    if (isupper(c))
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}


char *nc_nvr_url_encode(char const *s, int len, int *new_length)
{
    register unsigned char c;
    unsigned char *to = NULL, *start = NULL;
    unsigned char const *from, *end;

    from = (unsigned char *)s;
    end  = (unsigned char *)s + len;
    start = to = (unsigned char *) calloc(1, 3*len+1);
    if(start == NULL)
        return NULL;

    while (from < end)
    {
        c = *from++;

        if (c == ' ')
        {
            *to++ = '+';
        }
        else if ((c < '0' && c != '-' && c != '.') ||
                 (c < 'A' && c > '9') ||
                 (c > 'Z' && c < 'a' && c != '_') ||
                 (c > 'z'))
        {
            to[0] = '%';
            to[1] = hexchars[c >> 4];
            to[2] = hexchars[c & 15];
            to += 3;
        }
        else
        {
            *to++ = c;
        }
    }
    *to = 0;
    if (new_length)
    {
        *new_length = to - start;
    }
    return (char *) start;
}


int nc_nvr_url_decode(char *str, int len)
{
    char *dest = str;
    char *data = str;

    while (len--)
    {
        if (*data == '+')
        {
            *dest = ' ';
        }
        else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2)))
        {
            *dest = (char) nc_nvr_htoi(data + 1);
            data += 2;
            len -= 2;
        }
        else
        {
            *dest = *data;
        }
        data++;
        dest++;
    }
    *dest = '\0';
    return dest - str;
}
