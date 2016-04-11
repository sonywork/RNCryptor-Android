
#include <stdlib.h>
#include "debug.h"

void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
  char hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *result = (char *)malloc(binsz * 2 + 1);
  (*result)[binsz * 2] = 0;

  if (!binsz)
    return;

  for (i = 0; i < binsz; i++)
    {
      (*result)[i * 2 + 0] = hex_str[bin[i] >> 4  ];
      (*result)[i * 2 + 1] = hex_str[bin[i] & 0x0F];
    }
}

//the calling
//
//char buf[] = {0,1,10,11};
//char *result;
//
//bin_to_strhex((unsigned char *)buf, sizeof(buf), &result);
//printf("result : %s\n", result);
//free(result);
