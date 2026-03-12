/*
 * Production Botnet Loader - Utility Functions Header
 */

#ifndef _LOADER_UTIL_H
#define _LOADER_UTIL_H

#include <ctype.h>
#include <stdbool.h>

/* Type definitions */
typedef bool BOOL;
#define TRUE true
#define FALSE false

/* Function declarations */
int util_strlen(char *str);
char *util_stristr(char *haystack, int haystack_len, char *needle);
char *util_trim(char *str);

#endif
