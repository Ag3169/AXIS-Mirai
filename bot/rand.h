#ifndef _RAND_H
#define _RAND_H

#include "includes.h"

void rand_init(void);
uint32_t rand_next(void);
void rand_str(char *, int);
void rand_alpha_str(char *, int);

#endif
