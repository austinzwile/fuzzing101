// clang -fPIC -shared -o libcheck_password.so check_password.c
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_password(const char* input) {
	if (input[0] == 'f') {
		if (input[1] == 'u') {
			if (input[2] == 'z') {
				if (input[3] == 'z') {
					if (input[4] == '!') {
                        char* buf = malloc(8);;
                        strcpy(buf, input + 5);
						return 1;
					}
				}
			}
		}
	}
	return 0;
}
