#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t rdtsc() {
	uint64_t value;
	__asm__ __volatile__ (
        "xor %%rax, %%rax"			"\n\t"
        "cpuid"						"\n\t"
        "rdtsc"						"\n\t"
        : "=A" (value)
        :
        : "ebx", "ecx", "edx"
    );
	return value;
}

char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

struct Data {
    char c;
    uint64_t time;
};

int main(int argc, char** argv) {

    if(argc < 3) {
        printf("Arguments (string, int) required\n");
        exit(1);
    }

    char* test_str = argv[1];
    int index = strtol(argv[2], NULL, 10);
    if(index < 0 || index >= strlen(test_str)) {
        printf("Index out of bounds\n");
        exit(1);
    }

    char man_str[strlen(test_str) + 2];
    man_str[strlen(test_str)] = '-';
    man_str[strlen(test_str) + 1] = 0;
    strcpy(man_str, test_str);

    struct Data try = { 'x', 0 };

    for(int c = 0; c < strlen(chars); c++) {
        man_str[index] = chars[c];
        printf("%s\n", man_str);

        uint64_t start_time = rdtsc();
        volatile int _ = strcmp(test_str, man_str);
        uint64_t end_time = rdtsc();

        uint64_t cycles = end_time - start_time;
        printf("Char '%c' took %llu cycles\n", chars[c], cycles);

        if(cycles > try.time) {
            try.time = cycles;
            try.c = chars[c];
        }
    }

    printf("Most probable char: '%c'\n", try.c);
}
