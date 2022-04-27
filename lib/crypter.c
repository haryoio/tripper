#define _GNU_SOURCE

#include<crypt.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define NAMELEN 10

char* crypter (char *key, char *salt) {
    struct crypt_data data;
    data.initialized = 0;

    char* crypted = crypt_r(key, salt, &data);
    return crypted;
}

char* get_last(char*s) {
    char *subtext = (char*)malloc(sizeof(char) * NAMELEN+1);
    int len = strlen(s) - NAMELEN;
    strncpy(subtext, &s[len], NAMELEN);
    subtext[NAMELEN] = '\0';
    return subtext;
}

void main() {
    char *key = "aaaaaaaa";
    char *salt = "aa";
    // char *a = crypter(key, salt);
    char *l = crypter(key,salt);
    printf("%s\n", l);
    // printf("%s\n", a);
}
