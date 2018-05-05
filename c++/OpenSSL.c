//
//  main.cpp
//  Security
//
//  Created by 李雪峰 on 2018/5/5.
//  Copyright © 2018年 李雪峰. All rights reserved.
//

#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <map>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

# include <openssl/sm2.h>

unsigned char* unHex(const char * hexStr) {
    unsigned char* result = new unsigned char[strlen(hexStr)/2 + 1]();
    memset(result, '\0', strlen(hexStr)/2 + 1);
    std::map<char,int> maps {{'0', 0},{'1', 1},{'2', 2},{'3', 3},{'4', 4},{'5', 5},{'6', 6},{'7', 7},{'8', 8},{'9', 9},
        {'a', 10},{'b', 11},{'c', 12},{'d', 13},{'e', 14},{'f', 15},
        {'A', 10},{'B', 11},{'C', 12},{'D', 13},{'E', 14},{'F', 15}
    };

    unsigned char* ptr = result;
    for(int i = 0; i< strlen(hexStr); i+=2) {
        *ptr = ((maps[hexStr[i]] << 4) | (maps[hexStr[i+1]]));
        ptr++;
    }
    
    return result;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    EC_KEY *key = NULL;
    FILE *fp = NULL;
    if ((fp = fopen("/Users/lixf/c++/publicKey.pem", "r")) == NULL) {
        return 1;
    }
    key = EC_KEY_new();
    key = PEM_read_EC_PUBKEY(fp, &key, NULL, NULL);
    if (key == NULL) {
        return 1;
    }
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_GROUP_get_curve_GFp(group, p, a, b, NULL);
    char* p_hex = BN_bn2hex(p);
    char* a_hex = BN_bn2hex(a);
    char* b_hex = BN_bn2hex(b);
    
    printf("%s\n", p_hex);
    printf("%s\n", a_hex);
    printf("%s\n", b_hex);
    ECDSA_SIG *sig = NULL;
    int ok = -1;
    const char *userid = "1234567812345678";
    const char *message = "test sm3withsm2 content";
    const char *signResult_hex = "30460221008C42492EEA1E62A2DA073CC370CBA7A669606C8003DA7CC59388234BC2C8BC0F022100C8E6DDEA40488F5270142E7D37079A9D0597989E323FBB9B90EAFCA5987CAC48";
    unsigned char* signResult = unHex(signResult_hex);
    
    
    size_t signResult_len = strlen(signResult_hex)/2;
    const unsigned char* signData = signResult;
    
    size_t msg_len = strlen(message);
    sig = ECDSA_SIG_new();
    d2i_ECDSA_SIG(&sig, &signData, signResult_len);
    ok = SM2_do_verify(key, EVP_sm3(), sig, userid, (const uint8_t *)message, msg_len);
    
    fclose(fp);
    EC_KEY_free(key);

    std::cout << "Hello, World!\n";
    //sm2_sig_test();
    return 0;
}
