#include <iostream>

#include <privmx/crypto/Crypto.hpp>

using namespace std;
using privmx::crypto::Crypto;

int main(){

    string key = Crypto::randomBytes(32);
    string data = Crypto::randomBytes(5*1024*1024);
    string data_encrypted;

    int n = 100;

    for(int i = 0; i < n; i++){
        string tmp(data);
        string tmp2(key);
        data_encrypted = Crypto::aes256EcbEncrypt(data, key);
    }

    string data_decrypted = Crypto::aes256EcbDecrypt(data_encrypted, key);

    cout << (data == data_decrypted) << endl;

    return 0;
}