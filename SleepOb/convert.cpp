#include <iostream>
#include <fstream>
#include <iomanip>
#include"common.h"
using namespace std;


void saveToFile(const char* filename, unsigned char* data, size_t len) {
    ofstream outFile(filename);
    if (outFile.is_open()) {
        for (size_t i = 0; i < len; i++) {
            outFile << "\\x" << hex << setw(2) << setfill('0') << (int)data[i];
        }
        outFile.close();
    }
    else {
        cout << "Unable to open file" << endl;
    }
}

//int main() {
//    unsigned char mychar[] = "your shellcode here";
//    size_t len = sizeof(mychar) - 1; 
//
//    unsigned char key = 0xAB;
//
//    xor_encrypt_decrypt(mychar, len, key);
//    saveToFile("encrypted.txt", mychar, len);
//    printf("write done to encrypted.txt");
//
//    return 0;
//}
