#pragma once

#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include<iostream>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

void xor_encrypt_decrypt(unsigned char* data, size_t len, unsigned char key);
VOID ropOb(DWORD SleepTime);
