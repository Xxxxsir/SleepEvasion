#include <Windows.h>
#include <stdio.h>
#include <Sddl.h>
#include"common.h"

void SetProcessSecurityDescriptor() {
   
    LPCWSTR sddl = L"D:P"
        L"(D;OICI;GA;;;WD)"  // Deny all access to the "World" (Everyone)
        L"(A;OICI;GA;;;SY)"  // Allow all access to the "System"
        L"(A;OICI;GA;;;OW)"; // Allow all access to the process "Owner"

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;


    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        printf("\n fail convert");
        return;
    }


    if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, securityDescriptor)) {
        printf("\n fail set");
    }

    // Free the security descriptor
    LocalFree(securityDescriptor);
}


int main() {
    FreeConsole();
    
    SetProcessSecurityDescriptor();

    ropOb(40000);

    return 0;
}