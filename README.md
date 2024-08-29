The implementation of this tool's function is based on EKKO's work @5pider,thanks him for the nice code :)

### Note:
- Sleep obfuscation technique used in the code uses **CreateTimerQueueTimer** Win32 API.
- We used customed **XOR** crypt method to encrypt the running image.
- We provide a **remote loading function** to get access to the shellcode,but we didn't use it in this process due to the unconcealness.

### Highlight:
- We provide a **thorough pipeline** that execute the shellcode from start-to-end
- We only encrypted the **specific sections** of the PE file to make it harder to be detected
- We used the **SDDL**(Security Descriptor Definition Language) to prevent the process being detected by memory scan process
- The technique is proved to be efficient and reliable that can **bypass the mainstream anti-virus app**
- We provide the **whole Visual Studio Project** which makes it easy for you to compile
