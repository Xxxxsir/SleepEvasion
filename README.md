## Languages: [English](README.md) | [中文](README_zh.md)

I created this tool to simulated Red-Blue Team attack and defense exercise.Therefore, this tool is only for study and research purpose!
The implementation of this tool's function is based on EKKO's work [@5pider](https://github.com/Cracked5pider/Ekko),thanks him for the nice code :)

### Note
- Sleep obfuscation technique used in the code uses **CreateTimerQueueTimer** Win32 API.
- We used customed **XOR** crypt method to encrypt the running image.
- We provide a **remote loading function** to get access to the shellcode,but we didn't use it in this process due to the unconcealness.

### Highlight
- We provide a **thorough pipeline** that execute the shellcode from start-to-end
- We only encrypted the **specific sections** of the PE file to make it harder to be detected
- We used the **SDDL**(Security Descriptor Definition Language) to prevent the process being detected by memory scan process
- The technique is proved to be efficient and reliable that can **bypass the mainstream anti-virus app**
- We provide the **whole Visual Studio Project** which makes it easy for you to compile

### Usage
First,you are supposed to get the encrypt step done before building the project,you may use the xor method we provided as demonstrated below:
```cpp
void xor_encrypt_decrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```
After you generated your encrypted shellcode string,replace the shellcode and the key in ```rop.cpp``` with it as below:
```
unsigned char mychar[] = "Your shellcode after encrypted";
unsigned char key = Your KEY;
```
Then you can start build the project
### Disclaimer
This tool is only for cybersecurity education and research. It is prohibited to use it in illegal ways. I am not responsible for any actions and/or damages caused by your use or dissemination of this software. You take full responsibility for any actions you take using this software and acknowledge that this software is only for educational and research purposes. By downloading this software or the source code of the software, you automatically agree to the above.

### Credits
https://github.com/Cracked5pider/Ekko