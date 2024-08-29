## Languages: [English](README.md) | [中文](README_zh.md)

我创建了这个工具来模拟红蓝队的进攻和防御演习。因此，这个工具仅用于学习和研究目的的！
这个工具功能的实现基于 EKKO 的工作 [@5pider](https://github.com/Cracked5pider/Ekko)，感谢他提供了优秀的代码 :)

### 注意
- 代码中使用的 **Sleep 混淆技术** 采用了 **CreateTimerQueueTimer** 的 Win32 API。
- 我们使用了自定义的 **XOR 加密方法** 对运行中的镜像进行了加密。
- 我们提供了一个 **远程加载功能** 以便访问 shellcode，但由于不够隐蔽，我们在这个过程中并未使用它。

### 亮点
- 我们提供了一个 **完整的实现**，可以从头到尾执行您的 shellcode。
- 我们只加密了 PE 文件的 **特定部分**，以增加被检测的难度。
- 我们使用了 **SDDL**（安全描述符定义语言）来防止进程被内存扫描检测到。
- 这种技术已被证明高效且可靠，可以 **绕过主流的杀毒软件**。
- 我们提供了 **完整的 Visual Studio 项目**，便于您编译。

### 使用方式
首先，您应该在构建项目之前完成加密步骤，您可以使用我们提供的 xor 方法，如下所示：
```cpp
void xor_encrypt_decrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```
生成加密的 shellcode 字符串后，用它替换```rop.cpp```中的 shellcode 和密钥，如下所示：
```
unsigned char mychar[] = "Your shellcode after encrypted";
unsigned char key = Your KEY;
```
然后，您可以开始构建您的VS工程
### 免责声明
该工具仅用于网络安全教育和研究，禁止用于非法途径，我对您由使用或传播等由此软件引起的任何行为和/或损害不承担任何责任。您对使用此软件的任何行为承担全部责任，并承认此软件仅用于教育和研究目的。下载本软件或软件的源代码，您自动同意上述内容。

### 致谢
https://github.com/Cracked5pider/Ekko