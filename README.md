# Simple-Exe-Packing
本项目介绍最简单的32位exe程序加壳流程。本来是在寒假就已经写好了很大一部分代码，但是由于vs属性配置不起作用的原因，导致写的shellcode没法使用，也是最近才解决掉这个问题。

通过编写一个壳，可以对pe结构和程序执行过程有更深入的了解，而且这个壳的思路都是最简单的一种，只要shellcode厉害，壳就可以更能隐藏程序的信息。
## 前置知识 ##

### PE结构 ###
对pe结构体还是必须要有个大概的了解，不说能背，至少在peview工具中看到名称知道一些关机的结构体和其成员代表什么需要知道，还有exe在内存和在磁盘的区别已经如何转换。特别是对于IMAGE_EXPORT_DIRECTORY导出表和IMAGE_BASE_RELOCATION重定位表，实际上我在Windows-Hack-Programming的编程练习中，已经对这个很熟悉了。IMAGE_EXPORT_DIRECTORY导出表可能还没提到过，一般就是dll程序的导出函数的信息存储地方，由于我们要编写shellcode，所以需要获得kernel32.dll的一些导出函数，需要用到这个表。

### 如何编写shellcode ###
首先shellcode是可以在其他设备(windows)上也可以直接使用的，因为不会涉及到全局变量，并且调用的函数也必须是从kernel32.dll中直接寻找到，这是因为重定位的关系，程序加载的api函数的地址都是不固定的，一般是先找到GetProcAddress和GetModuleHandle和LoadLibrary，这样就可以基本上获取到其他所有函数。

通过peb获取kernel32基址：
[https://bbs.pediy.com/thread-266678.htm?msclkid=51ec2fddaf6711ec9ca04b75cc507387](https://bbs.pediy.com/thread-266678.htm?msclkid=51ec2fddaf6711ec9ca04b75cc507387)
### 解决vs的栈检测和优化 ###
在关闭了vs的安全检测和优化后，还是发现了栈检测的问题，并且在release编译环境下，仍可能会将简单的异或运算进行优化，优化为128bit的异或运算，并且将异或值设置为全局变量。最后的解决方法就是使用Debug模式编译，然后在ida中手动删除掉其中的栈检测汇编代码。

## 加壳思路 ##
算是最基础的一种加壳思路了。

- 添加一个节区，用来装载解密.text节区的shellcode。
- 加密.text节区，实际上应该还可以加密.idata节区。
- 编写shellcode，用来解密.text节区。
- 将shellcode写入添加的节区。

当然，shellcode的编写需要另外写一个项目。

## 成品实验 ##
The_Itach1.exe是一个弹窗程序。
![](https://s2.loli.net/2022/03/30/RJUAqT9iSC7HtZ1.png)
然后加壳生成test_shell.exe，运行一下。
![](https://s2.loli.net/2022/03/30/8hkiFbqMy5E73uC.png)
可以看到，仍然正常运行。

## 总结 ##
上面没有详细的讲解过程，但是看代码应该就完全可以明白了，而且这是最简单的一种壳的实现方式，如果shellcode写的更好，完全可以做到像upx壳完全隐藏原文件信息，将原文件信息和解密代码都放在upx1的节区中。可以通过编写一个壳来熟悉PE结构。
