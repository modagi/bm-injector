Automatically exported from code.google.com/p/bm-injector

please send mail to me what you want to say. I'm waiting for you.

0. Before beginning

I appreciate some advice for this project. Code, thoughts, or any advice on how to project management are welcome. I have a blog. If you are a Korean, it would be better to visit my blog(http://boooooom.tistory.com)

1. Introduction

The biggest object of this project is to inject a DLL into a process. We use a variety of ways to achieve this object.

There are code injection and API hooking techniques as well as DLL injection technique in this project. Therefore, you must be in the know of them.

2. The functions of BM Injector

Perhaps it doesn't work sometimes. Until now, I tested it in Windows XP and 7. It doesn't support 64-bit yet. BM Injector currently has the following features that are implemented.

A. Inject the selected DLL into the selected process.

B. Inject the selected DLL into a child process of the selected process.

3. The implementation of BM Injector

A. Inject the selected DLL into the selected process.

It is implemented using CreateRemoteThread and NtCreateThreadEx API.

B. Inject the selected DLL into a child process of the selected process.

In order to inject the selected DLL into a child process of the selected process, we inject some code into the selected process. The injected code hook ZwResumeThread API of the selected process in order to inject the selected DLL into a child process. In summary, the following features are required.

(a) Inject the selected DLL into a child process.

(b) Inject (a) code into the selected process, and make it work .

First, look (a). It is very simple to implement. The selected process inject the selected DLL into a child process, at the point of running a child process. It is implemented using ZwResumeThread API hooking.

Implementation (b) is more complicated than implementation (a). This is generally implemented using CreateRemoteThread API. You write addresses of functions using WriteProcessMemory API to allocated memory by using VirtualAllocEx API. And the allocated addresses by using VirtualAllocEx API must be parameters of CreateRemoteThread API when you call it, in order to be used by injected codes. It is basic method of code injection.

It is possible to pass the addresses of functions that are used by the injected codes, when you execute the injected codes using the above mothod. But we need to think another case, ZwResumeThread API hooking. In this case, MyZwResumeThread function(jumped from hooked ZwResumeThread API) is never called by CreateRemoteThread API. MyZwResumeThread function is called by other code, not your code. Therefore, you can't pass the addresses of the injected functions to use in MyZwResumeThread. In MyZwResumeThread, there are some user-defined functions, Windows API, and strings. You should make the MyZwResumeThread function know the addresses of them. So another method is required to make MyZwResumeThread work. Here I use a trick below.

When you call VirtualAllocEx API to inject MyZwResumeThread, you use larger size than the size of MyZwResumeThread. The memory area that are allocated is divided into two. You inject codes into the front part that obtain the addresses of functions that will be used in MyZwResumeThread. And you inject the MyZwResumeThread code in the rear part of the memory area that is allocated. In order to find the boundary between two parts of the allocated memory, it is necessary to inject a boundary value(0xB0000003).

And you divide the front part into two again. In the rear part of the memory area that is divided again, there must be saved the addresses that will be used in MyZwResumeThread. And five bytes of the front part of the memory area that is divided again, there must be CALL code that calls a function. What the function do is shown below.

(a) Finding the boundary value.

(b) Saving the rear part of the memory area that is divided at the first time to jump into MyZwResumeThread.

(c) Jumping into MyZwResumeThread.

After the CALL, you immediately do POP and save EIP to find the boundary value. From now on, is simple. It is simple from now on. You can find the address of MyZwResumeThread and the addresses that are used in MyZwResumeThread, using the address of boundary value. you store EAX with the address of MyZwResumeThread and jump to EAX. Then you can find the addresses that is necessary to use functions and strings. This process must be made by all functions that are injected into the selected process.

Finally, you inject the code shown above into the selected process. After the code injection, you have to call one of the injected codes using CreateRemoteThread API. In the remote thread of the selected process, the selected process do ZwResumeThread API hooking. Now, the selected process inject the selected DLL into every child process.
