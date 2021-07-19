# SysCall_ShellcodeLoad_Csharp

Blog link: working on it.

Github Link: https://github.com/Kara-4search/SysCall_ShellcodeLoad_Csharp

- Base on my another project: https://github.com/Kara-4search/Simple_ShellCodeLoader_CSharp
- A shellcode loader written in CSharp, the main purpose is to bypass the EDR API hook.
- Only tested in Win10_x64, may not gonna work in x86.
- Loading shellcode with direct syscall.
- You need to replace the "syscall identifier" with your syscall ID, which you could find on your system
- About how to find the syscall ID on your system, check the link below:

   1. Use windbg: https://jhalon.github.io/utilizing-syscalls-in-csharp-2/
   2. Check the system call table: https://j00ru.vexillium.org/syscalls/nt/64/
   3. Find the syscall ID automatically(50% done)

- You may need to read those posts below **the Reference link** so you could understand how it works.
- Feel free to make any issues.


## Usage

1. Replace the "buf1" with your own shellcode.
   ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_buf1.png)
2. Replace the syscall ID with your own.
- There are three syscall IDs you need to replace.
  1). NtAllocateVirtualMemory
  ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntAVM.png)
  2). NtCreateThreadEx
  ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntCT.png)
  3). NtWaitForSingleObject
- ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntWFSO.png)

 
## Reference link:

1. https://github.com/SolomonSklash/SyscallPOC
2. https://jhalon.github.io/utilizing-syscalls-in-csharp-1/
3. https://jhalon.github.io/utilizing-syscalls-in-csharp-2/
4. https://www.solomonsklash.io/syscalls-for-shellcode-injection.html
5. https://www.pinvoke.net/default.aspx
6. https://github.com/jhalon/SharpCall/blob/master/Syscalls.cs
7. https://github.com/badBounty/directInjectorPOC
8. https://j00ru.vexillium.org/syscalls/nt/64/
9. http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtAllocateVirtualMemory.html

   