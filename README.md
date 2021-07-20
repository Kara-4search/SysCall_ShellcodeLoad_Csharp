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
   3. Find the syscall ID automatically(DONE)

- Original shellcode is a Message
	```
            /*   Messagebox shellcode   */
            
            byte[] buf1 = new byte[328] {
                0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
                0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
                0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
                0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
                0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
                0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
                0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
                0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
                0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
                0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
                0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
                0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
                0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
                0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
                0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
                0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
                0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
                0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
                0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
                0x00, 0x3e, 0x48, 0x8d, 0x95, 0x1a, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
                0x85, 0x35, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
                0x56, 0x07, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6,
                0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
                0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
                0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 
                0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x20, 0x76, 0x69, 0x61, 0x20, 0x73, 
                0x79, 0x73, 0x63, 0x61, 0x6C, 0x6C, 0x00, 0x41, 0x50, 0x49, 0x20, 0x54, 
                0x65, 0x73, 0x74, 0x00 
            };
	
	```
- You may need to read those posts below **the Reference link** so you could understand how it works.
- Feel free to make any issues.


## Usage
1. I updated the SysCall_ShellcodeLoad, now it's gonna find the syscall ID automatically(Check the file - Auto_NativeCode.cs).
2. If you want to test the old verison SysCall_ShellcodeLoad，
	* You just need to remove all the "Auto_NativeCode" from Program.cs 
	* And Replace the syscall ID with your own.
3. Replace the "buf1" with your own shellcode.
   ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_buf1.png)
4. Replace the syscall ID with your own.
* There are three syscall IDs you need to replace.
	- 1). NtAllocateVirtualMemory
  ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntAVM.png)
	- 2). NtCreateThreadEx
  ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntCT.png)
	- 3). NtWaitForSingleObject
  ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/SysCall_ShellcodeLoad_CUntWFSO.png)


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

   