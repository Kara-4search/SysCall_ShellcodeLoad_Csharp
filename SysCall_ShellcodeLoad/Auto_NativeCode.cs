using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;

/*
	#include <Windows.h>
	#include <stdio.h>
	#include <tchar.h>
	#pragma comment(linker, "/section:.data,RWE")//.data段可执行

	CHAR FuncExample[] = {
		0x4c,0x8b,0xd1,			  //mov r10,rcx
		0xb8,0xb9,0x00,0x00,0x00, //mov eax,0B9h
		0x0f,0x05,				  //syscall
		0xc3					  //ret
	};

	typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(//函数指针
		HANDLE ProcessHandle,
		PVOID* BaseAddress, 
		ULONG_PTR ZeroBits, 
		PSIZE_T RegionSize, 
		ULONG AllocationType, 
		ULONG Protect);


	DOUBLE GetAndSetSysCall(TCHAR* szFuncName) {
		DWORD SysCallid = 0;
		HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));
		DWORD64 FuncAddr = (DWORD64)GetProcAddress(hModule, (LPCSTR)szFuncName);
		LPVOID CallAddr = (LPVOID)(FuncAddr + 4);
		ReadProcessMemory(GetCurrentProcess(), CallAddr, &SysCallid, 4, NULL);
		memcpy(FuncExample+4, (CHAR*)&SysCallid, 2);
		return (DOUBLE)SysCallid;
	}

	int main() {
		LPVOID Address = NULL;
		SIZE_T uSize = 0x1000;
		DOUBLE call = GetAndSetSysCall((TCHAR*)"NtAllocateVirtualMemory");
		pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)&FuncExample;
		NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &Address, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
		return 0;

	} 
*/

namespace SysCall_ShellcodeLoad
{
    class Auto_NativeCode
    {
		public uint NTSTATUS;
		public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

		// public uint SYSid = 0;
		public static byte[] SYSbyte1 =
		{
			0x4c, 0x8b, 0xd1,               
            0xb8
		};

		public static byte[] SYSbyte2 =
		{ 
			0x00, 0x00, 0x00,  
            0x0F, 0x05,                    
            0xC3                           
        };

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

		[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
		static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr GetModuleHandle(string lpModuleName);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll")]
		public static extern void RtlZeroMemory(IntPtr pBuffer, int length);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool ReadProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			int dwSize,
			out uint lpNumberOfBytesRead
		);


		public static uint GetSyscallID(string SysFunName)
        {
			uint SyscallID = 0;
			IntPtr SyscallID_mem = Marshal.AllocHGlobal(Marshal.SizeOf(SyscallID));
			RtlZeroMemory(SyscallID_mem, Marshal.SizeOf(SyscallID));

			IntPtr hModule = GetModuleHandle("ntdll.dll");
			IntPtr FunAddr = GetProcAddress(hModule, SysFunName);
			IntPtr CallAddr = FunAddr + 4;

			uint temp;
			bool read_result = ReadProcessMemory(GetCurrentProcess(), CallAddr, SyscallID_mem, 4, out temp);
			// Console.WriteLine("Error: " + Marshal.GetLastWin32Error());
			// Console.WriteLine("CallAddr：" + CallAddr + ", SyscallID" + SyscallID + ", temp: " + temp);

			SyscallID = (uint)Marshal.ReadInt32(SyscallID_mem);
			return SyscallID;
        }

		public static uint NtAllocateVirtualMemory
		(
			IntPtr ProcessHandle,
			ref IntPtr BaseAddress,
			IntPtr ZeroBits,
			ref UIntPtr RegionSize,
			uint AllocationType,
			uint Protect
		)
		{
			// set byte array of bNtAllocateVirtualMemory to new byte array called syscall
			uint SyscallID = Auto_NativeCode.GetSyscallID("NtAllocateVirtualMemory");
			byte[] syscall1 = SYSbyte1;
			byte[] syscallid = { (byte)SyscallID };
			byte[] syscall2 = SYSbyte2;
			byte[] sysfinal = syscall1.Concat(syscallid).Concat(syscall2).ToArray();

			/*
			foreach(byte temp in sysfinal)
            {
				Console.WriteLine("Sysfinal: " + temp);
			}
			*/

			// specify unsafe context
			unsafe
			{
				// create new byte pointer and set value to our syscall byte array
				fixed (byte* ptr = sysfinal)
				{
					// cast the byte array pointer into a C# IntPtr called memoryAddress
					IntPtr memoryAddress = (IntPtr)ptr;

					// Change memory access to RX for our assembly code
					if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)sysfinal.Length, PAGE_EXECUTE_READWRITE, out uint oldprotect))
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
