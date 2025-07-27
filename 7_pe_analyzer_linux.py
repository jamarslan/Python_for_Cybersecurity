import pefile

def check_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        print(f"\n=== Analyzing {file_path} ===")
        print("\n[Basic Info]")
        print(f"File Type: {'32-bit' if pe.FILE_HEADER.Machine == 0x14c else '64-bit'}")
        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        
        print("\n[Sections]")
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            print(f"- {name}: Size={hex(section.Misc_VirtualSize)}")
            if "UPX" in name:
                print("  ⚠️  WARNING: Possible packed executable!")
        
        print("\n[Imports]")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:3]:
                print(f"- Loads {entry.dll.decode()}")
        
        print("\n✅ Analysis complete!")
        
    except pefile.PEFormatError:
        print("❌ Error: Not a valid Windows EXE file")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        check_pe_file(sys.argv[1])
    else:
        print("Usage: python3 simple_pe_analyzer.py <path_to_exe>")
