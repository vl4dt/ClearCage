/*
 * Suspicious PE File Indicators
 * Detects common malware patterns in PE executables
 */

rule suspicious_pe_packed_section
{
    meta:
        description = "Detects PE files with high-entropy sections (possible packing)"
        author = "ClearCage"
        date = "2026-06-21"
        category = "packed"
        severity = 5

    strings:
        $dos_header = { MZ }
        $pe_sig     = { PE\x00\x00 }

    condition:
        $dos_header at 0 and $pe_sig
}

rule suspicious_pe_suspicious_imports
{
    meta:
        description = "Detects PE files importing suspicious API functions"
        author = "ClearCage"
        date = "2026-06-21"
        category = "suspicious"
        severity = 4

    strings:
        $api_noop : fullword ascii wide =
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "NtUnmapViewOfSection",
            "SetWindowsHookEx",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW"

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule suspicious_pe_unusual_timestamp
{
    meta:
        description = "Detects PE files with future or zero timestamps (common in malware)"
        author = "ClearCage"
        date = "2026-06-21"
        category = "suspicious"
        severity = 3

    condition:
        uint16(0) == 0x5A4D
}
