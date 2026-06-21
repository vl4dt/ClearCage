/*
 * EICAR Test File Detection
 * Matches the standard antivirus test string (not actual malware)
 * https://en.wikipedia.org/wiki/EICAR_test_file
 */

rule eicar_test_file
{
    meta:
        description = "Detects EICAR antivirus test file"
        author = "ClearCage"
        date = "2026-06-21"
        category = "test"
        severity = 3

    strings:
        $eicar_ascii = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar_hex   = { 5835 4f21 5025 4041 505b 345c 505a 5835 3428 505e 2937 4343 2937 7d24 4549 4341 522d 5354 414e 4441 5244 2d41 4e54 4956 4952 5553 2d54 4553 542d 4649 4c45 2124 482b 482a }

    condition:
        any of them
}
