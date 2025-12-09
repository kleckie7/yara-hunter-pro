rule EICAR_Test {
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Ransomware_LockBit {
    strings:
        $a = "LockBit" ascii wide
        $b = "encrypt" ascii
        $c = "ransom_note.txt" ascii
    condition:
        all of them and filesize < 10MB
}

rule Trojan_Emotet {
    strings:
        $a = "Emotet" ascii
        $b = /cmd\.exe.*\/c/
    condition:
        all of them
}

rule Phishing_HTML {
    strings:
        $a = "<script>alert(" ascii
        $b = "phishing" wide
    condition:
        any of them
}

rule BruteForce_Sim {
    strings:
        $a = "admin" ascii
        $b = "password123" ascii
        $c = "login_attempt" ascii
    condition:
        all of them
}

rule Clop_Ransomware_2025 {
    strings:
        $a = "Clop" ascii wide
        $b = "double_ext" ascii
    condition:
        all of them and uint16(0) == 0x5A4D
}

rule Suspicious_PowerShell {
    strings:
        $a = "powershell.exe" ascii
        $b = "-ExecutionPolicy Bypass" ascii
    condition:
        all of them
}

rule Fake_Malware_Hash {
    strings:
        $a = "malware_hash" ascii
    condition:
        $a and filesize > 1KB
}
