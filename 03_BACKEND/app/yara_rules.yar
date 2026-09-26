rule Suspicious_Keywords {
    meta:
        description = "Detects common phishing keywords"
        author = "HopZero SOC"
    strings:
        $s1 = "verify your account" nocase
        $s2 = "password reset" nocase
        $s3 = "urgent action required" nocase
        $s4 = "click here to login" nocase
    condition:
        any of them
}

rule Suspicious_Attachment_Ext {
    meta:
        description = "Detects dangerous file extensions in text"
    strings:
        $ext1 = ".vbs" nocase
        $ext2 = ".bat" nocase
        $ext3 = ".scr" nocase
        $ext4 = ".exe" nocase
    condition:
        any of them
}
