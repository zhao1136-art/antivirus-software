rule Shylock_Comments
{
    meta:
        id = "SHYLCK000000000000000000001"
        version = "1.0"
        creation_date = "2026-07-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "AnDun-Lab"
        author = "andun"
        description = "Identifies Win32/Shylock (aka Win32/Wolcape) description/comment metadata files."
        category = "MALWARE"
        malware = "SHYLOCK"
        malware_type = "TROJAN"

    strings:
        $wolcape_a = "Win32/Wolcape.A" ascii
        $wolcape_b = "Win32/Wolcape.B" ascii
        $bootkit = "bootkit dropper" ascii
        $wolcape = "Wolcape" ascii

    condition:
        ($wolcape_a or $wolcape_b) and $bootkit
}
