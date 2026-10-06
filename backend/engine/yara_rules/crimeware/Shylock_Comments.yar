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
        // 2026-10-05: 这里原有一行
        //     $wolcape = "Wolcape" ascii
        // 声明了却从未在 condition 中引用。旧的自制引擎默默忽略；换成真
        // libyara 后它属于编译错误（unreferenced string "$wolcape"），会让
        // **整个文件被拒**、本规则失效。该字符串不参与本规则判定，删掉即可
        // （对检测行为等价）。

    condition:
        ($wolcape_a or $wolcape_b) and $bootkit
}
