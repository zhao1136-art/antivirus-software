rule SpyEye_Archive
{
    meta:
        id = "SPYEyE0000000000000000000001"
        version = "1.0"
        creation_date = "2026-07-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "AnDun-Lab"
        author = "andun"
        description = "Identifies SpyEye banker dropper archive by its distinctive stored file names (malware.exe / config.dat / dropper.exe)."
        category = "MALWARE"
        malware = "SPYEYE"
        malware_type = "BANKING"

    strings:
        $zip_magic = { 50 4b 03 04 }
        $malware_exe = "malware.exe" ascii
        $malware_ext = "malware.ex~" ascii
        $config_dat = "config.dat" ascii
        $dropper_exe = "dropper.exe" ascii

    condition:
        $zip_magic at 0 and $malware_exe and ($config_dat or $dropper_exe or $malware_ext)
}

rule SpyEye_Payload
{
    meta:
        id = "SPYEyE0000000000000000000002"
        version = "1.0"
        creation_date = "2026-07-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "AnDun-Lab"
        author = "andun"
        description = "Identifies SpyEye banker payload by its configuration / bot protocol strings."
        category = "MALWARE"
        malware = "SPYEYE"
        malware_type = "BANKING"

    strings:
        $bot_version = "BOT_VERSION" ascii
        $bot_guid = "bot_guid" ascii
        $update_config = "UPDATE_CONFIG" ascii
        $data_from_server = "data from server is" ascii
        $bot_version_l = "bot_version" ascii

    condition:
        ($bot_version and $bot_guid) or ($update_config and $bot_version_l) or ($data_from_server and $bot_guid)
}
