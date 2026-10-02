rule AndroRAT_Android_Trojan
{
    meta:
        description = "AndroRAT Android Remote Access Trojan"
        author = "Andun Lab"
        malware_type = "TROJAN"
        severity = "high"
        family = "AndroRAT"
        reference = "https://github.com/AndroRAT/AndroRAT"
    strings:
        $s1 = "AndroRat" ascii nocase
        $s2 = "androrat" ascii nocase
        $s3 = "com.androrat" ascii nocase
        $s4 = "androrat.server" ascii nocase
        $s5 = "androrat.client" ascii nocase
        $c1 = "getContacts" ascii nocase
        $c2 = "getSms" ascii nocase
        $c3 = "getCallLog" ascii nocase
        $c4 = "getLocation" ascii nocase
        $c5 = "takePicture" ascii nocase
        $c6 = "recordAudio" ascii nocase
        $c7 = "sendSMS" ascii nocase
        $c8 = "sendUssd" ascii nocase
        $c9 = "getInstalledApps" ascii nocase
        $c10 = "getAccounts" ascii nocase
        $c11 = "uploadFile" ascii nocase
        $c12 = "downloadFile" ascii nocase
        $c13 = "startGPS" ascii nocase
        $c14 = "stopGPS" ascii nocase
        $c15 = "takePhoto" ascii nocase
        $c16 = "getBattery" ascii nocase
        $c17 = "getNetwork" ascii nocase
        $c18 = "getWifi" ascii nocase
        $c19 = "getDeviceInfo" ascii nocase
        $c20 = "getSimInfo" ascii nocase
        $c21 = "getSmsInbox" ascii nocase
        $c22 = "getSmsSent" ascii nocase
        $c23 = "monitorSms" ascii nocase
        $c24 = "getBookmarks" ascii nocase
        $c25 = "getHistory" ascii nocase
        $c26 = "getCookies" ascii nocase
        $c27 = "getProcess" ascii nocase
        $c28 = "killProcess" ascii nocase
        $c29 = "screenCapture" ascii nocase
        $c30 = "openUrl" ascii nocase
        $c31 = "setWallpaper" ascii nocase
        $c32 = "showMessage" ascii nocase
        $c33 = "playSound" ascii nocase
        $c34 = "recordCall" ascii nocase
        $c35 = "getClipboard" ascii nocase
        $c36 = "setClipboard" ascii nocase
        $c37 = "deleteFile" ascii nocase
        $c38 = "listDir" ascii nocase
        $c39 = "vibrate" ascii nocase
    condition:
        ($s1 or $s2 or $s3 or $s4 or $s5) or 6 of ($c*)
}

rule AndroRAT_Version_Identity
{
    meta:
        description = "AndroRAT version/build identification strings"
        author = "Andun Lab"
        malware_type = "INFO"
        severity = "medium"
        family = "AndroRAT"
    strings:
        $v1 = "AndroRAT" ascii nocase
        $v2 = "andro" ascii nocase
        $v3 = "rat" ascii nocase wide
        $p1 = "Client.java" ascii
        $p2 = "Connection.java" ascii
        $p3 = "Packet.java" ascii
        $p4 = "Streamer.java" ascii
        $p5 = "PhotoTaker.java" ascii
        $p6 = "SoundRecorder.java" ascii
        $p7 = "GPSTracker.java" ascii
        $p8 = "ContactsManager.java" ascii
        $p9 = "CallMonitor.java" ascii
        $p10 = "SMSSender.java" ascii
        $p11 = "SMSMonitor.java" ascii
    condition:
        ($v1 or ($v2 and $v3)) and 2 of ($p*)
}

rule Generic_Android_Trojan_Indicators
{
    meta:
        description = "Generic Android trojan suspicious indicators"
        author = "Andun Lab"
        malware_type = "MALWARE"
        severity = "medium"
        family = "GenericAndroidTrojan"
    strings:
        $dex = { 64 65 78 0A }
        $a1 = "BOOT_COMPLETED" ascii nocase
        $a2 = "READ_SMS" ascii nocase
        $a3 = "SEND_SMS" ascii nocase
        $a4 = "RECORD_AUDIO" ascii nocase
        $a5 = "READ_CONTACTS" ascii nocase
        $a6 = "ACCESS_FINE_LOCATION" ascii nocase
        $a7 = "PROCESS_OUTGOING_CALLS" ascii nocase
        $a8 = "SYSTEM_ALERT_WINDOW" ascii nocase
        $a9 = "BIND_DEVICE_ADMIN" ascii nocase
        $a10 = "com.metasploit.stage" ascii nocase
        $d1 = "DexClassLoader" ascii nocase
        $d2 = "Runtime.exec" ascii nocase
        $d3 = "getRuntime" ascii nocase
    condition:
        $dex at 0 and (
            (5 of ($a*)) or
            ($a10) or
            (2 of ($a*) and 2 of ($d*))
        )
}
