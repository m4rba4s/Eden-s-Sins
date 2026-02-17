/*
 * THE EDEN'S SINS — YARA Rules
 * Detects macOS implant artifacts, suspicious dylibs, and malicious plists
 */

rule macos_suspicious_dylib {
    meta:
        description = "Detects suspicious dynamic libraries on macOS"
        author = "The Eden's Sins Purple Team"
        mitre = "T1574.004"
        severity = "high"

    strings:
        $constructor = "__attribute__((constructor))"
        $dylib_header = { CF FA ED FE }  // MH_MAGIC_64
        $inject_str1 = "DYLD_INSERT" ascii wide
        $inject_str2 = "dlopen" ascii
        $inject_str3 = "task_for_pid" ascii
        $inject_str4 = "mach_vm_write" ascii
        $inject_str5 = "thread_create_running" ascii

        // Suspicious API calls in dylib
        $api1 = "CGEventCreateKeyboardEvent" ascii
        $api2 = "CGEventPost" ascii
        $api3 = "IOHIDPostEvent" ascii
        $api4 = "NSAppleScript" ascii
        $api5 = "SecKeychainFindGenericPassword" ascii

    condition:
        ($dylib_header at 0) and (
            ($constructor and any of ($inject_str*)) or
            (3 of ($api*)) or
            (2 of ($inject_str*) and any of ($api*))
        )
}

rule macos_implant_strings {
    meta:
        description = "Detects common implant strings in macOS binaries"
        author = "The Eden's Sins Purple Team"
        mitre = "T1059"
        severity = "critical"

    strings:
        // C2 indicators
        $c2_1 = "beacon_interval" ascii nocase
        $c2_2 = "exfiltrate" ascii nocase
        $c2_3 = "reverse_shell" ascii nocase
        $c2_4 = "bind_shell" ascii nocase
        $c2_5 = "keylogger" ascii nocase
        $c2_6 = "screenshot" ascii nocase
        $c2_7 = "webcam_capture" ascii nocase

        // Persistence indicators
        $persist_1 = "LaunchAgents" ascii
        $persist_2 = "LaunchDaemons" ascii
        $persist_3 = "com.apple.loginitems" ascii
        $persist_4 = "DYLD_INSERT_LIBRARIES" ascii

        // Credential access
        $cred_1 = "dump-keychain" ascii
        $cred_2 = "find-generic-password" ascii
        $cred_3 = "security export" ascii
        $cred_4 = "TCC.db" ascii

        // Evasion
        $evasion_1 = "ptrace" ascii
        $evasion_2 = "sysctl.proc_info" ascii
        $evasion_3 = "isBeingDebugged" ascii

    condition:
        (2 of ($c2_*)) or
        (2 of ($persist_*) and any of ($c2_*)) or
        (2 of ($cred_*) and any of ($c2_*)) or
        (any of ($evasion_*) and any of ($c2_*))
}

rule macos_malicious_plist {
    meta:
        description = "Detects suspicious LaunchAgent/Daemon plist content"
        author = "The Eden's Sins Purple Team"
        mitre = "T1543.001"
        severity = "high"

    strings:
        $plist_header = "<?xml" ascii
        $plist_dtd = "PropertyList" ascii

        // Suspicious programs in plists
        $prog_1 = "/tmp/" ascii
        $prog_2 = "/var/tmp/" ascii
        $prog_3 = "/Users/Shared/" ascii
        $prog_4 = "/private/tmp/" ascii
        $prog_5 = ".hidden" ascii

        // Suspicious keys
        $key_1 = "RunAtLoad" ascii
        $key_2 = "KeepAlive" ascii
        $key_3 = "StartInterval" ascii

        // Script execution
        $script_1 = "/bin/bash" ascii
        $script_2 = "/bin/sh" ascii
        $script_3 = "osascript" ascii
        $script_4 = "python" ascii
        $script_5 = "curl" ascii

    condition:
        $plist_header and $plist_dtd and
        any of ($key_*) and
        (any of ($prog_*) or (2 of ($script_*)))
}
