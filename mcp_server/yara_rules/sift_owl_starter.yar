/*
 * SIFT-OWL starter YARA ruleset
 *
 * A small, curated set of rules covering the most common ATT&CK techniques
 * SIFT-OWL is asked to detect. Designed to be:
 *   - Cheap (string-only matches, no PE structure walking)
 *   - Low-false-positive on legitimate Windows binaries
 *   - Mappable to specific MITRE techniques in the rule meta
 *
 * Bring your own rule pack with SIFT_OWL_YARA_RULES=/path/to/rules.yar
 * (overrides this default set).
 */


/* ---- T1055 / T1059 — PowerShell encoded execution ----------------------- */

rule SIFTOWL_PowerShell_EncodedCommand
{
    meta:
        author = "sift-owl"
        description = "PowerShell -EncodedCommand invocation — common base64 loader pattern"
        mitre = "T1059.001 / T1027.013"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" ascii nocase wide
        $b = "-encodedcmd" ascii nocase wide
        $c = "FromBase64String" ascii nocase wide
    condition:
        any of ($a, $b) or ($c and filesize < 50MB)
}


/* ---- T1003 — Mimikatz residue ------------------------------------------- */

rule SIFTOWL_Mimikatz_Strings
{
    meta:
        author = "sift-owl"
        description = "Mimikatz string residue — module names, error msgs, command outputs"
        mitre = "T1003"
        severity = "high"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii nocase wide
        $m2 = "sekurlsa::pth" ascii nocase wide
        $m3 = "sekurlsa::tickets" ascii nocase wide
        $m4 = "kerberos::ptt" ascii nocase wide
        $m5 = "kerberos::golden" ascii nocase wide
        $m6 = "kerberos::list" ascii nocase wide
        $m7 = "lsadump::sam" ascii nocase wide
        $m8 = "lsadump::secrets" ascii nocase wide
        $m9 = "lsadump::dcsync" ascii nocase wide
        $m10 = "mimikatz" ascii nocase wide
        $m11 = "gentilkiwi" ascii nocase wide
    condition:
        2 of them
}


/* ---- T1055 — Cobalt Strike beacon residue ------------------------------- */

rule SIFTOWL_CobaltStrike_Beacon_Indicators
{
    meta:
        author = "sift-owl"
        description = "Cobalt Strike beacon residue — pipe-name pattern + canonical strings"
        mitre = "T1055 / T1572"
        severity = "high"
    strings:
        // Default beacon named-pipe patterns
        $p1 = "\\\\.\\pipe\\msagent_" ascii wide
        $p2 = "\\\\.\\pipe\\postex_" ascii wide
        $p3 = "\\\\.\\pipe\\status_" ascii wide
        $p4 = "MSSE-" ascii wide
        // Common beacon-config / loader strings
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "Could not connect to pipe" ascii wide
        $s3 = "%s as %d" ascii wide
        $s4 = "beacon.dll" ascii nocase wide
        // Common malleable-C2 user-agent fragments often left in memory
        $ua1 = "spawnto_x86" ascii wide
        $ua2 = "spawnto_x64" ascii wide
    condition:
        any of ($p*) or 2 of ($s*) or any of ($ua*)
}


/* ---- T1219 — Remote Access Software (legitimate but high-signal) ------- */

rule SIFTOWL_RAS_Software_Common
{
    meta:
        author = "sift-owl"
        description = "Remote access software file/process names; legitimate, but high-signal in incident context"
        mitre = "T1219"
        severity = "low"
    strings:
        $tv1 = "TeamViewer" ascii wide
        $tv2 = "tv_x64.dll" ascii wide
        $tv3 = "tvnsrv.exe" ascii wide
        $a1 = "AnyDesk" ascii wide
        $a2 = "ad.trace" ascii wide
        $s1 = "ScreenConnect" ascii wide
        $s2 = "AteraAgent" ascii wide
        $s3 = "SplashtopStreamer" ascii wide
        $s4 = "Atera Agent" ascii wide
        $rmm = "remoteutilities.com" ascii nocase wide
    condition:
        any of them
}


/* ---- T1547.001 — Webshell signatures ------------------------------------ */

rule SIFTOWL_Webshell_Basic_ASPX
{
    meta:
        author = "sift-owl"
        description = "Basic ASPX webshell signatures — command-eval patterns"
        mitre = "T1505.003"
        severity = "high"
    strings:
        $a = "Request.Form[\"cmd\"]" ascii nocase
        $b = "Process.Start(\"cmd.exe\"" ascii nocase
        $c = "Diagnostics.Process" ascii nocase
        $d = "Request.Form(\"shell\")" ascii nocase
        $e = "Eval(Request" ascii nocase
        $f = "JScript.Encode" ascii nocase
    condition:
        2 of them
}


rule SIFTOWL_Webshell_Basic_PHP
{
    meta:
        author = "sift-owl"
        description = "Basic PHP webshell — eval / system / passthru of GET/POST input"
        mitre = "T1505.003"
        severity = "high"
    strings:
        $a = "eval($_POST" ascii nocase
        $b = "eval($_GET" ascii nocase
        $c = "system($_POST" ascii nocase
        $d = "system($_GET" ascii nocase
        $e = "passthru($_REQUEST" ascii nocase
        $f = "base64_decode($_POST" ascii nocase
        $g = "shell_exec($_REQUEST" ascii nocase
    condition:
        any of them
}


/* ---- T1003.005 — LSASS dump indicators ---------------------------------- */

rule SIFTOWL_LSASS_Dump_File
{
    meta:
        author = "sift-owl"
        description = "Windows MiniDump file header — file content from a process dump"
        mitre = "T1003.001"
        severity = "high"
    strings:
        $minidump = { 4D 44 4D 50 }  // "MDMP" minidump magic
    condition:
        $minidump at 0
}


/* ---- T1027 — PyInstaller / py2exe packers ------------------------------- */

rule SIFTOWL_PyInstaller_Packed
{
    meta:
        author = "sift-owl"
        description = "PyInstaller-packed PE — embedded Python runtime residue"
        mitre = "T1027.002"
        severity = "medium"
    strings:
        $a = "_MEIPASS2" ascii nocase
        $b = "_MEIPASS" ascii nocase
        $c = "pyi-runtime" ascii nocase
        $d = "PYZ-00.pyz" ascii nocase
    condition:
        any of them
}
