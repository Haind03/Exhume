import "elf"

/*
   Exhume custom rules for Linux threat hunting.
   Author: HaiND from the Post and Telecommunication Institute of Technology
   License: MIT
   Written for memory regions and persistence targets; each rule needs several
   independent indicators to keep false positives low.
*/

rule Exhume_Reverse_Shell_Oneliner
{
    meta:
        description = "Shell reverse-shell idioms (bash /dev/tcp, nc -e, mkfifo relays)"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $tcp1 = /bash -i *>& *\/dev\/tcp\/[0-9a-zA-Z.\-]{1,64}\/[0-9]{1,5}/
        $tcp2 = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,5} *0>&1/
        $nc = /\bnc(at)? (-[a-z]+ )*-e \/bin\/(ba)?sh/
        $fifo = /mkfifo [^;|]{1,64}; *(cat|tail -f) [^|]{1,64}\| *\/bin\/(ba)?sh -i/
    condition:
        filesize < 5MB and any of them
}

rule Exhume_Python_Pty_Reverse_Shell
{
    meta:
        description = "Python socket + dup2 + pty/subprocess reverse shell"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1059.006"
    strings:
        $s1 = "socket.socket(" ascii
        $s2 = "os.dup2(" ascii
        $s3 = "pty.spawn(" ascii
        $s4 = "subprocess.call([\"/bin/sh\"" ascii
        $s5 = "subprocess.call(['/bin/sh'" ascii
        $c = ".connect((" ascii
    condition:
        filesize < 2MB and $s1 and $s2 and $c and 1 of ($s3, $s4, $s5)
}

rule Exhume_LD_PRELOAD_Process_Hider
{
    meta:
        description = "Userland rootkit that hooks readdir to hide /proc entries (libprocesshider and derivatives)"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "critical"
        mitre = "T1014, T1574.006"
    strings:
        $dl = "dlsym" ascii
        $r1 = "readdir" ascii
        $r2 = "readdir64" ascii
        $p1 = "/proc/self/fd/%d" ascii
        $p2 = "/proc/%s/stat" ascii
        $p3 = "process_to_filter" ascii
        $p4 = "get_process_name" ascii
        $p5 = "get_dir_name" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and $dl and $r1 and $r2 and 3 of ($p*)
}

rule Exhume_LKM_Rootkit_Syscall_Hooks
{
    meta:
        description = "Kernel module with hooked kill/getdents handlers and hiding helpers (Diamorphine-like LKM)"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "critical"
        mitre = "T1014, T1547.006"
    strings:
        $m1 = ".modinfo" ascii
        $m2 = "__this_module" ascii
        $h1 = "hacked_kill" ascii
        $h2 = "hacked_getdents" ascii
        $h3 = "hacked_getdents64" ascii
        $h4 = "orig_getdents64" ascii
        $h5 = "module_hide" ascii
        $h6 = "module_show" ascii
        $h7 = "give_root" ascii
        $h8 = "is_invisible" ascii
        $h9 = "kallsyms_lookup_name" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and all of ($m*) and 3 of ($h*)
}

rule Exhume_Fileless_Memfd_Loader
{
    meta:
        description = "Dynamically linked ELF that imports memfd_create together with an exec and a network call (fileless loader)"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1620, T1027.011"
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB
        // Loaders are small programs; interpreters and big runtimes (python, libsystemd-shared)
        // legitimately import these functions among hundreds of others.
        and elf.dynsym_entries < 200
        // Imported (undefined, shndx 0) symbols only: libc and syscall tables define or merely
        // name these functions, a loader calls them.
        and for any s in elf.dynsym : (s.name == "memfd_create" and s.shndx == 0)
        and for any s in elf.dynsym : ((s.name == "fexecve" or s.name == "execveat" or s.name == "execve" or s.name == "execv") and s.shndx == 0)
        and for any s in elf.dynsym : ((s.name == "connect" or s.name == "curl_easy_perform" or s.name == "SSL_connect" or s.name == "getaddrinfo") and s.shndx == 0)
}

rule Exhume_Script_Memfd_Loader
{
    meta:
        description = "Script that loads an ELF into a memfd and executes it (Python/Perl fileless loader)"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1620, T1059.006"
    strings:
        $m1 = "memfd_create" ascii
        $m2 = "syscall(319" ascii
        $m3 = "syscall(279" ascii
        $e1 = "os.execv" ascii
        $e2 = "/proc/self/fd/" ascii
        $e3 = "exec {" ascii
        $e4 = "os.fexecve" ascii
        $s1 = "import os" ascii
        $s2 = "import ctypes" ascii
        $s3 = "use POSIX" ascii
        $s4 = "require 'fiddle'" ascii
    condition:
        filesize < 5MB
        and uint32(0) != 0x464c457f        // not ELF
        and uint32(0) != 0x72613c21        // not an ar archive (static libraries)
        and (uint16(0) == 0x2123 or any of ($s*))   // "#!" or interpreter imports
        and 1 of ($m*) and 1 of ($e*)
}

rule Exhume_XMRig_Miner
{
    meta:
        description = "XMRig-family cryptocurrency miner"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1496"
    strings:
        $a1 = "stratum+tcp://" ascii
        $a2 = "stratum+ssl://" ascii
        $b1 = "randomx" ascii nocase
        $b2 = "--donate-level" ascii
        $b3 = "cryptonight" ascii nocase
        $b4 = "\"max-cpu-usage\"" ascii
        $b5 = "xmrig" ascii nocase
    condition:
        filesize < 30MB and 1 of ($a*) and 2 of ($b*)
}

rule Exhume_PAM_Backdoor_Module
{
    meta:
        description = "PAM module that compares against a hardcoded password or logs credentials"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "critical"
        mitre = "T1556.003"
    strings:
        $p1 = "pam_sm_authenticate" ascii
        $p2 = "pam_get_item" ascii
        $s1 = "strcmp" ascii
        $l1 = "fopen" ascii
        $l2 = "fprintf" ascii
        $k1 = "PAM_AUTHTOK" ascii
        $x1 = /\/(tmp|dev\/shm|var\/tmp|usr\/share\/[a-z]{1,16})\/\.[a-zA-Z0-9_\-]{1,32}/ ascii
        $x2 = "%s:%s" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 1MB and all of ($p*) and $s1 and (($l1 and $l2 and $x2) or $x1)
        and not $k1
}

rule Exhume_Gsocket_Backdoor
{
    meta:
        description = "Global Socket (gs-netcat / gsocket) relay backdoor, abused for persistent access"
        author = "HaiND from the Post and Telecommunication Institute of Technology"
        severity = "high"
        mitre = "T1219, T1572"
    strings:
        $a = "GS_ARGS" ascii
        $b = "gs-netcat" ascii
        $c = "GSOCKET_ARGS" ascii
        $d = "gsocket.io" ascii
        $e = "GS_SECRET" ascii
    condition:
        filesize < 20MB and 3 of them
}
