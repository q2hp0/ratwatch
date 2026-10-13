# ratwatch

small windows watchdog tool i'm building to catch the kind of stuff rats like xworm / njrat / mason rat do
(auto-run persistence, weird processes running from appdata/temp, suspicious outbound connections).

not an antivirus, not trying to replace one. it's a focused scanner + a "watch mode" that polls every
few seconds and yells in the terminal when something looks off. point is to actually understand what
these things do instead of just trusting a gui av.

## why this exists

after messing with the xworm sample (see the hosts/port decrypt stuff), the pattern is pretty consistent:

- it drops itself somewhere like `%appdata%` or `%temp%` and adds a run key or scheduled task so it survives reboot
- the process that's actually running often has a weird parent (explorer.exe spawning a .exe with a random name, or outlook/word spawning powershell)
- it phones home on a regular interval to the same ip, which looks different from normal browser traffic once you graph it
- loader stuff for the .net payloads doesn't always touch disk as a dll, so just grepping for dll drops misses a lot of it. behavior is more reliable than file signatures here.

so ratwatch focuses on those three angles instead of trying to be a signature scanner.

## build (windows, mingw or msvc)

```
cmake -B build -S .
cmake --build build --config Release
```

cross compiling from linux for a quick syntax/link check:

```
cmake -B build-win -S . -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build-win
```

## usage

```
ratwatch.exe scan                one-shot check across persistence/process/network/memory, prints and exits
ratwatch.exe watch               keeps running, checks every 5s, logs to ratwatch.log
ratwatch.exe baseline            saves current state as "known good" so future scans only show new stuff
ratwatch.exe static <file.exe>   analyze a single pe file by itself (entropy per section, .net check, overlay size)
ratwatch.exe mem                 scan running processes for rwx private memory (shellcode/injection indicator)
ratwatch.exe suspend <pid>       freeze every thread in a process so you can go look at it without it doing more
ratwatch.exe resume <pid>        undo suspend
ratwatch.exe quarantine <file>   move a file into ./quarantine/, renamed + hidden + readonly, nothing deleted
ratwatch.exe strings <file>      check a file's strings against a small list of known rat indicators
ratwatch.exe report [out.txt]    run everything and dump it to a text file instead of the terminal
```

don't run `strings` on ratwatch.exe itself, it'll flag its own indicator list as a match, that's just
the detection strings being plain text inside the binary, not an actual issue.

`scan`/`watch`/`baseline` now also cover:
- windows services with a binary path outside the normal spots (system32, program files)
- wmi event subscriptions (CommandLineEventConsumer), a persistence trick that skips the registry entirely
- the hosts file, hashed and compared run to run so a silent edit gets flagged

drop a `ratwatch.conf` next to the exe to customize allowlists (see `ratwatch.conf.example`) so stuff like
discord or your ide running from appdata doesn't spam findings.

## what it actually checks right now

- `HKCU\...\Run`, `HKLM\...\Run`, `RunOnce`, and the startup folder, diffed against a baseline
- scheduled tasks (shells out to schtasks /query since the com api for this is a pain)
- running processes whose exe path is in appdata/temp/public but which aren't on an allowlist
- parent/child combos that are red flags (office apps or pdf readers spawning cmd/powershell/wscript)
- active tcp connections mapped back to the owning pid, flags repeated connections to the same remote ip on a tight interval (a crude beacon detector, nothing fancy)
- private rwx memory regions in running processes (`mem` command / part of `scan`) - normal code doesn't usually need writable+executable memory that isn't backed by a mapped file, this is one of the more reliable signs something unpacked/injected itself
- static pe analysis (`static` command) - parses the pe header by hand, flags high-entropy sections (likely packed/encrypted), large overlay data appended after the sections (common in droppers that bundle a second stage), and flags .net assemblies just as a heads up since xworm/njrat/mason are all .net

## response actions

`suspend`/`resume` freeze a process's threads via `SuspendThread` on every thread it owns - same mechanism
process explorer type tools use, fully reversible, doesn't touch memory or kill anything.

`quarantine` moves a file into `./quarantine/`, appends a timestamp + `.quarantined` extension so it can't
be double-clicked by accident, and sets it hidden+readonly. nothing is deleted, you can always rename it
back if a scan turns out to be a false positive.

## testing it

`tests/fake_rat.ps1` is a harmless powershell script that just does the boring persistence stuff
(adds a run key pointing at notepad, drops a copy of itself in appdata, starts a dummy process
with a weird parent) so you can run ratwatch against it in the vm and watch it get flagged, without
needing an actual rat sample. run it, then run `ratwatch.exe scan` and you should see 2-3 findings.
cleanup script included so it undoes everything after.

## what this is NOT

no kernel driver, no process injection, no hooking. it's all documented win32 apis (registry, toolhelp
snapshot, iphlpapi) that any sysadmin tool uses. a real rat author can absolutely evade this if they
try hard enough, this is meant to catch the common lazy persistence patterns, not be bulletproof.
