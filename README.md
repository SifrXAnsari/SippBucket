# SippBucket

SippBucket is a peer-to-peer document aggregator and a self-hosted repository server of its
own. Every machine you own is a server: they hold the same documents and talk to each
other directly, over a LAN or over the wire, with no account and no service in the middle.

There are no branches and no staging area. A repository is a linear chain of snapshots, and
each replica picks a mode: `power` keeps every snapshot so any past state can be restored,
`simple` keeps only the newest one, the last one it shared with each peer, which the next
merge with that peer needs as its base, and the one the last restore replaced, so a restore can
be undone. The command-line tool is `sip`.

It runs on Windows.

## Terms

Free, under the MIT licence in [`LICENSE`](LICENSE): use it, change it and share it as you
wish. There is no tech support. There is no auto-update: SippBucket never checks for or
fetches a newer version, and a newer one replaces the old only when you install it yourself.

## Project layout

| Project | Path | Target | What it is |
| --- | --- | --- | --- |
| `SippBucket.Core` | `src/SippBucket.Core` | `net10.0` | The library: repository, block store, crypto, sync protocol |
| `SippBucket.Cli` | `src/SippBucket.Cli` | `net10.0` | The command surface as a library: every `sip` command, the help text and `sip doctor`. One implementation serves both executables |
| `sip` | `src/sip` | `net10.0` | A shim over `SippBucket.Cli`. `AssemblyName` is `sip`, so the command is `sip` |
| `SippBucket.Tray` | `src/SippBucket.Tray` | `net10.0-windows` | `SippBucket.exe`: the Windows tray daemon (Windows Forms) with no arguments, the same commands as `sip` with them |
| `sipengine` | `src/sipengine` | C++20 | `sipengine.dll`, the native engine behind a C ABI: the content check Direct Push runs, reading the firmware's SMBIOS tables for Server.ID, and the randomness test peer health's mass-change hold uses |

`SippBucket.Core` takes two packages: `NSec.Cryptography`, which is libsodium, and
`Microsoft.DevTunnels.Ssh`, pinned to one exact version, for Direct Push's SSH transport.

## Build

You need the .NET 10 SDK and Microsoft's C++ build tools (Visual Studio or its Build Tools,
with "Desktop development with C++"): every build compiles `sipengine` with MSVC. To use a
different toolchain install, set `SIPPBUCKET_CPPENV` to your own activation script. From the
repository root, which holds `SippBucket.slnx`:

```bash
dotnet build
```

`SippBucket.exe` is published from the tray project:

```bash
dotnet publish src/SippBucket.Tray -c Release -o publish
```

The publish is three files: `SippBucket.exe`, `libsodium.dll` and `sipengine.dll`. Keep the two
DLLs beside the executable. It loads them from its own folder and says which one is missing
rather than start without it, instead of unpacking anything into `%TEMP%`.

`nuget.config` pins the package source to nuget.org and clears fallback folders, so a
machine-wide NuGet configuration cannot break the restore.

## Build standards

Set in `Directory.Build.props` rather than on the command line, so they cannot be skipped
locally:

- Warnings are errors, with no exceptions list, at `WarningLevel` 9999.
- .NET analyzers on at `AnalysisMode=All`, and code style enforced at build time. The
  solution builds clean at that setting: 0 warnings, 0 errors.
- Nullable reference types enabled.
- XML documentation required on public API. `GenerateDocumentationFile` is on by default and
  switched off in `sip` and `SippBucket.Tray`, so in practice the requirement lands on
  `SippBucket.Core`.
- One version for everything, `Version` in `Directory.Build.props`, with the company, product
  and copyright fields beside it.

## How it works

- **Content addressing.** Every file is split into blocks. A block is named by the
  BLAKE2b-256 hash of its plaintext and filed at `objects/ab/cdef…`, fanned out one level by
  the first byte. Nothing is ever overwritten, so storing content that already exists is a
  no-op rather than a conflict.
- **Block boundaries.** Content-defined, with FastCDC (Xia et al., USENIX ATC 2016): a block
  ends where a rolling hash of the last 48 bytes matches a mask, so inserting a byte moves
  only the boundaries next to it instead of every boundary after it. The average block is
  128 KiB and doubles with file size, up to 4 MiB, so a file stays near 2000 blocks; blocks
  run from a quarter of the average to four times it and never exceed 16 MiB. Crossing one
  of those size steps (just past 250 MiB, 500 MiB, 1000 MiB, about 1.95 GiB and 3.9 GiB)
  re-stores the whole file once. Files last saved by a build before FastCDC keep their
  fixed-size blocks (Syncthing's scheme, 128 KiB to 16 MiB) until they change, and the first
  save after that change stores the file in full once, because its new blocks are cut in
  different places from the old ones. Both kinds restore and sync.
- **Encryption at rest.** Blocks are encrypted with XChaCha20-Poly1305 via NSec. The nonce is
  derived from the block's own content hash, so identical blocks encrypt identically and
  deduplication keeps working. The bytes on disk are the bytes on the wire: a peer serves
  blocks still encrypted and never decrypts them.
- **Snapshots.** A save records the folder as a small fixed header plus one tree per folder.
  The trees are stored and carried as blocks — encrypted, deduplicated and fetched like any
  other block — and a folder nothing changed in keeps its tree, so changing one file writes,
  and sends, the trees on the path to it and nothing else. A snapshot's ID is the BLAKE2b-256
  of its header, bytes this project defines rather than a serializer, so identity cannot move
  when a library does. Snapshots saved by older builds keep their IDs and stay readable
  forever.
- **Identity.** Each machine has a permanent Ed25519 key pair, stored at
  `%APPDATA%\SippBucket\device.key`. A peer is trusted by its device ID, not its address.
- **Server.ID.** Beside the key, each machine knows which physical machine it is: a one-way
  hash of the motherboard's serial number and the system UUID, read from the firmware, shown as
  `Server.ID#XXX-XXX-XXX`, and a number among the person's own machines, "Server 1". The
  person's own machines tell each other theirs inside the encrypted connection and nobody else,
  so they recognise one another after a restart, a reinstall, or when two share a name. It is
  guidance and never authority: only the key proves who is who. `sip id` shows it.
- **Peer health.** Each machine keeps a record of what every other one sent it that was wrong,
  and holds a change that looks like damage instead of copying it: half a folder rewritten at
  once, files turning random-looking as encrypted files do, or a wave of renames to `.locked`.
  The person is asked once, "That was me" or "Not me".
- **Handshake.** `Noise_XK_25519_ChaChaPoly_BLAKE2b` from the Noise Protocol Framework,
  checked byte for byte against the published cacophony, noise-c and snow test vectors. The
  X25519 static key is derived from the Ed25519 device key. Neither device ID nor the
  repository ID crosses the wire in the clear. Noise itself is reviewed; the way SippBucket
  maps onto it (the version preamble, the payload formats, the chunking of large messages,
  reusing the device key) has not been reviewed by anyone outside this project.
- **Callers with no credential.** Until a caller has proved which machine it is, its frames
  are capped at 8 KiB and it has 15 seconds in all, however slowly it sends. The server holds
  at most 16 such connections from one address and 64 altogether; past either limit it closes
  the oldest one from the busiest address, so a flood from one address cannot keep out a
  paired machine at another.
- **Sync.** A pull, run from both ends. Nothing is pushed, so neither machine has to be
  reachable for the other to make progress. Both machines must add each other; a daemon
  refuses any device that is not in its own peer list.
- **Conflicts.** When both sides changed the same file, neither change is discarded. The
  local copy is renamed to `<name>.conflict-<device>-<timestamp><ext>`, the incoming version
  takes the original name, and the merged result is saved as a new snapshot. `<device>` is
  the short ID of the machine whose version the renamed copy holds, which is the machine
  that renamed it. A read-only file is never overwritten or deleted: where the other
  machine changed it, it is kept aside the same way; where the other machine deleted it,
  it stays.
- **What is not synced.** Links (junctions and symbolic links) inside the folder are never
  followed, and nothing is written or deleted through one. A folder that cannot be listed,
  a file another program holds without sharing, and a file that changes every time it is
  read are skipped by that save and listed by `sip status`, `sip save` and the tray's window; what
  was last recorded for them is kept, so none of them reads as deleted on another machine.
  A name that is not valid Unicode (half of a surrogate pair, which Windows allows) and a
  folder nested more than 256 levels down are skipped too, and named the same way: no
  snapshot can record them, so renaming or moving them is what makes them sync.
- **Restore.** `sip restore` puts the folder back to a snapshot and records the result as a
  new snapshot on top of the newest one, so history only moves forward and the restore
  reaches the other machines like any other save.

The repository encryption keys are in `.sip/config.json`, in the clear unless this machine's
copy is locked with a passphrase (`sip lock`, below). Anyone who reads an unlocked
`config.json` can read every document in the repository. An invite does not carry the keys:
it carries a one-time secret, and the key ring crosses only after the other machine has
proved it holds that secret, encrypted under a key derived from that exchange (CPace,
draft-irtf-cfrg-cpace-21).

Removing a machine (`sip peer remove`) rotates the folder's key: everything written from
that moment is under a fresh key the removed machine never receives, the removal travels to
your other machines at their next sync, and each drops the removed machine before storing
the new key. What rotation cannot do, said plainly: un-share the past — the removed machine
holds, or could have copied, everything from before. `sip peer role <machine> read-only`
keeps a member's changes out while it can still read; `sip peer expire <machine> <date>`
ends a membership on a date.

## Usage

On the first machine:

```bash
sip init
sip save -m "first"
sip invite
sip serve
```

`sip invite` prints a `sip2_` string holding this machine's addresses, its sync port, its
device ID and a one-time secret, then waits up to ten minutes for one machine to use it.
Then `sip serve` keeps the folder available.

On the second machine, in an empty folder:

```bash
sip join <invite>
sip sync
```

`sip join` records the first machine, and the first machine records the second, so there is
nothing to add by hand. `sip pair offer` and `sip pair enter` do the same with a code you
can read out instead of a string you paste.

The daemon serves every folder on the machine from one port, 8471 by default; the port is a
machine setting in `master.json` (`sip help config`). Run `sip help` for the command list, or
`sip help <command>` for detail on any one of them.

## Commands

`init`, `status`, `save`, `log`, `show`, `diff`, `blame`, `restore`, `tag`, `bisect`,
`verify`, `hooks`, `invite`, `join`, `pair`, `peer`, `sync`, `serve`, `id`, `lock`, `unlock`,
`bucket`, `doctor`, `config`, `push`, `inbox`, `quarantine`, `alerts`, `team`, `dm`,
`messages`, `pages`, `search`, `comments`, `net`, `help`.

Topics: `sip help keep-alive`, `sip help locking`.

### Locking a folder

```
sip lock            set a passphrase on this machine's copy
sip lock --off      remove it
sip unlock          check a passphrase opens it
```

Optional, off by default, and **per machine** — `.sip` is never synced, so each replica
keeps its own key and locking one leaves the others open. `sip help lock` states the four
things it does not cover; read it before relying on it.

For unattended use set `SIP_PASSPHRASE`, and read the warning in `sip help lock` about
where environment variables end up.

### Storage

```
sip bucket              what this folder is using, and what could be freed
sip bucket keep 20      keep the newest 20 snapshots
sip bucket keep 30d     keep 30 days
sip bucket quota 3GiB   refuse to grow past a size
sip bucket collect      delete what the policy no longer keeps
```

The reclaimable figure is shown whether or not anything is wrong, and it is a promise: what
it projects is what a collect frees.

### History, in your hands

```
sip show                        head's record, and what it changed
sip show 1a2b3c4d notes.md      one file, exactly as it was saved (redirect it)
sip diff v1 head                what changed between two snapshots, line by line
sip log notes.md                the saves that touched one file
sip blame notes.md              whose save each line is from
sip tag v1                      name head; a tagged snapshot survives retention
sip bisect start head v1        find the first snapshot where something broke
sip verify                      read the whole store back and check every hash
sip hooks set before-save "..."  your own command before each save, with a deadline
```

Snapshots are named by `head`, a full ID, a unique prefix, or a tag, everywhere one is
taken. Tags are per machine — `.sip` never syncs — and their one promise is local and
strong: a tagged snapshot survives every trim and collection here while the tag exists.
Bisect halves the suspect range each round and names the snapshot to restore and check;
verify reads through the same path a restore would, so what it passes is what you would
actually get; hooks are never on by default, run as you, and a hung one is stopped at its
deadline. `sip help` on any of them has the detail.

### Sending files to one of your machines

```
sip push on                          turn Direct Push on; it starts off
sip push laptop report.pdf photo.jpg send files to a paired machine's inbox
sip inbox                            what arrived here
sip inbox rules add --to D:\Invoices --type pdf
sip quarantine                       what arrived and was held back
sip quarantine release <hash>        bring a file back, under the name its content matches
```

Direct Push is the one exception to pull-only sync: you send particular files to one of your
own paired machines, over SippBucket's own SSH on its own port (8473), and they arrive in its
inbox. The receiving machine checks each file's bytes against its name: a program, whatever it
is called, and a file that is not what its name says go to quarantine, stored as they arrived
so the antivirus sees them, and released only by hand. Other people's machines can push only
once team features are on. `sip help push`, `sip help inbox` and `sip help quarantine` have
the detail.

### Working with other people

```
sip team                             whether team features are on, and why
sip team person add Ada laptop-ada   group a colleague's machines: one person, one count
sip dm Ada Lunch at noon?            send a direct message
sip dm Ada Here. --attach plan.pdf   with a file, sent as a Direct Push file
sip messages                         your conversations, each message's status
sip dm block Ada                     drop their messages; they are never told
```

Team features switch on when a team exists — you and 2 other people, or 2 in all by your own
exception — counted from the machines you answered "someone else's" about, with one person's
machines counting once (`sip team person`). Messages travel on Direct Push's connection and
wait on this machine until one of the person's machines can be reached: SippBucket is the
server, and no *central* server holds anything. Each copy is signed under its own context
label and checked against the machine that sent it. Statuses stop at *Delivered* — the most a
sender can verify — and *Sending* covers unreachable and blocked alike, so nothing you see can
say you are blocked. Stored messages are protected with Windows' per-user data protection, in
files whose names say nothing about who wrote to whom; text is shown as text, and an HTML file
is never run by SippBucket. `sip help team`, `sip help dm` and `sip help messages` have the
detail.

### The network

```
sip net                                   your networks, and where announcing is allowed
sip net allow                             announce on this network; unknown ones stay silent
sip config set network.portMapping 1      ask the router to forward the sync port; off by default
sip config set network.uploadKiBps 512    cap what this machine sends as blocks, machine-wide
sip config set network.downloadKiBps 0    the same for fetching; 0 is no ceiling, the default
```

Your machines find each other on a local network by fixed-size packets that identify
nothing — to anyone else they are indistinguishable from random noise — and announcing
happens only on networks you have allowed, once each; an unknown network is a refusal, not a
question deferred. Port mapping asks the router (PCP, NAT-PMP or UPnP, in that order) to
forward the sync port, and only when you turn it on. The two ceilings are token buckets
applied where block bytes actually move, so a background transfer cannot take the whole link
mid-video-call. While a transfer runs, `sip sync` prints its progress
(`Receiving · 812 / 1,284 blocks · from laptop`) and the daemon carries the same figure in
the folder's status; a large transfer asks your other machines what they hold and draws on
them too. `sip help net` and `sip help config` have the detail.

### A wiki, made of your files

```
sip pages                        the page tree, with each page's links in and out
sip pages links guide.md         one page's links and backlinks
sip search invoice march         find pages by words; runs here, sends nothing
sip comments add guide.md "Numbers in section 2 look off, @Ada"
sip comments guide.md            the margin of one page
sip comments mentions Ada        every comment that says @Ada
```

A folder of Markdown files synced by SippBucket is already a private wiki: every machine
holds all of it, offline, encrypted at rest, with full history. Pages open in your own
editor; these commands add the map, the search and the margins. Links are `[text](page.md)`
or `[[Page Name]]`, backlinks are computed, and a link to a page that does not exist yet is
shown as exactly that. Search reads Markdown and plain text and matches every file by name,
so a Word document is found by what it is called. When two people edit the same Markdown
page, edits that do not touch are merged into one file — both sides' words, nothing lost —
and edits that touch keep both copies, as every other file type does. Comments are small
signed files under `.sip-comments`, so they sync, work offline and never conflict; writing
one is a team feature, like `sip dm`.

### When another machine sends something wrong

```
sip alerts                          what was noticed, and what waits for your answer
sip alerts answer 3 me              that was me: apply the change it held
sip alerts answer 3 not-me          not me: keep it out, and take nothing more from that machine
sip peer health                     what each machine did wrong, and what it says about itself
sip peer health clear "Server 2"    take its changes again
```

A change that looks like damage is held, kept and not applied, and you are asked once. Faults a
machine commits (bad blocks, wrong snapshots, unsafe paths) are refused and counted, and five of
one kind in a day raise an alert. Every alert and answer is kept for good in `alerts.jsonl` and
never leaves this machine. The thresholds are in `master.json`'s `health` section; the checks
cannot be switched off. `sip help alerts` and `sip help peer` have the detail.

### Checking the standards

```
sip doctor
```

Checks this folder against the project's minimum standards, and prints the five rules it
cannot check rather than implying a clean run covers them. Its `PUSH` lines cover this
machine's Direct Push.

### Antivirus, and folders it watches

Norton's Data Protector and Windows Defender's Controlled folder access refuse writes into
Documents-shaped folders from programs they have not been told to trust, and the refusal
reads as a permissions error. SippBucket recognises the common cases and says what is
actually happening — allow SippBucket in the protection's own settings, or keep synced
folders elsewhere — and `sip doctor` says it before it bites. It never fights the
protection: a refused write is reported, not retried into, and the quarantine is stored
unencrypted precisely so the antivirus can read every byte of it.

### The manual

`sip help` is the manual and `sip help <command>` its pages, built from the same tables the
code enforces so they cannot drift.
