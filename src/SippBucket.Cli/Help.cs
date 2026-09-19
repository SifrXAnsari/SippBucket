using System.Globalization;
using SippBucket.Core.Configuration;

namespace SippBucket.Cli;

/// <summary>
/// The help text. This is a first-class part of the tool, not an afterthought: the command
/// surface is small precisely so that every command can be documented properly, and a power
/// user is expected to read this rather than guess.
/// </summary>
internal static class Help
{
    public static void PrintOverview()
    {
        Console.WriteLine(
            """
            sip - SippBucket, a peer-to-peer document aggregator.

            Your documents live on every machine you own. Each machine is a server: they
            talk to each other directly, over a LAN or over the wire, with no account and
            no service in the middle.

            USAGE
              sip <command> [options]

            COMMANDS
              init        Turn the current folder into a repository
              status      Show what has changed since the last save
              save        Take a snapshot of the current folder
              log         List snapshots newest first, or one file's history
              show        One snapshot's record, or one file exactly as it was saved
              diff        What changed between two snapshots, line by line
              blame       Whose save each line of a file is from
              restore     Put the folder back to a snapshot
              tag         Name a snapshot; a tagged snapshot survives retention
              bisect      Find the first snapshot that carries a problem, by halving
              verify      Read the whole store back and check every hash
              hooks       Your own commands around a save, with a deadline
              invite      Print a one-time sip2_ invite another machine can paste, and wait
              join        Join a repository with a sip2_ invite
              peer        Add, list and remove the machines you sync with
              sync        Pull changes from every peer, once
              serve       Run the daemon and answer peers until stopped
              id          Who this machine is: Server.ID, its number and its device ID
              lock        Put this machine's copy behind a passphrase
              unlock      Check a passphrase, or unlock for one command
              bucket      Show storage use, set retention, reclaim space
              pair        Offer a spoken code, or enter one from another machine
              doctor      Check this folder against the minimum standards
              config      Show, check or set this machine's settings (master.json)
              push        Send files straight to one of your machines (Direct Push)
              inbox       What arrived by Direct Push, and your forwarding rules
              quarantine  What arrived and was held back: disguised files, programs
              alerts      What was noticed about your other machines, and what it asks
              team        Whether team features are on, and who counts as one person
              dm          Send a direct message to a person on your servers
              messages    Read your conversations, and each message's status
              pages       The folder's Markdown pages: the tree, links and backlinks
              search      Find words across the folder's pages, here and only here
              comments    Read and write comments on pages; a team feature to write
              net         This machine's networks, and where announcing is allowed
              help        Show this text, or detail for one command

            TOPICS
              keep-alive  How SippBucket stops the machine sleeping mid-transfer
              locking     What a passphrase does and does not protect

            GETTING STARTED
              On the first machine:
                1. sip init                     turn the folder into a repository
                2. sip save -m "first"          snapshot what is there
                3. sip pair offer               shows a code and this machine's
                                                addresses, and waits

              On the second machine, in an empty folder:
                4. sip pair enter <address>:8471 <code>
                                                become a replica

              Both machines now list each other as peers; there is nothing to add
              by hand. Then:
                5. sip serve                    on the first machine, and leave it
                6. sip sync                     on the second, to pull everything

              'sip invite' and 'sip join' do the same as steps 3 and 4 with a string
              you paste instead of a code you read out.

            There are no branches. There is no staging area. You save, and you sync.

            Run 'sip help <command>' for detail on any command.
            """);
    }

    public static bool PrintCommand(string command)
    {
        var text = command.ToUpperInvariant() switch
        {
            "INIT" =>
                """
                sip init [--mode power|simple] [--name <name>]

                Creates a repository in the current folder. Writes a .sip directory holding
                the config, the object store and the snapshot chain. Nothing outside .sip is
                touched, and no files are moved.

                OPTIONS
                  --mode power    Keep every snapshot, so any past state can be restored.
                                  This is the default and what a power user usually wants.
                  --mode simple   Keep only the newest snapshot. The folder still syncs
                                  everywhere; there is simply no history to think about.
                  --name <name>   A label for the repository. Defaults to the folder name.

                There is no --port any more. One port serves every folder on this machine,
                8471 unless master.json says otherwise; see 'sip help config'.

                NOTES
                  The repository encryption key is generated here and written to
                  .sip/config.json in the clear. Anyone who can read that file can read the
                  object store. Protecting it with a passphrase is not yet implemented.
                """,

            "STATUS" =>
                """
                sip status

                Compares the folder against the newest snapshot and lists what is added,
                modified and removed.

                This command never writes. A file whose size and modification time both
                match the newest snapshot, and whose modification time is more than two
                seconds older than that snapshot, is taken as unchanged without being
                read. Every other file is read and its blocks compared. So an edit that
                leaves both the size and the modification time as they were is not seen
                until one of them moves.

                NOT READ
                  Links (junctions and symbolic links) are never followed, so nothing
                  behind one is synced from here. A folder that cannot be listed, a file
                  another program holds open without sharing, and a file that changes
                  every time it is read are skipped too, and what was last recorded for
                  them is kept. Each is listed first, with the reason, and counted in none
                  of the lists below it.
                """,

            "SAVE" =>
                """
                sip save [-m <message>]

                Takes a snapshot of the folder as it is now and makes it the newest.

                Every file is split into blocks, each block is hashed and stored encrypted,
                and the snapshot records the block hashes. Blocks that already exist are not
                written again, so saving an unchanged 2 GB file costs almost nothing.
                Block boundaries follow the content rather than fixed offsets, so an edit
                anywhere in a large file, even an insertion at the very start, stores only
                the blocks around the edit, not the whole file again. Two saves are the
                exception and store the whole file once: the first save of a file changed
                since it was saved by a build older than this one, and a save after a file
                crosses a size step (250 MiB, 500 MiB, 1000 MiB, about 2 and 4 GiB).

                If nothing has changed, no snapshot is created and the command says so.

                What the save could not read - a link, which is never followed, or a file
                or folder the system refused - is listed first. The save goes ahead with
                everything else, and keeps what the newest snapshot recorded for those,
                so nothing is recorded as deleted because it could not be looked at.

                One thing at a time writes to a folder: if the tray, or another sip command,
                is saving, syncing or restoring this folder at that moment, this waits a few
                seconds, then stops without changing anything and says what holds it. The
                same goes for sync, restore, bucket collect and lock.

                OPTIONS
                  -m <message>    A note about this save. Optional.
                """,

            "LOG" =>
                """
                sip log [-n <count>] [<file>]

                Lists snapshots newest first, walking backwards through the chain. With a
                file, lists the saves that touched that file instead: added, changed,
                removed - a rename reads as a remove and an add, under each name - and
                'present' where the file is there but the snapshot before it is no longer
                held, so what changed cannot be told.

                In simple mode only the newest snapshot is kept, plus the last one shared
                with each peer, which the next merge with that peer compares against, and
                the one the last 'sip restore' replaced, so the restore can be undone. So
                this shows one entry, or a few more. A shared one that came from the other
                machine may be a file list only, without its blocks: it is enough to merge
                against, and 'sip restore' of it stops with a missing block and changes
                nothing.

                OPTIONS
                  -n <count>      Show at most this many. Default 20.
                """,

            "SHOW" =>
                """
                sip show [<snapshot>] [<file>]

                One snapshot's whole record: its ID, format, the device that made it and
                whether its signature proves that, its date, parents, message, and what it
                changed against its parent. With no snapshot, head. With a file as well,
                prints that file's bytes exactly as the snapshot recorded them - pipe or
                redirect it to get an old version back without touching the folder:

                  sip show 1a2b3c4d notes.md > notes-as-it-was.md

                NAMING A SNAPSHOT
                  Every command that takes a snapshot takes it in any of these forms:
                  'head'; a full ID; enough of an ID's start to be unique; or a tag's name
                  ('sip tag'). A tag wins over an ID prefix spelled the same, because the
                  thing you named beats the thing that merely matches.
                """,

            "DIFF" =>
                """
                sip diff <a> <b> [<file>]

                What changed between two snapshots, oldest first reads best: each added,
                removed or changed file, text ones as unified line diffs. With a file,
                only that file. Lines are compared exactly, byte for byte after UTF-8
                decoding, except that a Windows line ending equals a Unix one - the same
                reading sync itself uses. A file with a NUL among its first bytes is
                called binary and only named, and a file past 8 MiB is only named, because
                a screen of its lines helps nobody.

                The two snapshots are named as 'sip help show' describes: head, an ID, an
                ID prefix, or a tag.
                """,

            "BLAME" =>
                """
                sip blame <file>

                Every line of the file as it stands at head, with the snapshot, machine
                and date whose save introduced it. 'you' is this machine; your other
                machines carry their peer names.

                It walks this machine's held history along first parents: the other side
                of a merge is credited to the merge itself, and history behind a snapshot
                this machine no longer holds is credited to the oldest one it does. Text
                files up to 8 MiB; 'sip log <file>' lists the saves themselves.
                """,

            "RESTORE" =>
                """
                sip restore <snapshot-id>

                Puts the folder back to the state of a snapshot, then saves the result as a
                new snapshot on top of the newest one. Missing files are written and saved
                files are replaced. Nothing is lost that no snapshot holds:

                  - A file you changed since your last save, where the snapshot has a
                    different version, is kept: it is renamed to
                    <name>.conflict-<device>-<timestamp><ext>, <device> being this
                    machine, and the snapshot's version takes the name. A read-only file
                    in the way is kept the same way. Each one kept is listed.
                  - A file the snapshot does not have is deleted only if your last save
                    has it, it has not changed since, and it is not read-only. New files
                    you never saved, and changed ones, stay where they are.
                  - Names are compared the way Windows compares them. A file whose name
                    differs from the snapshot's only in case is renamed to the snapshot's
                    casing, never deleted. Folder names keep their casing.
                  - A file this folder's .sipignore matches, and anything that is a link
                    or lies under one, is never written, replaced or deleted.

                Every file is written in full inside .sip first. If a block is missing, the
                folder is at its quota, or a file that would change is open in another
                program, nothing in the folder changes and the command says why.

                HISTORY MOVES FORWARD
                  The restore is recorded as a new snapshot whose parent is the snapshot
                  that was newest before it, like any other save. So the restore removes
                  nothing newer from 'sip log' - only a retention policy removes
                  snapshots, as it does after any save - and your other machines receive
                  the restore at their next sync instead of undoing it. To go back again,
                  restore the snapshot the restore was made on top of. Everything left in
                  the folder is in that new snapshot too: files you never saved, and the
                  copies kept aside. If the folder already matched the newest snapshot,
                  nothing is recorded.

                  In simple mode, which keeps no history, the snapshot a restore was made
                  on top of is kept until the next restore, so going back works there too.

                The snapshot is named as 'sip help show' describes: head, a full ID, a
                unique ID prefix, or a tag.
                """,

            "TAG" =>
                """
                sip tag
                sip tag <name> [<snapshot>]
                sip tag remove <name>

                Names for snapshots. With nothing, lists them. With a name, tags a
                snapshot - head unless one is given - and with 'remove', deletes the name.

                A tag's one promise is local and strong: for as long as the tag exists on
                this machine, the snapshot it names survives retention here - simple
                mode's trimming, 'sip bucket keep', and every collection - and so do its
                blocks. Removing the tag releases that at the next collection, unless
                something else keeps it.

                PER MACHINE
                  Tags live in .sip, which never syncs, so a tag made on the desktop does
                  not appear on the laptop, and does not protect the snapshot there. Tag
                  it on each machine that should keep it.

                NAMES
                  1 to 64 characters: letters, digits, '.', '-' and '_', not starting
                  with '.' or '-'. Anywhere a command takes a snapshot, its tag's name
                  works, and beats an ID prefix spelled the same.
                """,

            "BISECT" =>
                """
                sip bisect [status]
                sip bisect start <bad> <good>
                sip bisect good <snapshot>       sip bisect bad <snapshot>
                sip bisect reset

                Finds the first snapshot that carries a problem - a broken document, a
                wrong figure - by halving. Mark the newest snapshot where it is wrong and
                any snapshot where it was still right; each round names the snapshot that
                splits the remaining range most evenly. Restore it, look, and mark it:

                  sip restore <the one it names>
                  ...check your files...
                  sip bisect good <it>     or     sip bisect bad <it>

                About log2 of the range in rounds, one snapshot remains, and it is named
                with its date, machine and message. 'sip bisect reset' ends the search;
                nothing here ever touches the folder itself - restoring is your own
                'sip restore', which keeps unsaved work aside as it always does.

                It reasons over this machine's ancestry record, so it sees through
                snapshots no longer held as files, and only held ones are suggested for
                testing, because a suggestion that cannot be restored cannot be tested.
                """,

            "VERIFY" =>
                """
                sip verify

                Reads the whole store back and checks everything against its own name:
                every snapshot file authenticates under its ID and, for one saved by this
                build, carries a signature by the device it names; every tree and every
                block decrypts and re-hashes to the hash a snapshot records for it. What
                verify passes is what a restore or a served peer would actually get,
                because it reads through the same path.

                Problems are listed and the exit code is 1; nothing is repaired. The
                repair for a damaged or missing block is fetching it again from a peer at
                the next sync, and a damaged snapshot is worth keeping as evidence.
                Blocks nothing refers to are counted separately: they are what
                'sip bucket collect' reclaims, not damage.
                """,

            "HOOKS" =>
                """
                sip hooks
                sip hooks set before-save|after-save <command...> [--deadline <seconds>]
                sip hooks remove before-save|after-save
                sip hooks test before-save|after-save

                Your own commands around a save. Never on by default: no hook exists until
                you write one, and they are this machine's only - .sip never syncs, so a
                synced folder cannot carry a command onto another machine. Hooks run as
                you, with no elevation, in this folder, on 'sip save' and on the daemon's
                automatic saves. They do not run for a merge sync records, a restore's
                record, or anything else that is bookkeeping rather than you saving.

                BEFORE-SAVE
                  Runs first, before anything is scanned, so what it writes - a
                  formatter's output, say - is what the save records. If it exits
                  non-zero, or runs past its deadline, the save is refused and the
                  command's last words are shown. That refusal is the feature.

                AFTER-SAVE
                  Runs once the snapshot is recorded, with SIP_SNAPSHOT naming it. Its
                  failure is reported and changes nothing: the save already happened.

                THE DEADLINE
                  Every hook has one - 30 seconds unless set, at most 600. Past it the
                  command and every process it started are stopped, so a hung hook cannot
                  wedge the daemon's saves.

                WHAT THE COMMAND SEES
                  It runs under cmd.exe in the folder being saved, with SIP_FOLDER,
                  SIP_REPOSITORY, SIP_MESSAGE and, after a save, SIP_SNAPSHOT set.
                  'sip hooks test' runs one now, the same way, and says what happened.
                """,

            "INVITE" =>
                """
                sip invite [--host <address>]... [--owner mine|someone-else]

                Opens a pairing window and prints a sip2_ string for another machine to
                paste into 'sip join'. Then waits, like 'sip pair offer': for ten minutes,
                for one machine, for five failed attempts at most. Ctrl+C stops waiting.

                It is the pasteable form of 'sip pair'. The same exchange runs underneath;
                the only difference is a 128-bit secret you paste instead of a 48-bit code
                you read out.

                WHAT THE STRING HOLDS
                  This machine's addresses, its sync port, its device ID, and a one-time
                  secret. Not the folder's key. The key is sent only after the other
                  machine has proved it holds the secret, encrypted under a key derived
                  from that exchange, so it reaches that machine and nothing on the way.

                  Old sip1_ invites held the key itself, in plain text, and 'sip join'
                  now refuses them. If you ever sent one, anyone who saw it can read the
                  folder; there is no way to change a folder's key yet.

                OPTIONS
                  --host <address>  An address to put in the invite instead of this
                                    machine's own: a host name or IPv4 address, with
                                    no port, or with this folder's own; the invite
                                    carries that port. Repeat it to list several; the
                                    other machine tries them in order. By default the
                                    invite lists every usable IPv4 address this machine
                                    has, those on a network with a gateway first. Left
                                    out: loopback, link-local 169.254.x.x (what Windows
                                    assigns when nothing else did), and the virtual
                                    switches Hyper-V and WSL keep inside this PC. A VPN
                                    address, such as Tailscale's, is kept, after the
                                    others.
                  --owner <whose>   mine or someone-else: whose machine the one that
                                    joins is. Asked when it joins if it is not given
                                    and not already answered. See 'sip help pair',
                                    WHOSE MACHINE IT IS.

                  SippBucket listens on IPv4 only. It does not listen on IPv6 yet, so an
                  IPv6 address could not reach it, and --host refuses one.

                SECURITY, AND ITS LIMIT
                  Someone who only watches the network cannot get the secret, the key or
                  either machine's device ID from the exchange, and has nothing to test
                  guesses against later. They can see that two addresses talked.

                  What protects nothing is the string itself in the wrong hands. Whoever
                  uses it first, within the ten minutes, joins instead of your machine and
                  receives the key to every document in the folder. Send it privately, and
                  if it went somewhere it should not have, let it expire or press Ctrl+C.
                """,

            "JOIN" =>
                """
                sip join <sip2_...> [--mode power|simple] [--name <peer-name>]
                         [--owner mine|someone-else]

                Joins the repository a 'sip invite' on another machine is offering, and
                turns the current folder into a replica of it. The folder must not already
                be a repository, and should be empty.

                It dials the addresses in the invite in order and pairs through the first
                that answers, with the invite's secret as the password. It records the
                other machine at the address it actually reached, and that machine records
                this one at the address the connection came from - so both ends know each
                other and there is nothing to add by hand. Run 'sip sync' afterwards to
                pull the contents down.

                It also checks that the machine that answered is the one that made the
                invite, by the device ID the invite names, before it says anything about
                itself. A mismatch stops there and writes nothing.

                Nothing is written until the exchange has finished. A refusal - a wrong,
                expired or already-used invite, which all look the same from here on
                purpose - leaves the folder exactly as it was.

                A sip1_ invite is refused, with the reason: it carries the folder's key in
                plain text.

                Joining a folder that holds a .sip left from an earlier repository, a peer
                list and no config, keeps that peer list. Every other machine in it is
                named when the join finishes, because this copy will try to sync with
                each of them; remove any you do not want with 'sip peer remove'.

                OPTIONS
                  --mode <mode>   power or simple. Each replica chooses independently: one
                                  machine can keep history while another keeps only the
                                  newest snapshot.
                  --name <name>   What to call the inviting machine locally. Default
                                  'origin'.
                  --owner <whose> mine or someone-else: whose machine the inviting one is.
                                  Asked when the join succeeds if it is not given and
                                  not already answered. See 'sip help pair', WHOSE
                                  MACHINE IT IS.

                The other machine records this one at this machine's port, which serves
                every folder here: 8471 unless master.json says otherwise.
                """,

            "PEER" =>
                """
                sip peer add <name> <device-id> <host>[:<port>]
                sip peer list
                sip peer remove <device-id | id-prefix | name>
                sip peer owner <device-id | id-prefix | name> mine|someone-else
                sip peer role <device-id | id-prefix | name> read-only|read-write
                sip peer expire <device-id | id-prefix | name> <yyyy-mm-dd | never>
                sip peer health [<server>]
                sip peer health clear <server>
                sip peer port-updated

                Manages the machines this repository syncs with.

                A peer is trusted by its device ID, not its address. The address may change
                when a machine moves from a LAN to a mobile connection; the Ed25519 identity
                does not, and that is what authentication is pinned to.

                A daemon refuses any device that is not in its own peer list. Pairing -
                'sip pair' or 'sip invite' and 'sip join' - records both machines on both
                ends for you. 'sip peer add' is for doing it by hand, and then both
                machines must add each other.

                Get a machine's device ID by running 'sip id --device' on it.

                ADDRESSES
                  <host>[:<port>] is a host name or IPv4 address. The port is the other
                  machine's sync port. Left out, it is taken to be this machine's own, 8471
                  unless master.json says otherwise. An IPv6 address goes in brackets,
                  [fe80::1]:8471, so its colons cannot be mistaken for the port - but
                  SippBucket does not listen on IPv6 yet, so a peer at an IPv6 address will
                  not connect for now.

                ADDING A MACHINE THAT IS ALREADY LISTED
                  There is one entry per device ID, so adding the same device again
                  replaces its name and address. The command says which name and address
                  it replaced. When it last synced is kept. Pairing the same machine again
                  does the same, and says so the same way.

                REMOVING A PEER - AND WHAT REMOVAL NOW MEANS
                  Name the machine by its full device ID, by the short ID 'sip peer list'
                  prints (any prefix of 8 or more hex characters that only one machine
                  has), or by its name.

                  A name works only when exactly one peer has it. Names are labels, and
                  two machines can easily share one: pairing names a joining machine after
                  its own host name. If what you type could mean more than one machine,
                  nothing is removed. The candidates are listed with their IDs so you can
                  pick one.

                  Removing a machine ROTATES THE FOLDER'S KEY: a fresh key becomes
                  current, everything written from then on is under it, and the removed
                  machine never receives it. Your other machines learn the new key, and
                  the removal, at their next sync, and drop the removed machine before
                  they store it - so no machine that has heard of the removal can hand
                  the new key on. The old keys stay on the remaining machines so
                  everything already written stays readable. What rotation cannot do,
                  said plainly: un-share the past. The removed machine holds, or could
                  have copied, everything from before the removal. On a machine whose
                  copy is locked, unlock first: the rotated ring has to be resealed.

                READ-ONLY MEMBERS
                  'sip peer role <machine> read-only' means no change that machine MAKES
                  is taken here, ever. It can still read everything - it holds the key,
                  and a rule that pretended otherwise would be a lie. Enforced against
                  the maker, not the messenger: every snapshot is signed by the device
                  that made it, so a read-only machine relaying someone else's change
                  still serves it, and its own saves are refused wherever they arrive.
                  Set the role on each of your machines; peer settings are per machine.

                MEMBERSHIP WITH AN END DATE
                  'sip peer expire <machine> 2027-01-31' ends the membership at that UTC
                  date: from then this machine neither serves nor dials it, and says why
                  rather than looking like an outage. Expiry cuts off what comes after
                  it. It does not rotate the key - 'sip peer remove' is the departure
                  that means something.

                WHOSE MACHINE IT IS
                  'sip peer list' says, for each machine, whether you answered that it is
                  yours, someone else's, or have not answered. 'sip peer owner' answers or
                  changes it, named the same way 'remove' names a machine. The answer is kept
                  once for each machine, in machines.json beside the device key, so it holds
                  for every folder you share with that machine. Not answered counts as
                  someone else's wherever that protects you. See 'sip help pair'.

                HEALTH
                  'sip peer health' is what this machine has seen each other machine do,
                  kept for every folder at once, in health.json beside the device key. It
                  needs no folder open. Name a machine to see one: "Server 2", its
                  Server.ID, its label, the name you gave it, or 8 or more characters of
                  its install ID.

                  Two kinds of evidence, never mixed:
                    What it did      blocks that did not match their hash, snapshots that
                                     were not the ones asked for, paths that tried to leave
                                     the folder, malformed messages, failed handshakes,
                                     stalls, clocks hours ahead, pushes that went to
                                     quarantine. Each was refused and counted. Five of one
                                     kind in a day (health.faultsPerDay) raise one alert.
                    What it says     what one of your own machines reports about its
                    about itself     settings, its clock and its version, against the safe
                                     ranges. A machine can be wrong, or lie, about itself,
                                     so this is shown and never alerted.

                  A machine you answered "not me" about ('sip help alerts') is SUSPECT: no
                  change of its is taken, in any folder, and your other machines go on
                  syncing. 'sip peer health clear <server>' takes its changes again. It
                  clears every install of that server, and refuses a name that could mean
                  more than one machine.

                  Health is guidance, not authority: nothing here fixes, disables or judges
                  another machine.

                A RECORD THAT CANNOT BE USED
                  The peer list is .sip/peers.json and can be edited by hand. A record whose
                  device ID is missing or is not 64 hexadecimal characters, which has no
                  name, or which is not a peer at all is skipped: nothing syncs with it or
                  trusts it. 'sip peer list' and 'sip doctor' show each one, with its place
                  in the file and what is wrong. Nothing rewrites the file to drop it; fix it
                  there, or remove it by name, or by its device ID typed exactly.

                  A file that is not valid JSON at all, with a comma missing between two
                  records say, has no records to skip: the reader cannot tell where one
                  ends. Every peer command then stops and names the file and the line to
                  mend, and nothing is written to it.

                AFTER MOVING THIS MACHINE'S PORT
                  Every folder is served on this machine's port, server.listenPort in
                  master.json. A folder remembers the port its peers were given when it was
                  set up, and 'sip doctor' warns while the two differ. Give every paired
                  machine the new port with 'sip peer add' on that machine, then run
                  'sip peer port-updated' here: it records that they have it, and the warning
                  stops. It changes nothing about how the folder is served.
                """,

            "SYNC" =>
                """
                sip sync

                Contacts every peer in turn and pulls whatever this machine does not have.

                Sync is a pull, run from both ends. Nothing is pushed, so no machine has to
                be reachable for the other to make progress.

                WHAT HAPPENS ON A CONFLICT
                  If both machines changed the same file since their last common snapshot,
                  neither change is discarded. The local copy is renamed to
                  <name>.conflict-<device>-<timestamp><ext> and the incoming version takes
                  the original name. Both files remain, and the result is saved as a new
                  snapshot.

                  <device> is the first eight characters of the device ID of the machine
                  that made the renamed version - the machine the rename happened on, whose
                  copy it was. 'sip id' prints a machine's device ID.

                  A read-only file here is never overwritten or deleted. If the other
                  machine changed it, it is kept the same way, under a conflict name, and
                  the incoming version takes the name. If the other machine deleted it, it
                  stays, and the next save records it again.

                WHAT IS LEFT ALONE
                  A path this folder's .sipignore matches, or the incoming .sipignore
                  matches, and anything that is a link or lies under one: nothing is
                  written or deleted there, whatever the other machine did.
                """,

            "SERVE" =>
                """
                sip serve

                Runs the server in the foreground for this folder: listens on this
                machine's port and answers peers until interrupted with Ctrl+C.

                The port is the machine's, not the folder's: one port serves every folder on
                this machine, 8471 unless master.json says otherwise (see 'sip help config').
                The tray serves every watched folder on that same port, so 'sip serve' is
                for a machine where the tray is not running; beside it, it says the port is
                in use.

                The server only answers questions - what is your head, give me this
                snapshot, give me these blocks. It never writes to this repository on a
                peer's instruction, so a misbehaving peer cannot change anything here.

                Blocks are served still encrypted, exactly as they sit on disk.
                """,

            "PAIR" =>
                """
                sip pair - add a machine with a code you can say out loud

                USAGE
                  sip pair offer [host] [--owner mine|someone-else]
                                                       show a code and wait
                  sip pair enter <host[:port]> <code>  join using one, in an empty folder
                        [--mode power|simple] [--name <peer-name>] [--owner mine|someone-else]
                                                       the same options as 'sip join'

                WHOSE MACHINE IT IS
                  When a pairing succeeds, each side is asked once: "Is this another of your
                  machines, or someone else's?" --owner answers it on the command line.
                  The answer is kept once for each machine, for every folder you share with
                  it, so pairing the same machine into another folder does not ask again.

                  Someone else's machine: that person can read everything in the folder,
                  its whole history included, and removing them later does not take back
                  what they already have. SippBucket says so every time you share a folder
                  with them. Their files and messages never reach your synced folders by
                  a forwarding rule unless the rule names them, their inbox space is capped,
                  and this machine's Server.ID is never sent to them.

                  Left unanswered, which is what happens when a script runs the command and
                  nobody can answer, the machine is treated as someone else's for all of
                  that. Answer later with 'sip peer owner'.

                Replaces pasting a 400-character invite between two computers, which was the
                worst interaction in this product and was worst for the newest user.

                WHAT IT DOES
                  'offer' opens a pairing window on the sync port plus one, prints a code,
                  and prints this machine's usable IPv4 addresses, those with a gateway
                  first, as ready-made 'sip pair enter' lines, so you can read out
                  whichever one the other machine can reach. Loopback, link-local
                  169.254.x.x and the Hyper-V and WSL virtual switches inside this PC are
                  left out; a VPN address such as Tailscale's is kept, last. Given a host,
                  it prints just that one. It then waits until the code is used, burnt or
                  expired.

                  If the machine you are adding hangs up or goes quiet part way, it does
                  not hold the window: several connections are served at once, one that
                  says nothing gives way to a new one, and none lasts more than thirty
                  seconds. Only a connection that makes a guess spends one of the five.

                ADDRESSES
                  <host[:port]> is a host name or IPv4 address, with :port when it is not
                  8471. An IPv6 address goes in brackets, [fe80::1] or [fe80::1]:8471, so
                  its colons cannot be mistaken for the port - but SippBucket does not
                  listen on IPv6 yet, so an IPv6 address will not reach it for now, and
                  'offer' refuses one. The host given to 'offer' takes no port, or only
                  this folder's own.

                  'enter' dials that address, proves it has the same code, and receives the
                  folder. It records the offering machine at the address it dialled; the
                  offering machine records it at the address the connection came from. Both
                  ends know each other afterwards, and there is nothing to add by hand.
                  Nothing is written on the joining machine unless the whole exchange
                  succeeds.

                  The port in <host[:port]> is the other machine's sync port, as 'offer'
                  prints it; the pairing window is one above it. Left out, it is taken to be
                  this machine's own port, 8471 unless master.json says otherwise, which is
                  right whenever both machines use the same one.

                THE ALPHABET IS THE DESIGN
                  2345679AFHMQRWXY. Sixteen symbols, and sixteen is not a round number
                  picked for tidiness - it is what survives filtering for characters that
                  look alike AND characters that SOUND alike.

                  The rhyming set is the hard constraint: B C D E G P T V Z all sound the
                  same across a room, and removing them costs nine of the twenty-six letters
                  in one stroke. Then J and K collide with A, N with M, S with F, H with the
                  digit 8, and U with Q. Nine letters and seven digits survive, and there is
                  no spare letter left to add.

                  Being a power of two is a real benefit rather than a coincidence: each
                  character is exactly one nibble, so a code is cut straight from random
                  bytes with no modulo bias and no rejection loop to get subtly wrong.

                  If you mistype S, Z or G they are read as 5, 2 and 6. O, I, L, B, 0, 1 and
                  8 are rejected rather than guessed at - their look-alikes were removed
                  too, so forgiving them would resolve one wrong character into another and
                  tell you the code is wrong instead of which character is.

                YOU ALSO NEED THE ADDRESS
                  Discovery cannot introduce two machines that have never met. It drops any
                  announcement whose device ID is not already a configured peer, on purpose -
                  it answers "where is the machine I already trust", not "who else is here".
                  So pairing is a deliberate act and the address is typed.

                THE CODE NEVER CROSSES THE NETWORK
                  Pairing is CPace (draft-irtf-cfrg-cpace-21, ristretto255 with SHA-512), a
                  password-authenticated key exchange. Each machine sends a value derived
                  from the code and a fresh random number; both arrive at the same key only
                  if they used the same code. Each then proves it got that key before
                  anything secret moves, and the folder's key is sent encrypted under it.

                  So somebody recording the traffic has nothing to test guesses against:
                  not the code, not a hash of it, not anything sealed under it. The only
                  way to try a code is to take part in an exchange, one guess each time,
                  against a machine that is counting. Neither machine's device ID crosses
                  in the clear either.

                WHAT DEFENDS IT
                  Not the 48 bits. An attacker managing an unrealistic 10,000 guesses a
                  second for the whole ten-minute window still only reaches about one in 47
                  million. The control is the BUDGET: five wrong answers and the code is
                  dead, and the port closes. Twelve characters is the length at which a bug
                  in that budget would not be a breach.

                  An attempt is counted before the offering machine answers, so hanging up
                  without finishing still spends one. Wrong, expired, burnt and closed all
                  look the same from the other end, because which one it was tells you
                  whether a window is open - and that is worth more to a guesser than
                  knowing one guess was wrong.

                WHAT IT DOES NOT DEFEND AGAINST
                  Someone who hears the code. It is a password, and whoever uses it first,
                  within the ten minutes, is the one who pairs - instead of your machine.
                  The exchange protects the code from the network, not from the room.

                  Someone who has the code and sits between the two machines can pair each
                  side with itself. Nothing in the exchange can tell that apart from you
                  pairing, because it has what you have.

                WHAT IT HANDS OVER
                  The key that decrypts every document in the folder, now and in every
                  snapshot you have ever taken, to whichever machine proves it has the code.
                  Say the code out loud to the person at the other machine. Do not paste it
                  into a chat - use 'sip invite' for pasting.

                """,

            "DOCTOR" =>
                """
                sip doctor - check this folder against the minimum standards

                USAGE
                  sip doctor

                Exits non-zero if any check fails. Warnings do not fail the run.

                It reads and never repairs. A tool that fixed things while reporting on
                them could not be used to find out what is wrong.

                THIS MACHINE'S SETTINGS
                  Lines marked CFG are this machine's master.json: every setting whose value
                  differs from its default (a note: somebody chose it), and every entry that
                  was ignored or fell back to its default (a warning: somebody chose it and
                  did not get it). See 'sip help config'.

                DIRECT PUSH
                  Lines marked PUSH are this machine's Direct Push, whichever folder you run
                  the doctor in: whether it is on, whether anything answers on its port,
                  the inbox's free space, how full the quarantine is, and any forwarding
                  rule that is passed over. To see whether the port answers, the doctor
                  connects to it once; SippBucket's activity records that as a connection
                  that ended during the handshake. See 'sip help push'.

                IT PRINTS THE RULES IT CANNOT CHECK
                  Five of the standards need a person: whether a screen states its limits,
                  whether a quotation resolves to a source that contains it, whether each
                  claim was measured with the right instrument, whether each regression test
                  has been seen to fail with its fix reverted, and whether anyone outside the
                  project has reviewed how SippBucket maps onto Noise.

                  These are listed with a -- marker rather than omitted, because a tool that
                  says "all checks passed" while silently skipping the rules it cannot
                  verify is committing the exact offence the first standard exists to
                  prevent: claiming more than it has checked.

                SEE ALSO
                  STANDARDS.md, which has the full list and, for each rule, the defect in
                  this project that caused it to be written down.

                """,

            "BUCKET" =>
                """
                sip bucket - storage use, retention, and reclaiming space

                USAGE
                  sip bucket                 show what this folder is using
                  sip bucket keep all        keep every snapshot (the default)
                  sip bucket keep 20         keep the newest 20 snapshots
                  sip bucket keep 30d        keep 30 days of history
                  sip bucket quota 3GiB      refuse to grow past a size
                  sip bucket quota none      remove the cap
                  sip bucket collect         delete what the policy no longer keeps

                A bucket is this folder's store: its blocks and its snapshots. 'sip bucket'
                reports what it holds and, more usefully, what could be released.

                RECLAIMABLE IS THE NUMBER THAT MATTERS
                  "Full" on its own is a dead end - it tells you there is a problem and
                  nothing you can do about it. "Full, and 1.2 GiB is held by snapshots older
                  than your retention window" is a decision. So the reclaimable figure is
                  reported always, not only when something goes wrong.

                  It is also a promise: the figure shown before a collect is the figure the
                  collect frees.

                WHAT GETS DELETED
                  Snapshots the retention policy no longer keeps, and then every block that
                  no surviving snapshot refers to. Mark and sweep, in that order, because
                  sweeping first would compute the live set from snapshots that are about to
                  vanish - merely wasteful - while deleting snapshots against a stale live
                  set would sweep blocks the survivors still need, which is data loss.

                  The newest snapshot always survives, whatever the policy says. A
                  "keep 0" rule cannot delete the only record of what is in your folder.

                SIMPLE MODE USED TO GROW FOREVER
                  Simple mode trims the chain after every save so there is never any history
                  to reason about - but it never deleted the blocks those snapshots pointed
                  at. The mode that exists to stay small grew without bound, and grew faster
                  than Power mode would have. It now collects on every save.

                BINARY UNITS
                  GiB and MiB, meaning 1024, and labelled as such. Sizes are parsed the same
                  way: 3GiB, 500MiB, or a plain byte count.

                """,

            "LOCK" =>
                """
                sip lock - put this machine's copy behind a passphrase

                USAGE
                  sip lock            set a passphrase on this machine's copy
                  sip lock --off      remove it, storing the key in the clear again

                The repository key lives in .sip/config.json. Unlocked, it is there in plain
                base64: anyone who can read that file can read every document, now and in
                every snapshot you have ever taken. Locking wraps it with Argon2id so only
                the passphrase recovers it.

                WHAT IT COVERS
                  Another account on this PC reading .sip.
                  .sip being copied to a backup, a USB stick, or a cloud folder.

                WHAT IT DOES NOT COVER
                  Other machines. .sip is never synced, so every replica keeps its own
                  config with the same key. Locking the desktop leaves the laptop open,
                  and the documents are equally readable from either. Lock each machine
                  you care about.

                  A machine you pair. Pairing sends it the repository key - encrypted on
                  the way, and to it alone, but it then has the key and its own copy is
                  unlocked until you lock it there too. Invites no longer carry the key;
                  an old sip1_ one that was ever sent still does.

                  This PC while you are logged in. The daemon polls every sixty seconds, so
                  it holds the key in memory after one prompt. Anything running as you can
                  reach it. Locking protects a powered-off or logged-out machine, not a
                  running one.

                  Your working folder. The documents themselves sit in the folder in the
                  ordinary way. This protects the store, not the copy you open in Word.

                THERE IS NO RECOVERY
                  Lose the passphrase and this copy is gone. There is no reset, no hint, no
                  backup key, and none of those could exist without defeating the point. If
                  another machine is paired, its copy still has the documents.

                COST
                  Unlocking takes about 0.6 seconds by design. That is Argon2id at 256 MiB
                  and four passes, chosen so an attacker guessing offline pays the same.

                UNATTENDED USE
                  Set SIP_PASSPHRASE and sip will use it instead of prompting. This exists
                  because a tool with no non-interactive path makes people invent worse ones.

                  Be clear about the cost: an environment variable is readable by other
                  processes running as you, and it tends to end up in shell history, in CI
                  logs, and in crash dumps. If you set it, set it for one command rather than
                  exporting it, and do not put it in a file that syncs.

                """,

            "UNLOCK" =>
                """
                sip unlock - check a passphrase, or unlock for one command

                USAGE
                  sip unlock

                Prompts for the passphrase and reports whether it opens this copy.

                Unlocking is per-process, not a mode you switch on. This command unlocks the
                repository for the length of the command and then exits. The tray holds its
                key for as long as it runs, which is what lets the daemon keep syncing a
                locked folder without prompting every sixty seconds.

                Commands that need the key will prompt on their own. If input is redirected -
                a scheduled task, a script, a pipe - they fail instead of prompting, so an
                automated run cannot hang forever on a prompt nobody can see.

                """,

            "LOCKING" =>
                """
                Locking - what a passphrase does and does not protect

                See 'sip help lock' for the command. This topic is about the threat model,
                because a padlock icon says "protected" and that word does a lot of work it
                has not earned.

                WHAT IS ENCRYPTED, WITH OR WITHOUT A PASSPHRASE
                  Blocks. Every file's contents are split into blocks and each is encrypted
                  with the repository key before it touches the disk or the network.

                  Snapshots. Filenames, sizes and timestamps are encrypted too. This was not
                  always true: snapshots used to be readable JSON, so a "locked" repository
                  still showed anyone holding the folder that you had a file called
                  Tax Returns 2025/P60-confidential.txt. For a documents tool a filename is
                  frequently as revealing as the document.

                WHAT THE PASSPHRASE ADDS
                  Without it, the key sits next to the data it protects, so the encryption
                  above stops nobody who has the folder. The passphrase is what makes the
                  rest of it mean anything.

                WHAT NOTHING HERE COVERS
                  The working folder. Your documents are in your documents folder. That is
                  the point of the product.

                  A machine that is running and unlocked. The key is in memory by design.

                  Machines you pair. Each receives the key, and is locked or not on its own.
                  Old sip1_ invites carried the key in clear text; this version refuses
                  them, but one that was sent before is still readable by whoever has it.

                BITLOCKER IS ALREADY DOING THE OBVIOUS JOB
                  Full-disk encryption is on for every volume on this hardware, and it
                  already covers the stolen-powered-off-laptop case that people picture when
                  they think about encryption. What the passphrase adds on top is narrower:
                  another account on the same machine, and .sip ending up somewhere you did
                  not intend - a backup, a sync folder, a USB stick.

                  That is worth having. It is not the headline it sounds like, and the
                  feature defaults to off for exactly that reason.

                """,

            "KEEP-ALIVE" or "KEEPALIVE" =>
                """
                Keep Alive - stopping the machine sleeping part way through a transfer

                There is no command for this. It is automatic, and this topic exists so you
                know exactly what it does and what it does not.

                WHAT IT DOES
                  While blocks are actually moving - either being fetched from a peer or
                  served to one - SippBucket asks Windows to stay in the working state. The
                  request is dropped the moment the transfer finishes.

                WHAT IT DELIBERATELY DOES NOT DO
                  It does not keep your screen on. A background sync has no business
                  lighting up your display, so only the system request is made, never the
                  display one.

                  It does not use away mode. That is for media recorders, and Microsoft's
                  own guidance is that software on a laptop should not enable it, because
                  it stops the machine ever entering true sleep.

                  It does not hold the machine awake while idle. This is the part worth
                  understanding: the underlying call resets the system idle timer every
                  time it is made. The daemon polls every 60 seconds, so if it made that
                  call on every poll your machine would never sleep again - and you would
                  blame the laptop, not this program. A poll that finds nothing to do takes
                  no hold at all. There is a test whose only job is to keep that true.

                WHAT IT CANNOT DO
                  It cannot stop you putting the machine to sleep. Closing the lid or
                  pressing the power button still sleeps it, mid-transfer or not. Windows
                  is explicit that an application must not be able to override that, and
                  SippBucket does not try.

                  An interrupted transfer is not a corrupted one. Blocks are written to a
                  temporary name and moved into place, and a snapshot only becomes current
                  once every block it needs is stored. A sleep mid-sync costs you the
                  transfer, not the folder - the next sync picks it up.

                  It does not stop the screen saver.

                IF IT IS NOT WORKING
                  The call can fail, and a failure is recorded rather than thrown, because
                  failing to prevent sleep should never fail a sync. Run 'sip serve' and
                  watch for a line reporting it.
                """,

            "CONFIG" => ConfigHelp(),

            "PUSH" =>
                """
                sip push - send files straight to one of your machines

                USAGE
                  sip push on                        turn Direct Push on (it starts off)
                  sip push off                       turn it off
                  sip push status                    say whether it is on, and what is waiting
                  sip push <machine> <file>...       send files to a paired machine
                    --port <port>                    the other machine's Direct Push port,
                                                     when it is not the same as this one's
                    --anyway                         send files it will quarantine, unasked

                Folder sync only ever pulls: every machine asks the others what changed.
                Direct Push is the one exception. You send particular files to one of
                your machines, and they arrive in its inbox, like email. 'sip help inbox'
                says where; 'sip help quarantine' says what is held back.

                NAMING THE MACHINE
                  By its server number, as in 'sip push "Server 2" report.pdf' or
                  'sip push 2 report.pdf'; by its Server.ID or its label, as 'sip id' lists
                  them; or by the name, device ID or ID prefix 'sip peer list' shows. A
                  number reaches the machine's install that synced most recently, so a
                  dual-boot machine is reached in whichever Windows it is running.

                WHO CAN SEND TO YOU
                  A machine paired with any one of your folders, and then only one you said
                  is yours ('sip peer owner <machine> mine'), until team features are on.
                  Pairing is per folder, but Direct Push is per machine: to cut a machine
                  off, remove it from every folder it is paired with, or turn this off.
                  Nothing listens for Direct Push while it is off.

                HOW IT TRAVELS
                  Over SSH, SippBucket's own, on its own port (push.sshPort, 8473), not
                  Windows' OpenSSH. The device key is the SSH key: each machine proves it
                  holds the key it was paired with, both ways, before anything moves, so
                  there is no "trust this machine?" question. Only strong algorithms are
                  offered (ECDH over P-384, AES-256-GCM, ssh-ed25519), no password or other
                  login is accepted, and no shell, command or forwarding is possible. No
                  session can be set up without encryption.

                WHAT THE RECEIVING MACHINE DECIDES
                  Before anything is sent it answers for every file: a name Windows could
                  not open as itself, a file larger than it takes (push.largestFileMiB),
                  another person going past their space there (push.personInboxMiB), or a
                  disk that would be left with less than 1 GiB free, and that file is not
                  sent. Then each file's bytes are checked against its name as it arrives:
                  a program, whatever it is called, and a file that is not what its name
                  says, go to quarantine instead of the inbox.

                  This machine runs the same check before sending, only to warn you, so you
                  can think again before sending something that will be quarantined.
                  Asked at the keyboard; in a script, those files are left out unless
                  --anyway says otherwise. The receiving machine's decision is the one
                  that counts.

                FAST
                  One connection for each batch of up to 4,096 files, the files back to
                  back with no round trip between them, and a receipt for each at the end.
                  A file that changes after it was read does not arrive: its bytes no
                  longer match what was offered.

                LIMITS
                  Across two home networks it needs the same reachability sync does.
                  The content check catches a disguised file, not a malicious one: a
                  genuine picture can still carry a malformed payload. The antivirus still
                  scans whatever arrives, and SippBucket never gets in its way.
                """,

            "INBOX" =>
                """
                sip inbox - what arrived by Direct Push, and where it goes

                USAGE
                  sip inbox                          list what is waiting in the inbox
                  sip inbox folder                   print where the inbox is
                  sip inbox folder <path>            move it (files already there stay)
                  sip inbox folder --default         back to SippBucket Inbox in your profile
                  sip inbox rules                    list your forwarding rules
                  sip inbox rules add --to <folder> [--from <machine>] [--type <ext>]
                                      [--name <pattern>]
                  sip inbox rules remove <n>

                WHERE THINGS LAND
                  The inbox is SippBucket Inbox in your profile unless you choose another
                  folder, which must be on one of this machine's drives. It cannot be inside
                  a folder SippBucket syncs, or hold one: what arrives, quarantine included,
                  would then be synced on to other machines. A file whose name is already
                  taken gets a numbered one beside it, as Explorer numbers a copy; nothing is
                  ever overwritten. Files that arrive as neither a type SippBucket knows nor
                  a program are placed and marked "type not recognised".

                  Inside the inbox, Quarantine holds what was held back ('sip help
                  quarantine'), and the hidden .sippbucket folder holds SippBucket's own
                  staging area, its record of what arrived, and its lock.

                FORWARDING RULES
                  Like email rules. A rule matches on the sender, the file's type (what its
                  content is, such as pdf, not what its name says), a name pattern with *
                  and ?, or any of them together; the first rule that matches moves the
                  file to its folder, and a file no rule matches stays in the inbox.

                  Rules never touch quarantine. Rules never move another person's files
                  unless the rule names that person's machine with --from, so nothing
                  someone else sends lands in a synced folder by default. A rule cannot
                  send files into the quarantine, into SippBucket's own folder, or into a
                  synced folder's .sip.

                  These are your settings, kept in push.json beside your device key, not
                  the machine's; SippBucket picks up a change within half a minute.
                """,

            "QUARANTINE" =>
                """
                sip quarantine - what arrived and was held back

                USAGE
                  sip quarantine                     list what is in it
                  sip quarantine release <hash>      bring a file back into the inbox,
                                                     under the name its content matches
                    --as-sent                        under the name it was sent with instead
                    --it-is-a-program                confirm, after the warning, that you
                                                     want a program out
                  sip quarantine delete <hash>       delete a file, for good

                  <hash> is the file's hash as the list shows it; eight characters are
                  enough when they name one file.

                WHAT GOES THERE
                  A program, whatever it is named, and a file whose content is not what its
                  name says, such as a video named .md. Rather than refusing them, the
                  receiving machine keeps them where they can do no harm and you can look.

                NOTHING IN IT CAN RUN
                  Each file is stored under its hash with .quarantine after it, which no
                  program opens, beside a record of every time it arrived: its name, who
                  sent it, when, why it is here, and what its content is.

                  It is stored as it arrived and never encrypted, so the antivirus sees it
                  exactly as it is. If the antivirus removes something here, that is it
                  doing its job, and the list says so.

                NOTHING LEAVES BY ITSELF
                  No rule applies here and nothing is ever purged on a timer. A file comes
                  out only when you release it, and a program only after a warning you
                  confirm. Delete is permanent. The quarantine's size is capped
                  (push.quarantineMiB): once it is full, a file that belongs there is
                  refused rather than let in.
                """,

            "ALERTS" =>
                """
                sip alerts [--all]
                sip alerts answer <number> me|not-me

                What SippBucket noticed about your other machines, and the questions it is
                waiting for you to answer. Every alert and every answer is kept for good in
                alerts.jsonl beside the device key. Nothing is ever removed from it, and it
                never leaves this machine.

                Alerts waiting for an answer come first, then the latest 20 others, newest
                first. --all lists every one.

                WHEN A CHANGE IS HELD
                  A change another machine sends is held, kept and not applied, when it
                  looks like damage rather than your own work. Any one of three signs holds
                  it; these are the defaults:
                    - it changes or deletes half or more of a folder's files, once the
                      folder has 20 or more;
                    - files that were ordinary turn random-looking, as encrypted files do:
                      at least 5, and 30% or more of the changed files looked at (up to 64,
                      the first 64 KiB of each, before against after);
                    - 10 or more files are renamed to one extension the folder never had,
                      as when everything becomes .locked.
                  The thresholds are the health section of master.json ('sip help config').
                  Their limits keep every check on: it cannot be switched off.

                  You are asked once, however many more changes that machine sends while
                  you decide:
                    sip alerts answer <number> me       That was me: apply it. Now, if that
                                                        machine answers, or at the next sync
                                                        with it.
                    sip alerts answer <number> not-me   Not me: keep it out. The change stays
                                                        held for good, and no change from that
                                                        machine is taken, in any folder, until
                                                        'sip peer health clear' says so.

                  An answer is never changed. Giving the same answer again finishes anything
                  a failure left undone.

                  "That was me" covers what you were shown. A later change from the same
                  machine that looks like damage is asked about again.

                WHERE A HELD CHANGE IS
                  A copy of it is kept in the folder's .sip/held, which no trim of history
                  removes, no collection sweeps and no other machine is offered. Nothing in
                  the folder is touched while it waits, and your other machines go on syncing
                  as before. Once a change you approved is applied, its copy goes: it is in
                  the history. One you refused is kept, as evidence.

                WHEN A MACHINE KEEPS SENDING WHAT IS WRONG
                  Each bad block, wrong snapshot or unsafe path is refused, and counted
                  against the machine that sent it. Five of one kind in a day raise one
                  alert, at most once a day for each kind. 'sip peer health' has the whole
                  record, and 'sip help peer' explains it.
                """,

            "TEAM" =>
                """
                sip team
                sip team exception on|off
                sip team person list
                sip team person add <name> <machine>...
                sip team person remove <machine>

                Whether team features are on, and who counts as one person. Team features
                are off until a team exists: you and 2 other people, or you and 1 other by
                your own exception ('sip team exception on'). One person's machines count
                once. Until you group a colleague's machines under their name, each machine
                counts as its own person, because SippBucket can count machines but cannot
                know two of them are one colleague until you say so.

                While team features are off, other people's machines cannot push files or
                send messages to this one, and 'sip dm' does not send. What is NOT a team
                feature: the safety measures. The first machine you answer "someone else's"
                about gets the plain warning and every protective default, team or no team.

                GROUPING
                  sip team person add Ada laptop-ada desktop-ada
                    groups two paired machines under one name. From then on Ada's machines
                    share one inbox space cap, one message rate and one conversation, and
                    count once toward the team. The name is yours, set here, never taken
                    from their machines; what is verified is each machine's device key.
                  A machine must be paired and answered "someone else's" before it can be
                  grouped. Removing a machine ('sip team person remove') makes it count on
                  its own again; a person left with no machines is removed.

                Grouping is this machine's bookkeeping. Your other machines have their own
                lists, so group on each machine you read messages on.
                """,

            "DM" =>
                """
                sip dm <person> <text>... [--attach <file>]...
                sip dm block <person>      sip dm unblock <person>
                sip dm mute <person>       sip dm unmute <person>
                sip dm delete <message-id>

                Sends a direct message to a person on your servers. A team feature: both
                ends must have team features on ('sip team'). Messages travel over Direct
                Push's connection - the same pairing, the same device-key check, no
                unencrypted session possible - and wait on this machine until one of the
                person's machines can be reached. There is no server in the middle holding
                them.

                <person> is a name from 'sip team person list', or a paired machine's name
                for someone whose machines you have not grouped. Every machine of theirs
                you are paired with gets its own signed copy under one message ID, so a
                copy that arrives twice is stored once.

                ATTACHMENTS
                  --attach sends the file to each of their machines as a Direct Push file
                  first, then the message names it with its exact hash. Their machine's
                  content check still decides where it lands: a program, whatever it is
                  called, goes to their quarantine ('sip help push').

                BLOCK AND MUTE
                  block   Their messages are dropped without an answer. They are never
                          told: their messages simply never say Delivered, which they may
                          notice. Never used for anything else, so nothing you see can
                          tell you whether you are blocked.
                  mute    Their messages still arrive, without notifications.

                DELETE
                  Removes the message from this machine only. It does not delete the other
                  person's copy, and like any deleted file it is not securely erased from
                  the disk.

                Limits are the push section of master.json ('sip help config'): the largest
                message (push.largestMessageKiB), and how many messages a minute one person
                may deliver here (push.messagesPerMinute).
                """,

            "MESSAGES" =>
                """
                sip messages [<person>]

                Your conversations, one per person, newest first; with a person, that
                conversation, oldest first, each message with its status and ID.

                STATUSES - never more than this machine has verified
                  Sending       Not yet confirmed by any of their machines. This covers
                                unreachable, not yet tried, and a sender who has been
                                blocked; it never says which.
                  Delivered     One of their machines confirmed, over the authenticated
                                session, that it checked the signature and saved the
                                message, flushed to disk. Still that machine's own report.
                  Not accepted  Their machine refused it for a stated reason: too large,
                                too many too fast, or signature rejected. Never used for
                                blocking.
                  There are no read receipts. Delivered is the most a sender can know.

                STORED HOW
                  In one store with neutral file names, protected with Windows' per-user
                  data protection (DPAPI). That protects against other accounts on this
                  machine and against a copy taken without your Windows password. It does
                  not protect against an administrator while you are signed in, anyone who
                  knows your Windows password, or software running as you.

                  Text is shown as text. An HTML file travels as an attachment, and
                  SippBucket never runs it: open it in your browser on purpose, from the
                  inbox. Attachments are Direct Push files, stored unencrypted in the inbox
                  or quarantine so your antivirus can scan them.
                """,

            "PAGES" =>
                """
                sip pages
                sip pages links <page>

                A folder of Markdown files synced by SippBucket is a private wiki: every
                machine holds all of it, offline, encrypted at rest, with full history.
                Pages open in your own editor - SippBucket does not have one - and this
                command is the map: the tree of pages, and each page's links.

                'sip pages' lists every saved .md page with how many links leave it and
                how many point at it. 'sip pages links <page>' lists both ends for one
                page: [text](target.md) links and [[Page Name]] links alike, with an
                anchor (#section) ignored. A target that is not a page here - an outside
                URL, an image, or a page still to be written - is shown as exactly that,
                which is how a wiki grows: write the link first.

                Everything reads from the newest save, so every machine at the same head
                sees the same map; the daemon saves as you work. Links inside fenced or
                inline code are not counted.
                """,

            "SEARCH" =>
                """
                sip search <word>...

                Finds the saved files holding every one of the words. Words are runs of
                letters and digits, compared without case; content is read for Markdown
                and plain-text files up to 8 MiB, and every file's NAME counts for every
                file - which is how a Word document is found by what it is called, even
                though its bytes are not read. Best matches first, each with the first
                line that matched.

                The index is built here, from this machine's own store, and the search
                runs here: nothing you search for leaves this machine. It covers the
                newest save - what is saved is what is found - and the daemon saves as
                you work.
                """,

            "COMMENTS" =>
                """
                sip comments [<page>]
                sip comments add <page> <text>...
                sip comments mentions <name>

                Comments on pages. Each comment is one small file under .sip-comments,
                so comments sync exactly like documents: they arrive with the folder,
                work offline, are encrypted at rest, and two people commenting at once
                never conflict. Deleting the file deletes the comment, and that travels
                too.

                Every comment is signed by the device that wrote it, the way snapshots
                are signed: the folder's key proves membership, the signature proves the
                author. A comment whose signature does not verify is listed with that
                said in capitals, never hidden.

                Writing is a team feature, like 'sip dm': it needs a team (3 people, or
                2 by your exception - 'sip team'). Reading is just reading files.

                MENTIONS
                  @name in a comment's text is a mention. 'sip comments mentions Ada'
                  lists every comment that says @Ada. Mentions travel with the folder
                  when it syncs; there is no other channel and no read receipts.
                """,

            "NET" =>
                """
                sip net [check]
                sip net list
                sip net allow [<network-id>]     sip net deny [<network-id>]
                sip net forget [<network-id>]

                What this machine can see of its own networks, and the per-network consent
                local discovery runs under. 'sip net' only reads this machine - adapters,
                gateways, settings - and sends nothing, not even to the router.

                LOCAL DISCOVERY - finding your own machines on the same network
                  Your machines find each other's current addresses by a broadcast beacon,
                  so a laptop that came home syncs without anyone typing an IP. What goes
                  out is a fixed-size packet that names NOTHING: no device ID, no machine
                  name, no port, no folder. Each packet holds tokens only the machines you
                  gave keys to can recognise - keys exchanged automatically, inside the
                  encrypted connection, with machines you answered are your own. To anyone
                  else, on any network, every packet is indistinguishable from random noise,
                  every packet is the same size, and a captured packet replayed later, or
                  from another address, matches nothing.

                CONSENT IS PER NETWORK, AND OFF BY DEFAULT
                  Even a packet that identifies nothing is still a packet, so nothing is
                  announced on a network until you allow that network: home and office once
                  each, never a hotel by accident. An unknown network is a refusal, not a
                  question deferred. Listening runs everywhere - it emits nothing and costs
                  you nothing. A discovered address is only ever an addition: the address
                  you configured is always tried, and no broadcast can replace it or
                  introduce a machine you never paired.

                THE ROUTER, AND REACHING MACHINES ELSEWHERE
                  'sip net' also shows whether the daemon asks the router to forward the
                  sync port (network.portMapping in master.json, off by default), which is
                  what lets your other machines reach this one from outside this network.
                  'sip help config' has the setting; docs/NAT-TRAVERSAL.md has the design.
                """,

            "ID" => IdHelp(),

            _ => null,
        };

        if (text is null)
        {
            return false;
        }

        Console.WriteLine(text);
        return true;
    }

    /// <summary><c>sip help id</c>: Server.ID's three layers, and where the device key is.</summary>
    /// <remarks>
    /// The key's path is the one this process resolves, not a fixed one: it names the
    /// data-directory override when that is set, and it is printed as the path it is, with
    /// single backslashes (D-102: a raw string literal printed them doubled).
    /// </remarks>
    private static string IdHelp()
    {
        var overridden = Environment.GetEnvironmentVariable(Core.Platform.UserDataDirectory.OverrideVariable) is { } value &&
                         Path.IsPathFullyQualified(value);
        var where = overridden
            ? $"  {AppPaths.DeviceKeyFile}{Environment.NewLine}(there because {Core.Platform.UserDataDirectory.OverrideVariable} is set; " +
              "without it, it is in %APPDATA%\\SippBucket)"
            : $"  {AppPaths.DeviceKeyFile}";

        return $$"""
            sip id [--device]

            Shows who this machine is, in Server.ID's three layers (docs/SERVER-ID.md):

              server      its number among your machines, as in "Server 1", and its label
                          from the firmware, as in "Dell Inspiron 15 3511"
              Server.ID   Server.ID#XXX-XXX-XXX: a fingerprint of the permanent ID, in
                          symbols that cannot be confused, to read aloud
              permanent   the permanent ID: a one-way hash of the motherboard's serial number
                          and the system UUID, so it is the same after a restart or a Windows
                          reinstall. Where the firmware gives neither, a random value the
                          installer made stands in, or one kept for your account alone;
                          'source' says which, and why.
              device      the device ID: the Ed25519 public key that proves which install
                          this is. Only this is trusted, and pairing records it.
              run         the run ID: random each time SippBucket starts
              installs    the Windows installs known on this board: both, on a dual-boot one
              firmware    which of the firmware's values exist; never the values themselves

            Then your other servers: each machine you said is yours ('sip peer owner') that
            has exchanged records with this one, by number, and any it has heard of through
            them. Numbers are given automatically: the machine SippBucket was installed on
            first is Server 1, and if two ever claim one number, the one that claimed it
            first keeps it and the other takes the next free one.

            --device prints the device ID alone, for scripts and for 'sip peer add'.

            Server.ID is guidance, never authority: a serial number is not a secret, so it
            never wins a conflict or grants trust. It is exchanged only inside the encrypted
            connection, and only with machines you said are yours, never with anyone else's.
            The raw serial number never leaves this machine.

            The device key is made the first time it is needed, once per Windows account,
            and kept at
            {{where}}
            On Windows the file is encrypted with DPAPI for your account, and a key
            written by an older build is encrypted the first time it is loaded. That
            stops the file being read on another machine or from another ordinary
            account. It does not stop programs running as you, an administrator while
            you are signed in, or anyone with your password. 'sip doctor' checks the
            file itself.
            """;
    }

    /// <summary>
    /// <c>sip help config</c>: every setting, its default, its limits, and what a bad value
    /// does.
    /// </summary>
    /// <remarks>
    /// The settings part is built from <see cref="MasterSettings.All"/>, the same table the
    /// file is read against, so a setting cannot exist without being documented here, and
    /// the default and limits printed cannot drift from the ones enforced.
    /// </remarks>
    private static string ConfigHelp()
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine(
            """
            sip config - this machine's settings, in master.json

            USAGE
              sip config show              every setting, its value, and where it came from
              sip config check             everything in the file that was not used as written
              sip config set <key> <value> change one setting (asks for administrator rights)

            WHERE IT LIVES
              C:\ProgramData\SippBucket\master.json: one file per machine, never synced, so
              the laptop and the desktop each have their own. Every account can read it;
              only an administrator can change it, which is why 'set' asks Windows for
              permission (UAC) for that one write, and writes the whole file in one step.
              With no file at all, every setting is at its default.

              The limit of "only an administrator": the installer gives the folder those
              permissions. A copy run without the installer has ProgramData's own, under
              which any account can create the folder, or the file while it does not
              exist, though not change one an administrator wrote. So 'set', with
              administrator rights, refuses a folder or a file that another account made,
              and a folder or file that is a junction or link to somewhere else, and
              writes nothing; delete it as an administrator, then try again.

              When SIPPBUCKET_DATA_DIR names a folder by its full path, master.json is
              read from that folder instead, and 'set' needs no administrator.

            WHAT A BAD VALUE DOES
              Nothing to the server. A value of the wrong type, or outside its limits, is
              ignored and the default used. A syntax error anywhere means the default for
              everything. A key this build does not know is ignored, so a newer file does
              not break an older build. Every one of these is listed by 'sip config check'
              and by 'sip doctor', which also lists every value that differs from its
              default. The limits below are in the program, not in the file.

              The file tunes SippBucket; it cannot change what SippBucket tells you. No
              setting changes a status's wording, silences a warning, or turns off a check.

              SippBucket reads the file when it starts. After changing it, quit and reopen
              the tray, and restart any 'sip serve'.

            SETTINGS
            """);

        foreach (var section in MasterSettings.Sections)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"  {section}");

            var settings = MasterSettings.All.Where(s => s.Section == section).ToList();
            if (settings.Count == 0)
            {
                text.AppendLine("    Nothing yet. Reserved for bandwidth ceilings and discovery defaults.");
                text.AppendLine();
                continue;
            }

            foreach (var setting in settings)
            {
                text.AppendLine(CultureInfo.InvariantCulture, $"    {setting.Key}");
                text.AppendLine(CultureInfo.InvariantCulture, $"      default {setting.Default}, limits {setting.DescribeLimits()}");

                foreach (var line in Wrap(setting.Description, 72))
                {
                    text.AppendLine(CultureInfo.InvariantCulture, $"      {line}");
                }

                text.AppendLine();
            }
        }

        text.AppendLine(
            """
            EXAMPLE
              {
                // Comments are allowed, so the file can say why a value was chosen.
                "schema": 1,
                "server": { "listenPort": 8471 },
                "sync": { "pollIntervalSeconds": 120 }
              }
            """);

        return text.ToString();
    }

    private static IEnumerable<string> Wrap(string text, int width)
    {
        var line = new System.Text.StringBuilder();

        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                yield return line.ToString();
                line.Clear();
            }

            if (line.Length > 0)
            {
                line.Append(' ');
            }

            line.Append(word);
        }

        if (line.Length > 0)
        {
            yield return line.ToString();
        }
    }
}
