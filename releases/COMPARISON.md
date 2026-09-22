# 1.1.0 against 1.2.0: what changed, and how far each part has been proven

1.1.0 is the app as first packaged on 19 September 2026. 1.2.0 is everything committed since,
built on 22 September 2026. The last column is the honest state of each part in 1.2.0 at the
time of that build, and it is the column to read before installing.

| Area | 1.1.0 | 1.2.0 | State in 1.2.0 |
| --- | --- | --- | --- |
| Sync core: content-addressed store, chunking, encrypted transport, pairing, three-way merge, keep-both conflicts | yes | yes | tests green (1,236 of 1,246 Core tests) |
| Modes: Simple and Power | yes | yes | tests green |
| Direct Push between paired machines | yes | yes | tests green |
| Tray window: folders, computers, messages, activity, settings | basic | full reading pane | drawn and captured on screen |
| Search: `sip find`, `sip index`, ranked by the SQLite that ships with Windows, travelling index, version search | no | yes | driven by hand; no unit tests |
| Storage: multi-root store, cold tier, retention by file type, a 200-type table | no | yes | driven by hand; no unit tests |
| HTML document renderer (`sip render`) | no | yes | all five native audits green, debugged |
| Storage management: `sip disk` drives, usage, duplicates, health, trend, clean to the Recycle Bin, rename, move, eject, mount, format | no | yes | compiled; not driven |
| Network neighbours (read-only), dashboard, settings courier, politeness, databases (`sip db`) | no | yes | compiled; not driven |
| Protection report and `sip protection prove` | no | yes | compiled; not driven |
| Licence, third-party notices, backup reminder, printable key | no | yes | in the package; notices assembled at build |
| Sandbox: contained child, broker, `sip sandbox test` | no | yes | self-test 425 of 425 in Debug; never on a second machine |
| Branches (`sip branch`, tips carried on sync) | no | yes | compiled; never run |
| Add-on programme: manifest, fingerprint, scopes, audit, advisory pipe, `sip link` | no | yes | registration and launch exercised by the player; scopes not driven |
| Hold-free (`sip hold free`) | no | yes | compiled; never against a real peer |
| Window: read a file from the machine that is ahead, send to a computer, built-in editor, share, lock mark and passphrase | no | yes | drawn; lock mark and passphrase verb captured; editor and remote read not driven |
| Windows' own previews in the pane (PDF, Office) | no | yes | code path present; a small PDF fell to text in the capture (fix committed after this build, unverified) |
| Video player add-on (`sip play`, playing inside the pane) | no | yes | played on screen; contract proof, gcc and clang-cl green; tidy pending |
| Explorer "SippBucket versions" tab | no | yes | opened in a real Properties sheet; Open and Restore not clicked |
| Server.ID and server numbering | yes | yes | tests green |

Read as a whole: everything 1.1.0 did is still covered by green tests; most of what 1.2.0
adds is compiled and self-tested but not driven end to end. That is why the folder's README
says this build is not stable and not yet tested.
