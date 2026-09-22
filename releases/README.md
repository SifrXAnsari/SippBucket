# Read this before you download anything here

**These builds are NOT stable and are NOT yet tested.** They are development snapshots put here
so they can be tried, not releases. Install one only on a machine you can afford to have
misbehave, and expect things to break.

What that means for the build in this folder:

- The automated test suite was **not green** when it was packaged, and the native code audits
  were **not run** on this build.
- Several features have only ever been compiled: branches, freeing held files, add-on scopes,
  the sandbox command. Nobody has driven them against a second computer.
- The Explorer "SippBucket versions" tab loads inside Windows Explorer itself. A fault in it is a
  fault in Explorer.
- Uninstalling from Settings > Apps removes the program files and the Explorer registration.
  Your folders and their keys live in your profile and are not touched by install or uninstall.

Verify a download against `SHA256SUMS.txt` in the same folder before running it.

When a build here has passed the full build with its audits and a green suite, this file will
say so for that build. Until then, treat everything in this folder as unproven.
