# WipeFreeSpace #

WipeFreeSpace - a program for secure wiping of free space on file systems.

WipeFreeSpace wipes the following things (when supported by the backing library):

- free space (space in unused blocks/clusters)
- free space in partially used blocks (also called the "slack space")
- deleted files' names and other data that can be used to undelete a file (like the journal)

WipeFreeSpace does NOT decrease the amount of available free space when working.

The following method names (case-insensitive) are available:

- Gutmann (method similar to Gutmann's, the default, 36 passes)
- random (shred-like, 25 passes)
- schneier (Shneier's method, 7 passes, contains ITSG-06)
- dod (DoD, 3 passes, contains NAVSO P-5239-26 and German Federal Office for Information Security)

WipeFreeSpace also works for file systems created inside regular files on any host file system.

*NOTE*: it is best to use this program on unmounted file systems, what makes sure the journal is committed.

*NOTE*: if a block is damaged, it is only wiped until the first error. There is no guarantee that it will be fully wiped.

Project homepage: <https://wipefreespace.sourceforge.io/>.

Author: Bogdan Drozdowski, bogdro (at) users . sourceforge . net

License: GPLv2+

## WARNING ##

The `dev` branch may contain code which is a work in progress and committed just for tests. The code here may not work properly or even compile.

The `master` branch may contain code which is committed just for quality tests.

The tags, matching the official packages on SourceForge, should be the most reliable points.
