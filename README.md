kpatch: dynamic kernel patching
===============================

kpatch is a tool for the generation and application of kernel
modules that patch a running Linux kernel while in operation,
without requiring a reboot.  This is very valuable in cases
where critical workloads, which do not have high availability via
scale-out, run on a single machine and are very downtime
sensitive or require a heavyweight approval process and
notification of workload users in the event of downtime.


Installation
------------

The default install prefix is in /usr/local.

    make
    sudo make install


Quick Start
-----------

*NOTE: While kpatch is designed to work with any recent Linux
kernel on any distribution, the "kpatch build" command currently
only works on Fedora.*

First, use diff to make a source patch against the kernel tree, e.g. foo.patch.
Then:

    kpatch build foo.patch
    sudo insmod kpatch.ko kpatch-foo.ko

Voila, your kernel is patched.


License
-------

kpatch is under the GPLv2 license.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


Status
------

kpatch is currently is early development.  For now, it should _not_ be used
in production environments until significantly more testing on various
patches and environments is conducted.


Dependencies
------------

kpatch-build tools require libelf library and development headers to be installed.
See Gotchas section below.


Gotchas
-------

The version of elfutils (namely libelf) that ship with most distros as of
the time of this writing, have a bug in libelf that is exposed by kpatch.

elfutils-0.158 or higher contains the fix.

The specific commit is 88ad5ddb71bd1fa8ed043a840157ebf23c0057b3.

git://git.fedorahosted.org/git/elfutils.git


Patch module generation algorithm
---------------------------------

An example script for automating the patch module generation is
kpatch-build/kpatch-build.  The script is written for Fedora but should
be adaptable to other distributions with limited changes.

The primary steps in the patch module generation process are:
- Building the unstripped vmlinux for the kernel
- Patching the source tree
- Rebuilding vmlinux and monitoring which objects are building rebuilt.
  These are the "changed objects".
- Recompile each changed object with -ffunction-sections -fdata-sections
  resulting in the changed patched objects
- Unpatch the source tree
- Recompile each changed object with -ffunction-sections -fdata-sections
  resulting in the changed original objects
- Use create-diff-object to analyze each original/patched object pair
  for patchability and generate an output object containing modified
  sections
- Link all the output objects in a into a cumulative object
- Use add-patches-section to add the .patches section that the
  core kpatch module uses to determine the list of functions that need
  to be redirected using ftrace
- Generate the patch kernel module
- Use link-vmlinux-syms to hardcode non-exported kernel symbols
  into the symbol table of the patch kernel module


Demonstration
-------------

A low-level demonstration of kpatch is available on Youtube:

http://www.youtube.com/watch?v=WeSmG-XirC4

This demonstration completes each step in the previous section in a manual
fashion.  However, from a end-user perspective, most of these steps will
be hidden away in scripts (eventually).