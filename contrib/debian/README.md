
Debian
====================
This directory contains files used to package legad/lega-qt
for Debian-based Linux systems. If you compile legad/lega-qt yourself, there are some useful files here.

## lega: URI support ##


lega-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install lega-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your legaqt binary to `/usr/bin`
and the `../../share/pixmaps/lega128.png` to `/usr/share/pixmaps`

lega-qt.protocol (KDE)

