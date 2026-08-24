# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

Output docs/quickstart.gif

Require osh

Env XDG_CONFIG_HOME "/tmp/osh-quickstart-demo/config"
Env XDG_DATA_HOME "/tmp/osh-quickstart-demo/data"

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 650
Set Padding 20
Set TypingSpeed 40ms

Type "osh setup softhsm"
Enter
Sleep 2s

Type "osh setup testkeys"
Enter
Sleep 3s

Type "osh --output /tmp/signed debsign \"
Enter
Type "    --archive debian-trixie --suite trixie --version 257.13-1~deb13u1 \"
Enter
Type "    --architecture amd64 \"
Enter
Type "    --boot \"
Enter
Type "    systemd-boot-efi-amd64-signed-template"
Enter
Sleep 8s
