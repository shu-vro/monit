# monit

TUI for managing **macOS Internet Sharing** — see who's connected, block devices, view bandwidth.

## How it works

It basically does

1. `arp -a -i bridge100`
2. `/var/db/dhcpd_leases`
3. `nettop -L 1 -n -x -d -t external`
4. `pfctl -a monit/block -F all`
5. `pfctl -a monit/block -f ~/.config/monit/blocks.pf`
6. `pfctl -a monit/block -a monit/block -f ~/.config/monit/blocks.pf`

here, `arp -a -i bridge100` basically gets all connected networks in bridge100 (or bridge0 if 100 not available) which is internet sharing's bridge

`/var/db/dhcpd_lease` holds all connected network's assigned local ip address

`nettop` gets network up/down value

`pfctl` is used to block/unblock networks

`pfctl -a monit/block -F all` clears every rule sets inside `/monit/block`.

`pfctl -a monit/block -f ~/.config/monit/blocks.pf` loads the rules from `~/.config/monit/blocks.pf`

`pfctl -a monit/block -a monit/block -f ~/.config/monit/blocks.pf` loads the rules from `~/.config/monit/blocks.pf`

if you combine all these operation, you will get this utility's core job.

I have vibecoded only the docs part in the code and the `ratatui` ui. the rest of the logic is written by me.
