# helper scripts

Thin wrappers. They handle argument parsing and platform detection; they do not
replace reading [../GUIDE.md](../GUIDE.md).

## `open_telnet.sh`

Fetches `stich86/zteOnu` v0.0.7 and opens telnet on the ONT, printing the temporary
credentials.

```sh
./open_telnet.sh --install      # just download the binary
./open_telnet.sh                # default method
./open_telnet.sh --with-mac     # --new method, needs MAC 00:07:29:55:35:57
./open_telnet.sh -u <user> -p <pass>   # if the built-in credential list fails
./open_telnet.sh --permanent    # permanent telnet (root/Zte521) instead
./open_telnet.sh --seclvl 3     # if you get "Permission Denied"
```

Platform detection covers Linux and macOS on amd64/arm64/386. Override the ONT with
`-i` or `ROUTER_IP`.

The common failure is the built-in factory credential list being stale — Airtel locks
the factory account about a month after activation. If it retries and fails, pass your
real web UI credentials with `-u` / `-p`.

## `decrypt_config.sh`

Prints the `sendcmd` commands to decrypt the ONT config and pull it over tftp, plus
the query reference for poking at the config database.

```sh
./decrypt_config.sh --sql        # just the sendcmd reference
./decrypt_config.sh --dump-only  # the commands to paste into telnet
./decrypt_config.sh              # full walkthrough incl. tftp setup
```

`decry` was removed in later firmware. If it prints the command list back at you, your
firmware does not have it — see [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md).

## Why there is no "full automation" script

Telnet needs interactive credential entry, the credentials rotate every reboot, and
the unlock command types real values into a live device. Wrapping that in a script
would add a failure surface without removing any manual work. The two scripts here
cover the parts that are actually fiddly — asset selection and argument parsing.