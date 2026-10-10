# Unlocking the ZTE F670L — full walkthrough

Target: ZTE F670L GPON ONT on Airtel Xstream, firmware `V9.0.10P18N2B`, web UI at
`192.168.1.1`.

Steps 1–5 get you an unlocked ONT you control. Step 6 is optional and is the part
Airtel has since patched on newer firmware. Read the compatibility table in
[README.md](README.md) before starting — on `V9.0.10P18N3D` and later, steps 1 and 6
do not work at all.

Throughout, `<angle-brackets>` mean "substitute your own value". Never commit real
credentials.

---

## 1. Before you touch anything

**Take screenshots now.** This is the step everyone skips and then regrets. Unlocking
resets every setting to factory defaults — you will have to re-enter PPPoE and SIP by
hand afterwards, and if you did not write them down first, you are guessing.

Screenshot all of:

- **Network → WAN** (the PPPoE username is visible here)
- **Voice → VoIP / SIP account**
- Any WiFi SSID/password you care about
- The firmware version, from the status page

**Settle the PPPoE password now too**, while you still have a working connection and
a reachable account. Once unlocked and reconfigured you want to verify this anyway:

- Username: on the WAN page, looks like `0XXXXXXXXXXX_dsl@airtelbroadband.in`
- Password: your **Airtel account number**, found in the Airtel Thanks app or your
  email bill

There is a second, older credential in circulation: the **Relationship ID** from
legacy Airtel Xstream eBills. That applies to lines converted from DSL to fiber. If
the account number fails and your line was converted, try the Relationship ID from an
old bill. Airtel's own call centre does not know about either — this is documented in
[the PPPoE thread](https://broadband.forum/threads/232038/).

**Have Ethernet available.** The `--new` telnet method requires your adapter to have
MAC `00:07:29:55:35:57`. Windows will not let you set a `00:`-prefixed MAC on a
wireless adapter — on a wired adapter it works, and on Linux you can set it on
wireless too. Connect by wire and set it there.

---

## 2. Open telnet

Telnet is disabled in this firmware. Factory mode is used to open it and hand you
temporary credentials.

This repo ships its own implementation, with no dependencies:

```sh
python3 -m zte_unlock -i 192.168.1.1
```

It prints the telnet username and password when it succeeds.

**Pass your real web UI credentials if you have changed them.** Airtel locks the
factory account out about a month after activation, so the built-in list of
factory username/password pairs stops working on older connections:

```sh
python3 -m zte_unlock -i 192.168.1.1 -u <webui_user> -w <webui_password>
```

This is the single most common cause of "no credential pair worked".

If the tool reports `session negotiation failed ... unknown error`, the firmware
is patched and no method will work — see step 8.

### The upstream tool

If you would rather use the original binary, it does the same thing:

```sh
# https://github.com/stich86/zteOnu  (v0.0.7, AGPL-3.0)
tar xzf zteOnu_0.0.7_linux_amd64.tar.gz
./zteOnu -i 192.168.1.1
```

Useful flags there: `--telnet` enables *permanent* telnet (`root` / `Zte521`)
instead of temporary credentials — convenient, but it widens the attack surface
on a device sitting on your LAN. Prefer the temporary credentials and re-run when
you need access again. `--seclvl 3` helps if you get `Permission Denied`.

Both zteOnu projects are AGPL-3.0, which is why their source is not vendored
here. See [NOTICE.md](NOTICE.md).

### Log in

```sh
telnet 192.168.1.1
```

If it worked once and stopped working after a reboot, that is expected —
**telnet credentials rotate on every reboot**. Re-run the tool.

---

## 3. Unlock the region lock

This is the actual unlock. From the telnet shell:

```sh
upgradetest sdefconf 198
```

198 is the stock manufacturer region code. Airtel India ships 35.

> **Only use the bare command.** The thread also shows a `setmac 4 198/upgradetest sdefconf 198`
> variant. It does not work — several people report that dropping the `setmac` part is
> exactly what made it succeed for them.

**This resets all settings to factory defaults.** That is why step 1 exists.

### To re-lock

```sh
upgradetest sdefconf 35
```

Setting it back to 35 lets TR-069 push the ISP profile again, which is also a way to
recover your SIP and PPPoE profiles if you have lost them. You can always undo the
unlock, so nothing here is a one-way door.

Once unlocked you can make custom settings on `192.168.1.1` as normal.

---

## 4. Restore PPPoE

The connection is dead after step 3. Re-enter it under **Network → WAN**:

| Field | Value |
| --- | --- |
| Connection type | PPPoE |
| Username | `0XXXXXXXXXXX_dsl@airtelbroadband.in` (copy from your screenshot) |
| Password | your Airtel account number |
| VLAN | as it was — **do not change this** |
| 802.1p priority | as it was |

Get the VLAN ID right from your step-1 screenshot. It is not recoverable from the
account number and getting it wrong looks exactly like a bad password.

Uncheck "Default gateway" if you plan to put the ONT in bridge mode — otherwise the
ONT keeps advertising itself as your gateway. Leave it checked if the ONT will route
for you.

---

## 5. Restore SIP (VoIP / landline)

If you want the Airtel fixed line back, re-enter it under **Voice → VoIP**. The
credentials for Bihar and Jharkhand:

| Field | Value |
| --- | --- |
| SIP Account | `+91<landline number without leading 0>` |
| Authorization Username | `+91<landline number without leading 0>@bh.ims.airtel.in` |
| Password | `Nokia@1` |

`bh` is the state code for Bihar, and Jharkhand reuses it for reasons nobody has
explained. Other states use their own code — you will need to find yours, or
recover the real values from the ISP profile.

---

## 6. Bridge mode (optional — patched on newer firmware)

**Check first.** Go to **System Management** in the web UI. If there is no
**Software Upgrade** page, Airtel has removed firmware changes and this whole section
is dead for you. Skip to step 8.

The bridge-mode option is present in the page but hidden. You can unhide it with
devtools rather than needing a different firmware — but the setting does not survive
a reboot on current firmware, which is why the downgrade is part of this.

### 6a. Downgrade the firmware

Take the current config backup first if you have reconfigured anything.

1. Web UI → **System Management → Software Upgrade**
2. Upload `firmware/ZXHN_F670L_V9.0.11P1N40.bin` from this repo
3. Let it reboot

This is a **downgrade** to a 2022 build, despite the web UI calling it an upgrade.
The inspect-element trick exists in that older firmware and was patched in later ones.
Verify the file before uploading:

```sh
shasum -a 256 -c reference/firmware/ZXHN_F670L_V9.0.11P1N40.bin.sha256
```

### 6b. The inspect-element trick

1. Open **Network → WAN**
2. Right-click the "Add" / connection-type dropdown → **Inspect**
3. In devtools, find the hidden `bridge` option and delete the `hidden` /
   `style="display:none"` attribute that hides it
4. Select `Bridge` and save

On `V9.0.11P1N40` this persists across reboots. On `18N2B` it does not — which is the
entire reason for the downgrade.

### 6c. Bind the bridge to a LAN port

Bridge mode alone does nothing; a downstream router has to be plugged into the port
you bind.

1. **Network → Port Binding** (may be under Internet)
2. Select the bridge connection you just created
3. Choose a LAN port — e.g. LAN 4. That port becomes your bridge port.
4. Set **DHCP Port Control** for that same port to **Internet**

Then run Ethernet from that LAN port on the ONT to the **WAN** port of your own router,
and configure PPPoE there with the same credentials from step 4.

Leave the ONT's own WiFi off if it is bridging, or you will have two DHCP servers on
one segment.

---

## 7. Dumping the ONT config

Useful before you change anything, to see what the ISP actually provisioned.

From telnet:

```sh
sendcmd 1 DB decry /userconfig/cfg/db_user_cfg.xml
```

The decrypted XML lands at `/tmp/debug-decry-cfg`. To pull it to your machine, run a
tftp server on your LAN host and:

```sh
tftp -l db_user_cfg.xml -p 192.168.1.2
```

Other commands worth having:

```sh
sendcmd 1 DB all                    # list every table name
sendcmd 1 DB p <Table Name>         # dump one table
sendcmd 1 DB set <Table> <row> <Field> <Value>   # modify a field
sendcmd 1 DB save                   # persist changes
/etc/init.d/regioncode               # current region settings
```

Example — change the super password:

```sh
sendcmd 1 DB set UserInfo 0 Password <new_password>
```

`dbcry` was **removed in later firmware**. If `decry` just prints the command list back
at you instead of producing a file, your firmware does not have it. That is a dead
end, not a syntax error.

---

## 8. If it does not work

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

The quick triage, in order:

1. **`step [2] send sq: unknown error`, all 5 retries** → firmware is patched
   (`18N3D`+). No workaround from this guide.
2. **Everything retries with no output** → pass your real web UI credentials with
   `-u` / `-p`. The built-in factory list is locked out after ~1 month.
3. **`Permission Denied` in telnet** → try `--seclvl 3`.
4. **Telnet worked, now doesn't** → credentials rotated on reboot. Re-run the tool.
5. **Bridge mode reverts after reboot** → you need the firmware downgrade first.
6. **PPPoE won't authenticate** → check VLAN ID against your screenshot before
   suspecting the password.