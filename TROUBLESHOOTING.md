# Troubleshooting

> If you are here because something is already broken, I am not responsible and
> I will not be pretending otherwise. What I will do is point you at the thing
> that most likely caused it, in the order it actually tends to happen.
>
> Before you read on: if you flashed firmware, hit the hardware reset button, or
> ran `upgradetest sdefconf 35`, some of these are not recoverable by reading a
> webpage. Say so in your post and someone on the forum may have a way back.
>
> Also check you did not skip [GUIDE.md section 1](GUIDE.md#1-before-you-touch-anything).
> A missing config backup turns most of these into much bigger problems than
> they look.

Ordered by how often each one actually comes up.

---

## `step [2] send sq: unknown error` (all 5 retries)

```
step [0] reset factory: ok
step [1] request factory mode: ok
step [2] send sq: unknown error Attempt retrying..(1/5)
...
step [2] send sq: unknown error Attempt retrying..(5/5)
```

Steps 0 and 1 succeeding means the tool is talking to the ONT correctly. Step 2 is
where the actual exploit payload is sent, and it is being rejected.

**Cause:** the firmware is patched. Confirmed on `V9.0.10P18N3D`. Changing the MAC
and adding `--new` does not help. The patch is in the firmware's HTTP handler, not
in the request headers.

**Not fixable from this guide.** You need either a firmware that is not patched, or
an ONT with native bridge-mode support.

---

## Tool retries forever, never succeeds

**Cause:** the built-in factory username/password list no longer matches. Airtel
locks the factory account roughly a month after activation, so a list that worked in
April does not work in June.

**Fix:** pass your actual web UI credentials.

```sh
uv run zte_unlock -i 192.168.1.1 -u <webui_user> -w <webui_password>
```

Also worth trying: factory-reset the ONT and run again, and set the adapter MAC
to `00:07:29:55:35:57` (`uv run zte_unlock --check-mac` will tell you whether
a local interface currently has it).

---

## `Access Denied` immediately at the telnet login prompt

**Cause:** the credentials were copied wrong out of the tool's output. This is the
single most common mistake with the original Go tool, whose output is delimited.

The username is **between `=` and `&`**. The password is **after the `=`, not
including the trailing `\`**.

```sh
telnet 192.168.1.1
```

`uv run zte_unlock` prints the credentials on their own lines, so this does
not come up when using it.

---

## `Permission Denied` after a successful telnet login

**Fix:** the telnet security level is too restrictive.

```sh
# only the original Go tool exposes this
./zteOnu -i 192.168.1.1 --telnet --seclvl 3
```

---

## Telnet worked, now refuses the same credentials

**Not a bug.** Telnet credentials and access are regenerated on every reboot and
factory reset. Re-run the tool and use the new credentials.

This is also why the *permanent* telnet option exists:

```sh
# only the original Go tool exposes this
./zteOnu -i 192.168.1.1 --telnet
# then: root / Zte521
```

Trade-off: permanent telnet stays open on your LAN until you change it. Only use it
if you are comfortable with that, or on a segment you control.

---

## Cannot set MAC `00:07:29:55:35:57` on Windows

Windows blocks locally-administered (`00:`-prefixed) MAC addresses on **wireless**
adapters. It works on a **wired** adapter.

**Fixes:**

- Use Ethernet instead of WiFi
- Or use Linux, where the wireless adapter MAC can be set freely

---

## `upgradetest sdefconf 198` does nothing / settings still locked

**Cause, most likely:** you ran the `setmac 4 198/upgradetest sdefconf 198` variant.

That combined form is quoted in the source thread but does not work. Use the bare
command:

```sh
upgradetest sdefconf 198
```

**Also check:** that you are actually in the telnet shell and not sitting at a busybox
prompt that swallowed the command. And confirm the ONT did not reboot mid-command:
reconnect and re-run.

**To confirm you are unlocked:** the web UI at `192.168.1.1` should now let you edit
WAN settings freely.

---

## PPPoE will not authenticate after unlocking

Check in this order:

1. **VLAN ID**: must match your pre-unlock screenshot exactly. This is the usual
   cause and it presents identically to a wrong password.
2. **Password**: the Airtel account number from the Thanks app. If your line was
   converted from DSL to fiber, it is instead the **Relationship ID** from an old
   Xstream eBill.
3. **Username**: `0XXXXXXXXXXX_dsl@airtelbroadband.in`, copy it rather than retyping.
4. **Default gateway checkbox**: if your downstream router is meant to own the
   gateway, uncheck it. Leaving it checked can cause a routing loop.

---

## Bridge mode reverts after every reboot

**Cause:** the inspect-element trick writes the setting to a config that gets
regenerated on boot in current firmware.

**Fix:** downgrade to `firmware/ZXHN_F670L_V9.0.11P1N40.bin` first. The trick persists
on that build.

---

## No **Software Upgrade** page under System Management

**Cause:** Airtel has removed firmware management from this firmware.

**Consequence:** no downgrade, therefore no bridge mode via the inspect trick. You
need an ONT with native bridge-mode support, or another route entirely.

---

## Bridge mode is on but there is still no internet

Bridge mode alone is not enough: nothing is bound to a port.

1. **Network -> Port Binding**: select your bridge connection, bind it to a LAN port
2. Set **DHCP Port Control** for that port to **Internet**
3. Run Ethernet: ONT's bound LAN port -> your router's **WAN** port
4. Configure PPPoE on your own router
5. Turn off the ONT's WiFi, or you have two DHCP servers on one segment

---

## `sendcmd 1 DB decry ...` just prints the command list

**Cause:** `decry` does not exist in your firmware. It was removed in later builds:
the command silently degrades into a help listing.

**Not a syntax error, and not fixable.** This step only works on older firmware. If you
need the config dump, do it before upgrading, or use the ONT's own config-download
page in the web UI.

---

## Want to undo everything

```sh
upgradetest sdefconf 35
```

Back to the Airtel region code. TR-069 will re-provision the ONT, which also restores
the PPPoE and SIP profiles if you lost them. Nothing in this guide is irreversible.

---

## Related, not ZTE

If you have a **Nokia G-2425G-A** instead, the procedure is entirely different:
config decrypt/re-encrypt plus `ritool set OperatorID ALCL`, and a different reset
procedure. Do not follow this guide for it.

See [Unlock G-2425G-A router running on latest firmware](https://broadband.forum/threads/220038/).