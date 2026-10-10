# Unlock an Airtel Xstream ZTE F670L ONT

> ### Read this first
>
> I am not responsible for your router. Not for the bricked ones, not for the
> locked ones, not for the ones where the PPPoE went quiet and you are now
> arguing with Airtel. I wrote down what worked for me and I am sharing it
> because it is useful, not because I am your warranty.
>
> If you brick it, that is between you and the ONT. If you point the finger at
> me, I will laugh at you. Nothing here comes with a warranty, and the forum
> threads this came from are full of people who skipped a step and regretted
> it — read them and you will see the pattern.
>
> So please:
>
> - Back up your config before you touch anything. [GUIDE.md](GUIDE.md) §1 says
>   how, and it is the step people skip and regret.
> - Do not flash firmware you have not verified. `firmware/` in this repo ships
>   with a sha256 for exactly this reason.
> - Do not use the hardware reset button to "fix" something. That is how you
>   lose a working unlock permanently.
> - Do not do any of this on hardware you do not own. See the note below.
>
> The people this is actually built on — `@BornArcher8` and the rest of the
> forum — had the same exposure and took the same care. The forum posts are
> still up, and they are the primary source. If something here contradicts
> them, believe them.

These are my notes from unlocking my own ZTE F670L GPON ONT (Airtel Xstream, India)
in April 2025: opening telnet, clearing the ISP region lock, restoring PPPoE and
SIP, and reaching bridge mode.

I wrote this up because the working procedure is scattered across 178 forum posts
that contradict each other in places, and because I lost access to the account I
had posted under. The full walkthrough is in [GUIDE.md](GUIDE.md); if something
here is wrong, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) before assuming the
hardware is at fault.

This was not a solo job. The unlock command, the PPPoE credentials, and most of
the reasoning came from other people on
[india broadband forum](https://broadband.forum/) — `@BornArcher8` in particular,
whose posts answered most of what I asked. I worked out the SIP credentials and
the bridge-mode firmware downgrade myself. Those threads are cited throughout;
see [reference/forum_posts.md](reference/forum_posts.md).

> **This is ISP equipment you do not own.** Unlocking defeats the operator's
> provisioning lock and voids any warranty or support you have with them. It may
> also violate your ISP's terms of service. Do this on hardware you are allowed
> to modify.

## What this actually is

An ONT is provisioned by the ISP with a *region code* baked into its config. Airtel
India uses code **35**. The stock/unlocked state is code **198**. Every locked
behaviour — editable WAN, bridge mode, the ability to keep your own settings — comes
back when you switch the code back to 198. That is the entire trick; everything else
is just getting a shell to type it into.

## The procedure in one line

Open telnet (`python3 -m zte_unlock`) → `upgradetest sdefconf 198`
→ re-enter PPPoE and SIP credentials → (optional) downgrade firmware and use the
inspect-element trick for bridge mode.

## Firmware compatibility

What the method was last confirmed against, and where it breaks:

| Firmware | Telnet | `sdefconf 198` | Bridge mode via inspect trick | Notes |
| --- | --- | --- | --- | --- |
| `V9.0.10P18N2B` | works | works | no | The unlock itself is fine here; bridge mode needs the downgrade below |
| `V9.0.11P1N40` | n/a | n/a | **works** | Downgrade target, vendored in `firmware/` |
| `V9.0.10P18N3D` | **broken** | — | **broken** | Airtel patched both. `step [2] send sq: unknown error` |

If your ONT reports `18N3D` or later, both the telnet tool and the bridge-mode trick
are patched out. Get a firmware downgrade path, or use an ONT that natively supports
bridge mode.

The single fastest check: look for **System Management → Software Upgrade** in the
web UI. No such page means Airtel has removed the ability to change firmware, which
means the bridge-mode section of [GUIDE.md](GUIDE.md) will not work for you.

## Layout

```
GUIDE.md                  the full numbered walkthrough
TROUBLESHOOTING.md        error strings -> causes and fixes
NOTICE.md                 credits, licensing, and why no upstream code is vendored
zte_unlock/               the factory-mode client
firmware/                 the V9.0.11P1N40 downgrade image, vendored
reference/forum_posts.md  the source posts this writeup is derived from
tests/                    padding, handshake and status-page parsing tests
```

## Credits

I did not work this out alone. Nearly everything here came out of public
discussion on [india broadband forum](https://broadband.forum/), mainly:

- [F670Lv9.0 Telnet Access](https://broadband.forum/threads/220550/) — the main thread
- [Successful Telnet access on ZTE F670L router and unlock](https://broadband.forum/threads/233670/)
- [Bridge mode on unlocked ZTE F670L](https://broadband.forum/threads/233689/)
- [SIP setup on Airtel ZTE F670LV9](https://broadband.forum/threads/217511/)

**`@BornArcher8`** did most of the actual research. The unlock command
(`upgradetest sdefconf 198`), the re-lock counterpart, the explanation of what the
region code actually does, and the PPPoE password all came from them — I mostly
asked questions and they answered them. If this repo is useful to you, that is
who to thank.

The SIP credentials and the bridge-mode firmware downgrade I worked out myself,
by reading what others had already tried and following the dead ends.

A note on attribution: I posted about this on the forum in April 2025 under the
name **ghostrox69**, which was a temporary account. I no longer have access to
it, which is part of why I wrote all this down here. The posts are still up and
are quoted in [reference/forum_posts.md](reference/forum_posts.md), so the trail
back to the original discussion is intact even though the account is not.

### The tool in `zte_unlock/`

`zte_unlock/` is an independent implementation of the ONT factory-mode
handshake, written so this procedure does not depend on any single upstream
binary continuing to exist.

```sh
pip install -e .
python3 -m zte_unlock -i 192.168.1.1
```

Two dependencies, both installed by the above: `cryptography` for AES and
`psutil` for the MAC check.

Upstream tools it is compatible with:

- [stich86/zteOnu](https://github.com/stich86/zteOnu) (fork of
  [Septrum101/zteOnu](https://github.com/Septrum101/zteOnu)) — opens telnet
- [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools) — alternative Python implementation
- [zainarbani/ztelnet](https://github.com/zainarbani/ztelnet) — Windows `.exe` alternative

Both zteOnu projects are **AGPL-3.0**, which is why none of their source appears
here: copying it would make this repository's documentation AGPL too. The
protocol constants are reproduced because interoperability requires them; the
implementation is original. See [NOTICE.md](NOTICE.md).

## About the vendored firmware

`firmware/ZXHN_F670L_V9.0.11P1N40.bin` is ZTE's proprietary firmware image,
redistributed **unmodified**.

**It is not covered by this repo's WTFPL license and remains the property of ZTE.**
Everything else in this repository — the guide, the troubleshooting notes, the
scripts — is WTFPL.

- **Version:** `V9.0.11P1N40` (`ZXHN F670L UNI V9.0.11P1N40`, built 2022-05-25)
- **Size:** 24,070,224 bytes
- **sha256:** `57c0728a446b20f48c1c9da37e37e379fd4c7b1bc0a96cd5ce952ee1fbc0701e`
- **md5:** `bd178fc2d1469bf354d743c01e3dc9ec`
- **Original source:** linked from
  [this forum post](https://broadband.forum/threads/233689/post-1687611) that I
  made while working this out

Verify before flashing:

```sh
shasum -a 256 -c reference/firmware/ZXHN_F670L_V9.0.11P1N40.bin.sha256
```

It is vendored here because the original link was a personal Google Drive file that
can disappear at any time, and this is the only thing standing between you and the
bridge-mode section. It is a **downgrade**, not an upgrade — flashing current
firmware through this path would be a no-op at best.