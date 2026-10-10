# Unlock an Airtel Xstream ZTE F670L ONT

Notes from unlocking an ISP-locked ZTE F670L GPON ONT (Airtel Xstream, India) in April 2025:
opening telnet, clearing the ISP region lock, restoring PPPoE and SIP, and
reaching bridge mode.

Written up because the existing forum threads scatter the working procedure across
178 posts and contradict each other in places. The full walkthrough is in
[GUIDE.md](GUIDE.md); if something here is wrong, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
before assuming the hardware is at fault.

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

Open telnet with [`stich86/zteOnu`](https://github.com/stich86/zteOnu) → `upgradetest sdefconf 198`
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
firmware/                 the V9.0.11P1N40 downgrade image, vendored
reference/forum_posts.md  the source posts this writeup is derived from
scripts/                  helper scripts for telnet and config extraction
```

## Credits

Everything here was assembled from public discussion on
[india broadband forum](https://broadband.forum/), principally:

- [F670Lv9.0 Telnet Access](https://broadband.forum/threads/220550/) — the main thread
- [Successful Telnet access on ZTE F670L router and unlock](https://broadband.forum/threads/233670/)
- [Bridge mode on unlocked ZTE F670L](https://broadband.forum/threads/233689/)
- [SIP setup on Airtel ZTE F670LV9](https://broadband.forum/threads/217511/)

The unlock and PPPoE procedure came from `@BornArcher8`. The SIP credentials and the
bridge-mode firmware downgrade were worked out independently. Upstream tools:

- [stich86/zteOnu](https://github.com/stich86/zteOnu) (fork of
  [Septrum101/zteOnu](https://github.com/Septrum101/zteOnu)) — opens telnet
- [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools) — alternative Python implementation
- [zainarbani/ztelnet](https://github.com/zainarbani/ztelnet) — Windows `.exe` alternative

## About the vendored firmware

`firmware/ZXHN_F670L_V9.0.11P1N40.bin` is ZTE's proprietary firmware image,
redistributed **unmodified**. It is not covered by this repo's WTFPL license; it remains
the property of ZTE.

- **Version:** `V9.0.11P1N40` (`ZXHN F670L UNI V9.0.11P1N40`, built 2022-05-25)
- **Size:** 24,070,224 bytes
- **sha256:** `57c0728a446b20f48c1c9da37e37e379fd4c7b1bc0a96cd5ce952ee1fbc0701e`
- **md5:** `bd178fc2d1469bf354d743c01e3dc9ec`
- **Original source:** linked from
  [this forum post](https://broadband.forum/threads/233689/post-1687611) by the
  original author of this writeup

Verify before flashing:

```sh
shasum -a 256 -c reference/firmware/ZXHN_F670L_V9.0.11P1N40.bin.sha256
```

It is vendored here because the original link was a personal Google Drive file that
can disappear at any time, and this is the only thing standing between you and the
bridge-mode section. It is a **downgrade**, not an upgrade — flashing current
firmware through this path would be a no-op at best.