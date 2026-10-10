# Source material

Every factual claim in this repo traces back to one of these. Post IDs are
XenForo's and are permanent.

A note on the account: I posted all of this on the forum under the name
**ghostrox69**, which was a throwaway I made because I did not want my real
account associated with router-modifying advice. I have since lost access to it.
The posts are still up, so the trail back to the original discussion survives even
though the account does not — which is the main reason this repo exists.

## Where it came from

Five threads on [broadband.forum](https://broadband.forum/), forum: Airtel Xstream
Broadband.

| Thread | Posts | What it gave me |
| --- | --- | --- |
| [F670Lv9.0 Telnet Access](https://broadband.forum/threads/220550/) | 178 | The bulk of it. `upgradetest sdefconf 198`, PPPoE credentials, the `decry` config-dump commands |
| [Successful Telnet access on ZTE F670L router and unlock](https://broadband.forum/threads/233670/) | 3 | The summary post naming zteOnu and the unlock command |
| [Bridge mode on unlocked ZTE F670L](https://broadband.forum/threads/233689/) | 20 | Bridge mode, the port binding steps, the downgrade firmware |
| [SIP setup on Airtel ZTE F670LV9](https://broadband.forum/threads/217511/) | 8 | The unanswered SIP question, answered later |
| [How to Retrieve My Airtel Account Password](https://broadband.forum/threads/232038/) | 24 | PPPoE password = account number, and the Relationship ID exception |

## My posts

I did the walkthrough in [GUIDE.md](../GUIDE.md) between 16–18 April 2025. These
are my twelve posts, in order. Quoted as written, typos included, since they are
the primary record.

### The unlock itself

**[Successful Telnet access on ZTE F670L router and unlock](https://broadband.forum/threads/233670/)**
— post 1687425, 17 Apr 2025:

> The zte0nu tool by user stich86 on GitHub works on latest firmware as of writing
> (V9.0.10P18N2B) and provides telnet access to router which then can be unlocked
> fully by using the upgradetest sdefconf 198 command.

### PPPoE credentials

**[How to Retrieve My Airtel Account Password](https://broadband.forum/threads/232038/)**
— post 1687325, 16 Apr 2025:

> I dont see this relationship ID in my current ebill, prepaid connection from the
> start not converted from dsl or anything.

**F670Lv9.0 Telnet Access** — post 1687324, 16 Apr 2025:

> Does the tool unlock bridge mode capability and does the router still work fine on
> its own if we are not using it in bridge mode
> Regarding the pppoe creds, we can see the username right in the ui but where is the
> password in the ebill like everyone says, maybe I'm blind but I dont see it.

**How to Retrieve My Airtel Account Password** — post 1687390, 16 Apr 2025:

> thanks! found the acc number from app, will unlock my ZTE router using the zteonu
> tool from github, lets hope the creds work

**F670Lv9.0 Telnet Access** — post 1687382, 16 Apr 2025. Notable for the question that
shaped step 1 of the guide — backing up settings before unlocking:

> EDIT - Got my acc number from the app, should work for pppoe pass but need to try.
> Just another question to BornArcher, is there anything you wish you would've backed
> up or had screenshots of from default settings before unlocking the router?

**F670Lv9.0 Telnet Access** — post 1687424, 17 Apr 2025:

> this fork still works for latest firmware as of writing (V9.0.11P1N40)... just
> changed the mac of wifi card on linux and was easily able to log in PPPoE using acc
> number as password.

### SIP credentials

Posted twice, to two different threads, same content.

**[SIP setup on Airtel ZTE F670LV9](https://broadband.forum/threads/217511/)** —
post 1687504, 17 Apr 2025:

> Years later but these are credentials for Jharkhand and Bihar at least
>
> - SIP Account -> `+91<landline num without 0>`
> - Authorization Username -> `+91<landline num without 0>@bh.ims.airtel.in` (bh is the
>   state code for Bihar and Jharkhand also for some reason)
> - Password -> `Nokia@1`

**F670Lv9.0 Telnet Access** — post 1687503, 17 Apr 2025:

> I took multiple screenshots of WAN and VOIP and other stuff just in case haha, only
> thing I'm struggling with right now is the SIP account details to make landline work

### Bridge mode

**[Bridge mode on unlocked ZTE F670L](https://broadband.forum/threads/233689/)** —
post 1687533, 17 Apr 2025:

> Does anyone know how to enable bridge mode on an unlocked ZTE router, I unlocked it
> using the zte0nu tool but can't seem to turn on bridge mode using the old inspect
> element trick.

Same thread — post 1687611, 18 Apr 2025, the resolution and the origin of the
vendored firmware:

> UPDATE - Upgraded my firmware and was able to use the inspect element trick to get
> bridge mode to finally retain in WAN tab.

The attached file is `ZXHN_F670L_V9.0.11P1N40.bin`, now vendored in this repo at
`firmware/`. The post says "upgraded" but the file is a **downgrade** to a 2022 build
— `@BornArcher8` points this out in
[the next reply](https://broadband.forum/threads/233689/post-1687780):

> this firmware is actually older than the current firmware. So while we use "upgrade"
> process in webui to change the firmware technically we are downgrading. As this
> exploit exsisted in the older firware and was fixed after update.

**F670Lv9.0 Telnet Access** — posts 1687512 and 1687515, 17 Apr 2025, closing out the
thread. Note the intended end state — OPNsense, not a consumer router:

> hopefully it works without having to deal with Airtel, will need to check by
> installing opnsense on proxmox most likely as I lack a lot of the hardware as well

---

## What I owe to other people

`@BornArcher8` (`tr1k0N4`) did most of the actual research. I came in with a
locked router and a vague idea; the unlock command, the re-lock counterpart, the
explanation of what the region code actually does, the PPPoE password, and the
port-binding steps are all theirs. Without those answers I would have given up
somewhere around the credential-parsing step.

**The unlock and re-lock commands** — [post 1687154](https://broadband.forum/threads/220550/post-1687154):

> To unlock router use these command - `upgradetest sdefconf 198`. This will unlock
> router and you can do custom settings on 192.168.1.1.

[post 1680700](https://broadband.forum/threads/220550/post-1680700):

> If you again want to lockdown the router you can just run this command -
> `upgradetest sdefconf 35`. 35 is the regioncode for India. Once we set to 35
> automatically tr069 will send us the profile and the router will be locked but you
> can get the sip profile and PPPoE profile this way.

**The region-code explanation** — [post 1608820](https://broadband.forum/threads/220550/post-1608820):

> admin was always accesible in webui but the thing is airtel locked it with something
> regioncode that locks the ont to region specific isp 35 being india so basically u
> just need to chnage it to 198 which is a stock manufacture region code which will
> unlock eveyrthing

**The bare-command correction.** [Post 1608812](https://broadband.forum/threads/220550/post-1608812)
gives the three-step original procedure including the `setmac 4 198/` prefix, but
[post 1686602](https://broadband.forum/threads/220550/post-1686602) reports the bare
form is what works:

> by putting the command in 3rd line "setmac 4 198/upgradetest sdefconf 198" was not
> working instead changing it to "upgradetest sdefconf 198" did the job

**PPPoE password** — [post 1687326](https://broadband.forum/threads/220550/post-1687326):

> The PPPoE password in my case was just my Airtel account number. You can find your
> Airtel account number in ebill or just in the Airtel app.

And that the ONT routes or bridges, both fine —
[same post](https://broadband.forum/threads/220550/post-1687326):

> After unlocking we can put the ont in bridge mode and use an external router or use
> the ont for routing too (without bridge mode). It works both ways.

**The Relationship ID exception** — [post 1678255](https://broadband.forum/threads/232038/post-1678255):

> here was using the current Account Number (found in the Airtel Thanks app) as the
> password instead of the Relationship ID found in your old Airtel Xstream eBills,
> due to which he was unable to establish PPPoE session

**Port binding steps** — [post 1694043](https://broadband.forum/threads/233689/post-1694043).
Condensed in the guide, but note the closing caveat:

> I suggest you to watch some videos from the above channel and use ChatGPT. I can't
> help more as I don't actually use bridge mode.

**The config-dump commands** — credited to `@conquest` and `@scn` in
[posts 1609043](https://broadband.forum/threads/220550/post-1609043),
[1609086](https://broadband.forum/threads/220550/post-1609086) and
[1609093](https://broadband.forum/threads/220550/post-1609093).

## Known-bad advice, and why

Recorded so nobody re-derives it.

| Claim | Reality |
| --- | --- |
| `setmac 4 198/upgradetest sdefconf 198` | Does not work. Use the bare `upgradetest sdefconf 198`. |
| `decry` works on all firmware | Removed in later builds. Silently prints the command list instead. |
| The firmware link is an "upgrade" | It is a downgrade to a 2022 build. |
| Changing the MAC fixes `send sq: unknown error` | Only helps with the `--new` variant. A patched `send sq` is unfixable. |
| Telnet creds are permanent | They rotate on every reboot. |
| `dbcry` is still available | Removed. `decry` too, on newer builds. |

## Caveats on this writeup

- Written in October 2026 from a run I did in April 2025. **Nothing here was
  re-tested against hardware.** Firmware state has moved on since.
- The `18N3D` breakage is reported by users in late 2025 and April 2026, not observed
  directly.
- Bridge mode via inspect element is **the fragile part**. It depends on an unpatched
  firmware staying flashable. Treat it as time-limited.
- Other states' SIP credentials are unknown; only Bihar/Jharkhand (`bh`) is documented.
- Where the thread contradicts itself, this guide follows the reports that were
  confirmed working by multiple people, and says so inline.