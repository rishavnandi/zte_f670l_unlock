# NOTICE

This repository contains an independent implementation of the ZTE ONU
factory-mode interface. No source code was copied from any other project.

## Protocol facts are not copyrightable expression

The following are interface elements (they define what the ONT firmware
speaks and accepts) and are reproduced because interoperability requires it:

- Endpoint paths (`/webFac`, `/webFacEntry`)
- Command strings (`SendSq.gch`, `RequestFactoryMode.gch`, `CheckLoginAuth.gch`,
  `SendInfo.gch`, `FactoryMode.gch`)
- The AES key pools and the magic MAC constant `00:07:29:55:35:57`
- The key derivation rule (pool window indexed by the request's seconds value,
  XORed with `0xA5`)

These come from the ONT's own firmware behaviour. They are documented publicly
at [hack-gpon.org](https://hack-gpon.org/ont-zte-f6005v3/#enable-telnet) and in
the [broadband.forum threads](reference/forum_posts.md) this project cites.

Everything else here (the handshake state machine, credential handling, the
protocol-specific zero padding, error messages, CLI, tests and documentation)
was written for this repository.

The AES primitive itself comes from the `cryptography` library, not from this
code.

## Upstream projects this is compatible with

This tool speaks the same protocol as, and can replace, these projects. Neither
was copied; both remain the reference implementations of the approach:

| Project | Author | License | Role |
| --- | --- | --- | --- |
| [stich86/zteOnu](https://github.com/stich86/zteOnu) | stich86 | **AGPL-3.0** | The fork that works on current Airtel firmware (V9.0.10P18N2B) |
| [Septrum101/zteOnu](https://github.com/Septrum101/zteOnu) | Septrum101 | **AGPL-3.0** | The original tool stich86's fork derives from |

**AGPL-3.0 is why no upstream code appears in this repository.** Vendoring or
copying that source would have made this repository (including its
documentation) AGPL-3.0. This is an independent implementation so the guide and
tooling can stay under WTFPL.

Other implementations of the same approach, for reference:

- [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools): AGPL-3.0
- [zainarbani/ztelnet](https://github.com/zainarbani/ztelnet): ships a Windows binary

## Why this exists

Upstream projects are stable and public, but a procedure that depends on one
repository remaining reachable is fragile. This implementation means the guide in
[GUIDE.md](GUIDE.md) keeps working even if a tool disappears.

## Verification

The cipher comes from `cryptography`, so its correctness is that project's
responsibility. What this repository owns is the protocol-specific zero padding,
which is **not** PKCS#7: it pads with NULs and appends a whole block even when
the input is already aligned. That is cross-checked against the OpenSSL CLI
across all three key sizes with randomised keys and lengths, and pinned to the
FIPS-197 known-answer vector in the tests.

An earlier version of this repository hand-rolled the cipher instead of taking a
dependency, and replaced it during development once it became clear the primitive
is not the interesting part. No committed version of this repository shipped a
broken cipher: the AES-192 key schedule bug was found and fixed before the code
was first committed.

Protocol compatibility was verified by **differential testing against the
compiled upstream Go binary**: both clients were pointed at the same mock ONT and
their request sequences compared step for step, including decrypted payload
contents. Four scenarios are covered: v2 negotiation, v1 negotiation,
FactoryMode returning a non-200 with a valid body, and authentication rejection
All produce identical request sequences and outcomes.

That process found real defects that unit tests alone had missed, most
importantly that the handshake must ride a **single persistent connection**: the
ONT tracks factory-mode state per connection, and urllib's default
`Connection: close` silently broke it. `tests/test_handshake.py` and
`tests/test_compat.py` cover each of these.

**This is not validated against real ONT hardware.** Everything above is against
a mock and a reference binary. See the caveats in [GUIDE.md](GUIDE.md).

## Trademarks

ZTE and the F670L are trademarks of their respective owners. This project is
unofficial and unaffiliated. Firmware images in `firmware/` remain the property
of ZTE and are excluded from this repository's license.