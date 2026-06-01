# SOUPEDECODE.LOCAL — TryHackMe Writeup

**Difficulty:** Intermediate
**Category:** Active Directory

---

## Overview

A Windows Server 2022 Active Directory room that chains together classic AD attack techniques — from unauthenticated enumeration all the way to Domain Admin via a backup share and Pass-the-Hash. Each finding feeds naturally into the next.

---

## Reconnaissance

Initial nmap scan revealed a Domain Controller (`DC01.SOUPEDECODE.LOCAL`) running Windows Server 2022, with standard AD services exposed — Kerberos, LDAP, SMB, and RDP.

---

## User Enumeration

Used `kerbrute` to enumerate valid domain accounts via Kerberos pre-authentication probing, identifying `charlie`, `admin`, and `administrator`. SMB enumeration with a null session revealed two non-standard shares: `backup` and `Users`.

A guest session allowed RID brute forcing via `crackmapexec`, dumping 1069 domain users.

---

## Initial Access

Password spraying the full user list with `--no-bruteforce` (username as password) returned a hit: `ybob317:ybob317`. Accessed the `Users` share via SMB and retrieved the user flag from the Desktop.

---

## Privilege Escalation

Kerberoasting with `impacket-GetUserSPNs` returned TGS hashes for five service accounts. Hashcat cracked one — `file_svc:Password123!!`.

`file_svc` had read access to the `backup` share, which contained NTLM hashes for domain machine accounts. Pass-the-Hash testing against each revealed `FileServer$` had local admin rights on the DC.

Running `impacket-secretsdump` via `FileServer$` performed a full NTDS dump, returning the Administrator NT hash. This was used to authenticate via `evil-winrm` and retrieve the root flag from the Administrator Desktop.

---

## Attack Chain Summary

| Step | Technique |
|---|---|
| User enumeration | Kerbrute + RID brute force |
| Initial foothold | Password spray (user:user) |
| Credential access | Kerberoasting → hashcat |
| Lateral movement | SMB backup share → machine account hashes |
| Domain Admin | Pass-the-Hash → secretsdump → evil-winrm |

---

## Key Takeaways

- Always RID brute force with a guest session — it can dump thousands of usernames without credentials
- Username as password is still surprisingly common even in CTF environments designed to mimic real AD
- Backup shares are high value targets — they often contain credential material
- Machine accounts can hold elevated privileges; don't skip PTH testing against them
- `evil-winrm` supports Pass-the-Hash natively, making it the cleanest way onto a DC once you have the Administrator hash