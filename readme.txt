=== Ocasio Limit Login Attempts ===
Contributors: ocas
Tags: limit login attempts, login security, brute force, login protection, failed login
Requires at least: 5.8
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protects your site from automated brute-force attacks by limiting the number of failed login attempts from a single IP address.

== Description ==

Hackers and automated botnets constantly hammer WordPress login screens with thousands of password guesses.

Ocasio Limit Login Attempts blocks these brute-force attacks in their tracks. It tracks consecutive failed login attempts by IP address and automatically locks out any visitor who fails 3 times in a row.

Locked visitors receive a temporary timeout (default 20 minutes) before they can try logging in again.

It includes a built-in IP whitelist with a 1-click "Whitelist My IP" button so you never accidentally lock yourself out, plus a live list of locked IPs where you can unlock someone with one click.

Zero bloat, zero tracking scripts, and no heavy database queries.

== Installation ==

1. Upload the `ocasio-limit-login-attempts` folder to your `/wp-content/plugins/` directory, or install it directly through your WordPress admin screen.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **Ocasio Plugins -> Limit Login Attempts** in your admin sidebar to adjust lockout settings and whitelist your IP.

== Frequently Asked Questions ==

= How many failed attempts trigger a lockout? =
By default, 3 consecutive failed login attempts will trigger a temporary lockout.

= How long does the lockout last? =
The default lockout duration is 20 minutes. You can easily change this number in the settings screen.

= Can I accidentally lock myself out? =
No. Click the "Whitelist My IP" button on the settings screen. Whitelisted IP addresses will never be locked out under any circumstances.

= Does this work behind Cloudflare or reverse proxies? =
Yes. It detects real visitor IP addresses using Cloudflare headers (`HTTP_CF_CONNECTING_IP`) and standard proxy headers (`HTTP_X_FORWARDED_FOR`).

= Does this slow down my website? =
No. It only runs lightweight checks on the WordPress login form and doesn't run extra scripts on your public pages.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Added 3-attempt brute-force lockout engine with configurable timeout duration.
* Added 1-click IP whitelisting.
* Added live locked IPs inspector with 1-click unlock action.
* Added total blocked attacks statistics counter.
* Integrated into the unified Ocasio Plugins suite dashboard.
