=== Web Vault ===
Contributors: jackperry
Tags: dashboard, auto-login, rest-api, management, ssl
Requires at least: 5.8
Tested up to: 6.8
Stable tag: 1.4.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connects your WordPress site to the Web Vault central management dashboard with secure auto-login and REST API support.

== Description ==

Web Vault is a lightweight connector plugin that links your WordPress site to the Web Vault central management dashboard.

**Features:**
* Secure token-based auto-login for administrators and assigned users
* REST API endpoints for site status, authentication, and token retrieval
* SSL bypass support for HTTP-only environments (no certificate required)
* Granular user access control — choose exactly who can be auto-logged in
* Clean, modern admin interface

**REST API Endpoints:**
* `POST /wp-json/WP/v1/ping` — Returns site info and status
* `POST /wp-json/WP/v1/auth` — Validates an access token
* `GET  /wp-json/WP/v1/get-token` — Returns the stored token (requires Secret header)

== Installation ==

1. Upload the `web-vault` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** screen in WordPress.
3. Go to **Settings → Web Vault** to find your access token.
4. Enter the token in your central dashboard.

== Changelog ==

= 1.4.0 =
* Complete UI redesign with sidebar navigation
* Added Access Users tab for granular auto-login control
* Added API Endpoints reference tab
* Token regeneration with confirmation prompt
* Replaced string comparison with hash_equals() for timing-safe token validation
* Activation hook auto-generates token on first install
* All code in English; no third-party dependencies

= 1.3.0 =
* Added assigned users feature
* SSL bypass for HTTP-only environments

= 1.2.0 =
* Added SSL detection and HTTP fallback
* REST API endpoints
