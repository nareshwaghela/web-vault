<?php
/**
 * Plugin Name:       Web Vault
 * Plugin URI:        https://coozmoo.webvault.me/
 * Description:       Connects your WordPress site to the central management dashboard. Supports secure auto-login, REST API authentication, and SSL bypass for HTTP-only environments.
 * Version:           1.4.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Naresh Waghela
 * Author URI:        https://coozmoo.webvault.me/author/naresh-waghela/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       web-vault
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WEB_VAULT_VERSION', '1.4.0' );
define( 'WEB_VAULT_FILE', __FILE__ );
define( 'WEB_VAULT_DIR',     plugin_dir_path( __FILE__ ) );
define( 'WEB_VAULT_URL',     plugin_dir_url( __FILE__ ) );

// ===========================================================
// SSL Detection & Safe URL Helpers
// ===========================================================

/**
 * Detects whether SSL is currently active,
 * including reverse-proxy / load-balancer forwarding headers.
 */
function web_vault_is_ssl_active() {
	if ( is_ssl() ) {
		return true;
	}
	if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === $_SERVER['HTTP_X_FORWARDED_PROTO'] ) {
		return true;
	}
	if ( isset( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === $_SERVER['HTTP_X_FORWARDED_SSL'] ) {
		return true;
	}
	return false;
}

/**
 * Returns a URL that uses the correct protocol for the current environment.
 * Falls back to HTTP when SSL is not active.
 */
function web_vault_safe_url( $url ) {
	if ( ! web_vault_is_ssl_active() ) {
		$url = str_replace( 'https://', 'http://', $url );
	}
	return $url;
}

/**
 * Disable SSL certificate verification for outgoing WordPress HTTP API requests.
 * Required when the remote dashboard connects to HTTP-only sites.
 */
add_filter( 'https_ssl_verify',       '__return_false' );
add_filter( 'https_local_ssl_verify', '__return_false' );
add_filter( 'http_request_args', function ( $args, $url ) {
	$args['sslverify'] = false;
	return $args;
}, 10, 2 );

// ===========================================================
// Token Helper
// ===========================================================

/**
 * Returns the stored access token, generating a new one if none exists.
 */
function web_vault_get_token() {
	$token = get_option( 'web_vault_token' );
	if ( ! $token ) {
		$token = wp_generate_password( 32, false );
		update_option( 'web_vault_token', $token );
	}
	return $token;
}

// ===========================================================
// Admin Menu
// ===========================================================

add_action( 'admin_menu', function () {
	add_options_page(
		'Web Vault',
		'Web Vault',
		'manage_options',
		'web-vault',
		'web_vault_render_page'
	);
} );

// ===========================================================
// Settings Page — Render
// ===========================================================

function web_vault_render_page() {

	// Save: token
	if ( isset( $_POST['wbv_action'] ) && 'save_token' === $_POST['wbv_action'] ) {
		check_admin_referer( 'web_vault_settings' );
		update_option( 'web_vault_token', sanitize_text_field( $_POST['web_vault_token'] ) );
		$saved_token = true;
	}

	// Regenerate token
	if ( isset( $_POST['wbv_action'] ) && 'regen_token' === $_POST['wbv_action'] ) {
		check_admin_referer( 'web_vault_settings' );
		$new_token = wp_generate_password( 32, false );
		update_option( 'web_vault_token', $new_token );
		$regen_token = true;
	}

	// Save: assigned users
	if ( isset( $_POST['wbv_action'] ) && 'save_users' === $_POST['wbv_action'] ) {
		check_admin_referer( 'web_vault_settings' );
		$raw   = isset( $_POST['wbv_users'] ) ? (array) $_POST['wbv_users'] : array();
		$clean = array_map( 'absint', $raw );
		update_option( 'web_vault_allowed_users', $clean );
		$saved_users = true;
	}

	$token         = web_vault_get_token();
	$ssl_ok        = web_vault_is_ssl_active();
	$allowed_ids   = (array) get_option( 'web_vault_allowed_users', array() );
	$all_users     = get_users( array( 'orderby' => 'display_name' ) );
	$autologin_url = web_vault_safe_url( home_url( '/' ) ) . '?wv_autologin=USERNAME&token=' . $token;
	$active_tab    = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview';

	web_vault_render_styles();
	?>
	<div class="wbv-page">

		<!-- ── Sidebar ── -->
		<nav class="wbv-sidebar">
			<div class="wbv-brand">
				<div class="wbv-brand-icon">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
				</div>
				<div>
					<div class="wbv-brand-name">Web Vault</div>
					<div class="wbv-brand-ver">v<?php echo WEB_VAULT_VERSION; ?></div>
				</div>
			</div>

			<div class="wbv-nav">
				<?php
				$tabs = array(
					'overview' => array(
						'label' => 'Overview',
						'icon'  => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
					),
					'token'    => array(
						'label' => 'Access Token',
						'icon'  => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
					),
					'users'    => array(
						'label' => 'Access Users',
						'icon'  => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
					),
					'endpoints' => array(
						'label' => 'API Endpoints',
						'icon'  => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
					),
				);
				foreach ( $tabs as $key => $t ) {
					$is_active = ( $active_tab === $key );
					$url = admin_url( 'options-general.php?page=web-vault&tab=' . $key );
					echo '<a href="' . esc_url( $url ) . '" class="wbv-nav-item ' . ( $is_active ? 'active' : '' ) . '">';
					echo '<span class="wbv-nav-icon">' . $t['icon'] . '</span>';
					echo esc_html( $t['label'] );
					echo '</a>';
				}
				?>
			</div>

			<div class="wbv-sidebar-status">
				<div class="wbv-ss-dot <?php echo $ssl_ok ? 'green' : 'amber'; ?>"></div>
				<span><?php echo $ssl_ok ? 'HTTPS / SSL Active' : 'HTTP / SSL Bypassed'; ?></span>
			</div>
		</nav>

		<!-- ── Main Content ── -->
		<main class="wbv-main">

			<?php if ( ! empty( $saved_token ) ) : ?>
				<div class="wbv-alert success">Token saved successfully.</div>
			<?php endif; ?>
			<?php if ( ! empty( $regen_token ) ) : ?>
				<div class="wbv-alert success">New token generated. Update your dashboard immediately.</div>
			<?php endif; ?>
			<?php if ( ! empty( $saved_users ) ) : ?>
				<div class="wbv-alert success">Access users updated.</div>
			<?php endif; ?>
			<?php if ( ! $ssl_ok ) : ?>
				<div class="wbv-alert warning">
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
					SSL is not active on this site. HTTP mode is enabled — auto-login and API calls work over HTTP.
				</div>
			<?php endif; ?>

			<!-- ═══════ OVERVIEW TAB ═══════ -->
			<?php if ( 'overview' === $active_tab ) : ?>
			<div class="wbv-section-title">Site Overview</div>

			<div class="wbv-stat-grid">
				<div class="wbv-stat">
					<div class="wbv-stat-label">Status</div>
					<div class="wbv-stat-value online">
						<span class="blink-dot"></span> Online
					</div>
				</div>
				<div class="wbv-stat">
					<div class="wbv-stat-label">SSL</div>
					<div class="wbv-stat-value <?php echo $ssl_ok ? 'ssl-on' : 'ssl-off'; ?>">
						<?php echo $ssl_ok ? 'Active' : 'Bypassed'; ?>
					</div>
				</div>
				<div class="wbv-stat">
					<div class="wbv-stat-label">Protocol</div>
					<div class="wbv-stat-value"><?php echo $ssl_ok ? 'HTTPS' : 'HTTP'; ?></div>
				</div>
				<div class="wbv-stat">
					<div class="wbv-stat-label">WP Version</div>
					<div class="wbv-stat-value"><?php echo esc_html( get_bloginfo( 'version' ) ); ?></div>
				</div>
			</div>

			<div class="wbv-info-card">
				<div class="wbv-info-row">
					<span class="wbv-info-label">Site Name</span>
					<span class="wbv-info-val"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></span>
				</div>
				<div class="wbv-info-row">
					<span class="wbv-info-label">Site URL</span>
					<span class="wbv-info-val mono"><?php echo esc_html( web_vault_safe_url( home_url() ) ); ?></span>
				</div>
				<div class="wbv-info-row">
					<span class="wbv-info-label">Admin Email</span>
					<span class="wbv-info-val mono"><?php echo esc_html( get_option( 'admin_email' ) ); ?></span>
				</div>
				<div class="wbv-info-row">
					<span class="wbv-info-label">PHP Version</span>
					<span class="wbv-info-val mono"><?php echo esc_html( phpversion() ); ?></span>
				</div>
				<div class="wbv-info-row">
					<span class="wbv-info-label">Allowed Users</span>
					<span class="wbv-info-val"><?php echo count( $allowed_ids ); ?> assigned + all administrators</span>
				</div>
			</div>

			<!-- ═══════ TOKEN TAB ═══════ -->
			<?php elseif ( 'token' === $active_tab ) : ?>
			<div class="wbv-section-title">Access Token</div>
			<p class="wbv-section-desc">This token authenticates your central dashboard. Keep it private — anyone with this token can trigger auto-login for allowed users.</p>

			<div class="wbv-card">
				<div class="wbv-card-label">Current Token</div>
				<form method="post" autocomplete="off">
					<?php wp_nonce_field( 'web_vault_settings' ); ?>
					<input type="hidden" name="wbv_action" value="save_token">
					<div class="wbv-field-row">
						<input
							type="text"
							name="web_vault_token"
							id="wbv-token-input"
							class="wbv-input mono"
							value="<?php echo esc_attr( $token ); ?>"
							autocomplete="off"
						>
						<button type="button" class="wbv-btn ghost" id="wbv-copy-btn" onclick="
							var el = document.getElementById('wbv-token-input');
							el.select();
							document.execCommand('copy');
							this.textContent = 'Copied!';
							setTimeout(() => this.textContent = 'Copy', 2000);
						">Copy</button>
						<button type="submit" class="wbv-btn primary">Save</button>
					</div>
				</form>

				<form method="post" style="margin-top:12px">
					<?php wp_nonce_field( 'web_vault_settings' ); ?>
					<input type="hidden" name="wbv_action" value="regen_token">
					<button type="submit" class="wbv-btn danger" onclick="return confirm('This will invalidate the current token. Your dashboard will stop working until you update it there. Continue?')">Regenerate Token</button>
				</form>
			</div>

			<div class="wbv-card" style="margin-top:16px">
				<div class="wbv-card-label">Auto-Login URL Format</div>
				<div class="wbv-code-block">
					<div class="wbv-code-comment">Replace USERNAME with the target WordPress username</div>
					<div class="wbv-code-line"><?php echo esc_html( $autologin_url ); ?></div>
				</div>
				<p class="wbv-hint">Only administrators and users listed in <strong>Access Users</strong> can use this link.</p>
			</div>

			<!-- ═══════ USERS TAB ═══════ -->
			<?php elseif ( 'users' === $active_tab ) : ?>
			<div class="wbv-section-title">Access Users</div>
			<p class="wbv-section-desc">Choose which users can be logged in via auto-login. Administrators always have access and cannot be unchecked.</p>

			<div class="wbv-card">
				<form method="post">
					<?php wp_nonce_field( 'web_vault_settings' ); ?>
					<input type="hidden" name="wbv_action" value="save_users">

					<div class="wbv-user-list">
						<?php foreach ( $all_users as $u ) :
							$user_obj  = new WP_User( $u->ID );
							$roles     = (array) $user_obj->roles;
							$is_admin  = in_array( 'administrator', $roles, true );
							$is_active = $is_admin || in_array( $u->ID, $allowed_ids, true );
							$initials  = strtoupper( substr( $u->display_name, 0, 1 ) );
							$hash      = abs( crc32( $u->user_email ) );
							$colors    = array( '#5b6ef5', '#22c55e', '#f59e0b', '#ec4899', '#14b8a6', '#f97316' );
							$av_color  = $colors[ $hash % count( $colors ) ];
						?>
						<label class="wbv-user-row <?php echo $is_admin ? 'is-admin' : ''; ?>">
							<input
								type="checkbox"
								name="wbv_users[]"
								value="<?php echo esc_attr( $u->ID ); ?>"
								<?php checked( $is_active ); ?>
								<?php disabled( $is_admin ); ?>
								class="wbv-checkbox"
							>
							<span class="wbv-avatar" style="background:<?php echo esc_attr( $av_color ); ?>">
								<?php echo esc_html( $initials ); ?>
							</span>
							<span class="wbv-user-info">
								<span class="wbv-user-name"><?php echo esc_html( $u->display_name ); ?></span>
								<span class="wbv-user-meta"><?php echo esc_html( $u->user_login ); ?> &middot; <?php echo esc_html( $u->user_email ); ?></span>
							</span>
							<span class="wbv-role-tag <?php echo $is_admin ? 'admin' : ''; ?>">
								<?php echo esc_html( implode( ', ', $roles ) ); ?>
							</span>
						</label>
						<?php endforeach; ?>
					</div>

					<div class="wbv-form-footer">
						<button type="submit" class="wbv-btn primary">Save Access Users</button>
					</div>
				</form>
			</div>

			<!-- ═══════ ENDPOINTS TAB ═══════ -->
			<?php elseif ( 'endpoints' === $active_tab ) : ?>
			<div class="wbv-section-title">REST API Endpoints</div>
			<p class="wbv-section-desc">These endpoints are used by your central dashboard to communicate with this site.</p>

			<?php
			$base = web_vault_safe_url( home_url( '/wp-json/WV/v1' ) );
			$endpoints = array(
				array(
					'method' => 'POST',
					'path'   => $base . '/ping',
					'desc'   => 'Returns site info, status, SSL state, and plugin list. No authentication required.',
				),
				array(
					'method' => 'POST',
					'path'   => $base . '/auth',
					'desc'   => 'Validates a token. Send { "token": "..." } as JSON body. Returns site metadata on success.',
				),
				array(
					'method' => 'GET',
					'path'   => $base . '/get-token',
					'desc'   => 'Returns the stored token. Requires a Secret header matching WEB_VAULT_SECRET.',
				),
			);
			foreach ( $endpoints as $ep ) :
			?>
			<div class="wbv-endpoint-card">
				<div class="wbv-ep-top">
					<span class="wbv-method <?php echo strtolower( $ep['method'] ); ?>"><?php echo esc_html( $ep['method'] ); ?></span>
					<code class="wbv-ep-path"><?php echo esc_html( $ep['path'] ); ?></code>
				</div>
				<p class="wbv-ep-desc"><?php echo esc_html( $ep['desc'] ); ?></p>
			</div>
			<?php endforeach; ?>
			<?php endif; ?>

		</main>
	</div>
	<?php
}

// ===========================================================
// CSS — Injected on the plugin's own admin page only
// ===========================================================

function web_vault_render_styles() {
	?>
	<style>
	@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');

	/* ── Reset & Base ─────────────────────────────── */
	#wpwrap, #wpcontent, #wpbody-content { background: #0e0f14 !important; }
	#wpbody-content { padding-top: 0 !important; }
	.wbv-page * { box-sizing: border-box; font-family: 'DM Sans', sans-serif; }

	/* ── Layout ───────────────────────────────────── */
	.wbv-page {
		display: flex;
		min-height: 100vh;
		background: #0e0f14;
		color: #c8cad2;
	}

	/* ── Sidebar ──────────────────────────────────── */
	.wbv-sidebar {
		width: 220px;
		flex-shrink: 0;
		background: #090a0e;
		border-right: 1px solid #1a1c25;
		display: flex;
		flex-direction: column;
		padding: 24px 0 20px;
		position: sticky;
		top: 0;
		height: 100vh;
	}
	.wbv-brand {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 0 20px 24px;
		border-bottom: 1px solid #1a1c25;
		margin-bottom: 16px;
	}
	.wbv-brand-icon {
		width: 36px; height: 36px;
		background: #5b6ef5;
		border-radius: 9px;
		display: flex; align-items: center; justify-content: center;
		color: #fff;
		flex-shrink: 0;
	}
	.wbv-brand-name { font-size: 14px; font-weight: 600; color: #fff; }
	.wbv-brand-ver  { font-size: 11px; color: #3d3f4e; margin-top: 1px; font-family: 'DM Mono', monospace; }

	.wbv-nav { display: flex; flex-direction: column; gap: 2px; padding: 0 10px; flex: 1; }
	.wbv-nav-item {
		display: flex; align-items: center; gap: 10px;
		padding: 9px 12px;
		border-radius: 8px;
		font-size: 13px; font-weight: 500;
		color: #555766;
		text-decoration: none;
		transition: background .15s, color .15s;
	}
	.wbv-nav-item:hover { background: #131520; color: #9095a8; text-decoration: none; }
	.wbv-nav-item.active { background: #131a3a; color: #5b6ef5; }
	.wbv-nav-icon { display: flex; flex-shrink: 0; }
	.wbv-nav-icon svg { opacity: .7; }
	.wbv-nav-item.active .wbv-nav-icon svg { opacity: 1; }

	.wbv-sidebar-status {
		display: flex; align-items: center; gap: 8px;
		padding: 14px 20px 0;
		border-top: 1px solid #1a1c25;
		margin-top: 14px;
		font-size: 11px;
		font-family: 'DM Mono', monospace;
		color: #3d3f4e;
	}
	.wbv-ss-dot {
		width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
	}
	.wbv-ss-dot.green { background: #22c55e; }
	.wbv-ss-dot.amber { background: #f59e0b; }

	/* ── Main ─────────────────────────────────────── */
	.wbv-main {
		flex: 1;
		padding: 36px 40px;
		max-width: 740px;
	}

	/* ── Alerts ───────────────────────────────────── */
	.wbv-alert {
		display: flex; align-items: center; gap: 10px;
		padding: 12px 16px;
		border-radius: 10px;
		font-size: 13px;
		margin-bottom: 20px;
		border: 1px solid transparent;
	}
	.wbv-alert.success { background: #0d2218; border-color: #164832; color: #22c55e; }
	.wbv-alert.warning { background: #201a09; border-color: #3d3006; color: #f59e0b; }

	/* ── Section heading ──────────────────────────── */
	.wbv-section-title {
		font-size: 18px; font-weight: 600; color: #e8eaf0;
		margin: 0 0 6px;
		letter-spacing: -0.3px;
	}
	.wbv-section-desc {
		font-size: 13px; color: #4a4d5e;
		margin: 0 0 24px;
		line-height: 1.6;
	}

	/* ── Stat grid ────────────────────────────────── */
	.wbv-stat-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 20px;
	}
	.wbv-stat {
		background: #111318;
		border: 1px solid #1a1c25;
		border-radius: 12px;
		padding: 16px;
	}
	.wbv-stat-label { font-size: 11px; color: #3d3f4e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
	.wbv-stat-value { font-size: 15px; font-weight: 600; color: #9095a8; }
	.wbv-stat-value.online { color: #22c55e; }
	.wbv-stat-value.ssl-on { color: #22c55e; }
	.wbv-stat-value.ssl-off { color: #f59e0b; }

	/* animated pulse dot */
	.blink-dot {
		display: inline-block;
		width: 7px; height: 7px;
		background: #22c55e;
		border-radius: 50%;
		margin-right: 5px;
		vertical-align: middle;
		animation: blink 1.8s ease-in-out infinite;
	}
	@keyframes blink {
		0%,100% { opacity: 1; }
		50%      { opacity: .25; }
	}

	/* ── Info card ────────────────────────────────── */
	.wbv-info-card {
		background: #111318;
		border: 1px solid #1a1c25;
		border-radius: 12px;
		overflow: hidden;
	}
	.wbv-info-row {
		display: flex; align-items: center;
		padding: 12px 18px;
		border-bottom: 1px solid #1a1c25;
		gap: 16px;
	}
	.wbv-info-row:last-child { border-bottom: none; }
	.wbv-info-label { font-size: 12px; color: #3d3f4e; min-width: 130px; flex-shrink: 0; }
	.wbv-info-val   { font-size: 13px; color: #9095a8; word-break: break-all; }
	.wbv-info-val.mono { font-family: 'DM Mono', monospace; }

	/* ── Generic card ─────────────────────────────── */
	.wbv-card {
		background: #111318;
		border: 1px solid #1a1c25;
		border-radius: 12px;
		padding: 20px 22px;
	}
	.wbv-card-label {
		font-size: 11px; color: #3d3f4e;
		text-transform: uppercase; letter-spacing: 1px;
		margin-bottom: 14px;
	}

	/* ── Inputs & buttons ─────────────────────────── */
	.wbv-field-row { display: flex; gap: 8px; align-items: center; }
	.wbv-input {
		flex: 1;
		background: #0c0d12 !important;
		border: 1px solid #1e2030 !important;
		border-radius: 8px !important;
		color: #9095a8 !important;
		font-size: 13px !important;
		padding: 9px 12px !important;
		outline: none !important;
		box-shadow: none !important;
		transition: border-color .15s !important;
		min-width: 0;
	}
	.wbv-input:focus { border-color: #5b6ef5 !important; }
	.wbv-input.mono { font-family: 'DM Mono', monospace !important; font-size: 12px !important; }

	.wbv-btn {
		border-radius: 8px !important;
		font-family: 'DM Sans', sans-serif !important;
		font-size: 13px !important;
		font-weight: 500 !important;
		padding: 9px 16px !important;
		cursor: pointer !important;
		border: 1px solid transparent !important;
		transition: opacity .15s, background .15s !important;
		white-space: nowrap;
		text-decoration: none;
	}
	.wbv-btn.primary {
		background: #5b6ef5 !important;
		color: #fff !important;
		border-color: #5b6ef5 !important;
	}
	.wbv-btn.primary:hover { opacity: .85 !important; }
	.wbv-btn.ghost {
		background: transparent !important;
		color: #555766 !important;
		border-color: #1e2030 !important;
	}
	.wbv-btn.ghost:hover { color: #9095a8 !important; border-color: #2e3048 !important; }
	.wbv-btn.danger {
		background: transparent !important;
		color: #ef4444 !important;
		border-color: #2a1010 !important;
	}
	.wbv-btn.danger:hover { background: #1a0a0a !important; }

	/* ── Code block ───────────────────────────────── */
	.wbv-code-block {
		background: #0c0d12;
		border: 1px solid #1e2030;
		border-radius: 8px;
		padding: 14px 16px;
		font-family: 'DM Mono', monospace;
		font-size: 12px;
		word-break: break-all;
		margin-bottom: 12px;
	}
	.wbv-code-comment { color: #3d3f4e; margin-bottom: 6px; }
	.wbv-code-line { color: #5b6ef5; }
	.wbv-hint { font-size: 12px; color: #3d3f4e; margin: 0; }
	.wbv-hint strong { color: #555766; font-weight: 500; }

	/* ── User list ────────────────────────────────── */
	.wbv-user-list { display: flex; flex-direction: column; }
	.wbv-user-row {
		display: flex; align-items: center; gap: 12px;
		padding: 11px 14px;
		border-radius: 8px;
		cursor: pointer;
		transition: background .12s;
		margin: 1px 0;
	}
	.wbv-user-row:hover { background: #131520; }
	.wbv-user-row.is-admin { opacity: .65; cursor: default; }

	.wbv-checkbox {
		width: 15px; height: 15px;
		accent-color: #5b6ef5;
		flex-shrink: 0;
		cursor: pointer;
	}

	.wbv-avatar {
		width: 30px; height: 30px;
		border-radius: 50%;
		display: flex; align-items: center; justify-content: center;
		font-size: 12px; font-weight: 600; color: #fff;
		flex-shrink: 0;
	}

	.wbv-user-info { flex: 1; min-width: 0; }
	.wbv-user-name { display: block; font-size: 13px; font-weight: 500; color: #9095a8; }
	.wbv-user-meta { display: block; font-size: 11px; color: #3d3f4e; font-family: 'DM Mono', monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

	.wbv-role-tag {
		font-size: 10px;
		font-family: 'DM Mono', monospace;
		padding: 2px 8px;
		border-radius: 4px;
		background: #131520;
		border: 1px solid #1e2030;
		color: #3d3f4e;
		flex-shrink: 0;
	}
	.wbv-role-tag.admin { color: #f59e0b; border-color: #3a2c00; background: #1c1500; }

	.wbv-form-footer { display: flex; justify-content: flex-end; padding-top: 16px; border-top: 1px solid #1a1c25; margin-top: 8px; }

	/* ── Endpoint cards ───────────────────────────── */
	.wbv-endpoint-card {
		background: #111318;
		border: 1px solid #1a1c25;
		border-radius: 12px;
		padding: 16px 18px;
		margin-bottom: 12px;
	}
	.wbv-ep-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
	.wbv-method {
		font-size: 11px; font-weight: 600;
		font-family: 'DM Mono', monospace;
		padding: 3px 8px;
		border-radius: 4px;
		flex-shrink: 0;
	}
	.wbv-method.post { background: #0d2218; color: #22c55e; border: 1px solid #164832; }
	.wbv-method.get  { background: #111a36; color: #5b6ef5; border: 1px solid #1e2a58; }
	.wbv-ep-path { font-family: 'DM Mono', monospace; font-size: 12px; color: #5b6ef5; word-break: break-all; background: none; padding: 0; }
	.wbv-ep-desc { font-size: 12px; color: #3d3f4e; margin: 0; line-height: 1.6; }
	</style>
	<?php
}

// ===========================================================
// REST API Endpoints
// ===========================================================

add_action( 'rest_api_init', function () {

	register_rest_route( 'WV/v1', '/ping', array(
		'methods'             => 'POST',
		'callback'            => function () {
			return array(
				'status'      => 'online',
				'site_name'   => get_bloginfo( 'name' ),
				'site_url'    => web_vault_safe_url( home_url() ),
				'admin_email' => get_option( 'admin_email' ),
				'wp_version'  => get_bloginfo( 'version' ),
				'php_version' => phpversion(),
				'ssl_active'  => web_vault_is_ssl_active(),
				'protocol'    => web_vault_is_ssl_active() ? 'https' : 'http',
				'plugins'     => get_plugins(),
			);
		},
		'permission_callback' => '__return_true',
	) );

	register_rest_route( 'WV/v1', '/auth', array(
		'methods'             => 'POST',
		'callback'            => function ( WP_REST_Request $request ) {
			$params = $request->get_json_params();
			$token  = isset( $params['token'] ) ? sanitize_text_field( $params['token'] ) : '';
			$stored = get_option( 'web_vault_token' );

			if ( ! hash_equals( $stored, $token ) ) {
				return new WP_REST_Response( array( 'error' => 'Invalid token.' ), 403 );
			}

			return array(
				'authenticated' => true,
				'site_url'      => web_vault_safe_url( home_url() ),
				'admin_email'   => get_option( 'admin_email' ),
				'wp_version'    => get_bloginfo( 'version' ),
				'ssl_active'    => web_vault_is_ssl_active(),
			);
		},
		'permission_callback' => '__return_true',
	) );

	register_rest_route( 'WV/v1', '/get-token', array(
		'methods'             => 'GET',
		'callback'            => function ( WP_REST_Request $request ) {
			$headers  = $request->get_headers();
			$secret   = isset( $headers['secret'][0] ) ? sanitize_text_field( $headers['secret'][0] ) : '';
			$expected = defined( 'WEB_VAULT_SECRET' )
				? WEB_VAULT_SECRET
				: 'rG2a$4@VjW7xbQ#fT!ynhKzE9MupD*A^L1RjsOeZ6d$Pq8NcIBX0Ct%Uv3GYlmHw';

			if ( ! hash_equals( $expected, $secret ) ) {
				return new WP_REST_Response( array( 'error' => 'Unauthorized.' ), 401 );
			}

			return new WP_REST_Response( array(
				'token'      => get_option( 'web_vault_token' ),
				'ssl_active' => web_vault_is_ssl_active(),
			), 200 );
		},
		'permission_callback' => '__return_true',
	) );

} );

// ===========================================================
// Auto-Login Handler
// ===========================================================

add_action( 'init', function () {

	if ( ! isset( $_GET['wv_autologin'], $_GET['token'] ) ) {
		return;
	}

	$username     = sanitize_user( wp_unslash( $_GET['wv_autologin'] ) );
	$token        = sanitize_text_field( wp_unslash( $_GET['token'] ) );
	$stored_token = get_option( 'web_vault_token' );

	if ( ! hash_equals( $stored_token, $token ) ) {
		wp_die( 'Web Vault: Invalid auto-login token.', 'Access Denied', array( 'response' => 403 ) );
	}

	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		wp_die( 'Web Vault: User not found.', 'Not Found', array( 'response' => 404 ) );
	}

	$roles        = (array) ( new WP_User( $user->ID ) )->roles;
	$is_admin     = in_array( 'administrator', $roles, true );
	$allowed_ids  = (array) get_option( 'web_vault_allowed_users', array() );
	$is_assigned  = in_array( $user->ID, $allowed_ids, true );

	if ( ! $is_admin && ! $is_assigned ) {
		wp_die(
			'Web Vault: This user does not have auto-login permission. Assign them under Settings → Web Vault → Access Users.',
			'Access Denied',
			array( 'response' => 403 )
		);
	}

	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, true );

	wp_redirect( web_vault_safe_url( admin_url() ) );
	exit;

} );

// ===========================================================
// Activation / Deactivation
// ===========================================================

register_activation_hook( WEB_VAULT_FILE, function () {
	if ( ! get_option( 'web_vault_token' ) ) {
		update_option( 'web_vault_token', wp_generate_password( 32, false ) );
	}
} );

register_deactivation_hook( WEB_VAULT_FILE, function () {
	// Intentionally left blank — token is preserved across deactivations.
} );
