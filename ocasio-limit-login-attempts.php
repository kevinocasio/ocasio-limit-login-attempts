<?php
/**
 * Plugin Name: Ocasio Limit Login Attempts
 * Plugin URI:  https://kevinocasio.com/wordpress-plugins/ocasio-limit-login-attempts/
 * Description: Protects your site from automated brute-force attacks by limiting the number of failed login attempts from a single IP address.
 * Version:     1.0.0
 * Author:      Kevin Ocasio
 * Author URI:  https://kevinocasio.com
 * License:     GPL-2.0+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ocasio-limit-login-attempts
 */

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Helper: Smart Brand URL Resolver (Keeps links local on .local, points to live domain on production)
 */
function ocasio_lla_brand_url($path = '/wordpress-plugins/') {
	if (isset($_SERVER['HTTP_HOST']) && strpos($_SERVER['HTTP_HOST'], '.local') !== false) {
		return home_url($path);
	}
	return 'https://kevinocasio.com' . $path;
}

// -------------------------------------------------------------------------
// 1. CORE LOGIC: IP DETECTION, THROTTLING & LOCKOUTS
// -------------------------------------------------------------------------

/**
 * Get visitor IP, supporting Cloudflare and reverse proxies
 */
function ocasio_lla_get_ip() {
	$ip = '';
	if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
		$ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
	} else {
		$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
	}
	return sanitize_text_field(trim($ip));
}

/**
 * Check if IP is currently locked out
 */
function ocasio_lla_is_locked($ip) {
	$lockout_time = get_transient('ocasio_lla_lockout_' . $ip);
	if (!empty($lockout_time)) {
		return true;
	}
	// Backward-compatible check for legacy transient
	$legacy = get_transient('ko_lla_lockout_' . $ip);
	return !empty($legacy);
}

/**
 * Check if IP is whitelisted
 */
function ocasio_lla_is_whitelisted($ip) {
	$whitelist = get_option('ocasio_lla_whitelist');
	if ($whitelist === false) {
		$whitelist = get_option('ko_lla_whitelist', array());
	}
	return in_array($ip, (array) $whitelist, true);
}

/**
 * Check authentication and block locked IPs
 */
function ocasio_lla_login_check($user, $username, $password) {
	$enabled = get_option('ocasio_lla_enabled');
	if ($enabled === false) {
		$enabled = get_option('ko_lla_enabled', 1);
	}
	if ((int) $enabled !== 1) {
		return $user;
	}

	$ip = ocasio_lla_get_ip();

	if (ocasio_lla_is_whitelisted($ip)) {
		return $user;
	}

	if (ocasio_lla_is_locked($ip)) {
		$duration = get_option('ocasio_lla_duration');
		if ($duration === false) {
			$duration = get_option('ko_lla_duration', 20);
		}
		$minutes = (int) $duration;
		return new WP_Error(
			'too_many_retries',
			sprintf(
				/* translators: %d: lockout duration in minutes */
				__('<strong>Error</strong>: Too many failed login attempts. Please try again in %d minutes.', 'ocasio-limit-login-attempts'),
				$minutes
			)
		);
	}

	return $user;
}
add_filter('authenticate', 'ocasio_lla_login_check', 10, 3);

/**
 * Track failed login attempts and trigger lockout
 */
function ocasio_lla_login_failed($username) {
	$enabled = get_option('ocasio_lla_enabled');
	if ($enabled === false) {
		$enabled = get_option('ko_lla_enabled', 1);
	}
	if ((int) $enabled !== 1) {
		return;
	}

	$ip = ocasio_lla_get_ip();

	if (ocasio_lla_is_whitelisted($ip)) {
		return;
	}

	$attempts = (int) get_transient('ocasio_lla_attempts_' . $ip);
	if (!$attempts) {
		$attempts = (int) get_transient('ko_lla_attempts_' . $ip);
	}
	$attempts++;
	set_transient('ocasio_lla_attempts_' . $ip, $attempts, HOUR_IN_SECONDS);

	if ($attempts >= 3) {
		$duration = get_option('ocasio_lla_duration');
		if ($duration === false) {
			$duration = get_option('ko_lla_duration', 20);
		}
		$duration = (int) $duration;
		set_transient('ocasio_lla_lockout_' . $ip, time() + ($duration * 60), $duration * 60);
		delete_transient('ocasio_lla_attempts_' . $ip);
		delete_transient('ko_lla_attempts_' . $ip);

		// Increment total blocked attacks counter
		$total = get_option('ocasio_lla_total_lockouts');
		if ($total === false) {
			$total = get_option('ko_lla_total_lockouts', 0);
		}
		update_option('ocasio_lla_total_lockouts', (int) $total + 1);
	}
}
add_action('wp_login_failed', 'ocasio_lla_login_failed');

/**
 * Reset failed attempts on successful login
 */
function ocasio_lla_login_success($user_login, $user) {
	$ip = ocasio_lla_get_ip();
	delete_transient('ocasio_lla_attempts_' . $ip);
	delete_transient('ko_lla_attempts_' . $ip);
}
add_action('wp_login', 'ocasio_lla_login_success', 10, 2);

// -------------------------------------------------------------------------
// 2. ADMIN MENU, SETTINGS & ACTIONS
// -------------------------------------------------------------------------

/**
 * Register Admin Menu under Ocasio Plugins -> Limit Login Attempts (Position 65)
 */
function ocasio_lla_register_menu() {
	if (empty($GLOBALS['admin_page_hooks']['ocasio-plugins-main'])) {
		$icon_url = plugins_url('assets/favicon.svg', __FILE__);

		add_menu_page(
			'Ocasio Plugins',
			'Ocasio Plugins',
			'manage_options',
			'ocasio-plugins-main',
			'ocasio_plugins_suite_dashboard_html',
			$icon_url,
			65
		);

		add_submenu_page(
			'ocasio-plugins-main',
			'Ocasio Plugins',
			'Dashboard',
			'manage_options',
			'ocasio-plugins-main',
			'ocasio_plugins_suite_dashboard_html'
		);
	}

	add_submenu_page(
		'ocasio-plugins-main',
		'Ocasio Limit Login Attempts',
		'Limit Login Attempts',
		'manage_options',
		'ocasio-limit-login-attempts',
		'ocasio_lla_render_page'
	);
}
add_action('admin_menu', 'ocasio_lla_register_menu');

/**
 * Settings Link on Plugins Screen
 */
function ocasio_lla_action_links($links) {
	$settings_link = '<a href="' . esc_url(admin_url('admin.php?page=ocasio-limit-login-attempts')) . '">' . esc_html__('Settings', 'ocasio-limit-login-attempts') . '</a>';
	array_unshift($links, $settings_link);
	return $links;
}
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'ocasio_lla_action_links');

/**
 * Enqueue Admin Assets
 */
function ocasio_lla_admin_assets($hook) {
	wp_add_inline_style('common', '#adminmenu .toplevel_page_ocasio-plugins-main .wp-menu-image img { width:20px!important; height:20px!important; padding:5px 0 0 0!important; opacity:1!important; }');

	if (strpos($hook, 'ocasio-limit-login-attempts') !== false || strpos($hook, 'ocasio-plugins-main') !== false || $hook === 'toplevel_page_ocasio-plugins-main') {
		wp_enqueue_style('ocasio-lla-admin-css', plugins_url('assets/admin.css', __FILE__), array(), '1.0.0');
		wp_enqueue_script('ocasio-lla-admin-js', plugins_url('assets/admin.js', __FILE__), array('jquery'), '1.0.0', true);
		wp_localize_script('ocasio-lla-admin-js', 'ocasio_lla_vars', array(
			'ajaxurl'     => admin_url('admin-ajax.php'),
			'suite_nonce' => wp_create_nonce('ocasio_suite_toggle_nonce'),
		));
	}
}
add_action('admin_enqueue_scripts', 'ocasio_lla_admin_assets');

/**
 * Sanitize IP Whitelist
 */
function ocasio_lla_sanitize_whitelist($input) {
	if (is_array($input)) {
		return array_unique(array_filter(array_map('sanitize_text_field', $input)));
	}
	return array();
}

/**
 * Register Settings
 */
function ocasio_lla_init_settings() {
	register_setting('ocasio_lla_settings_group', 'ocasio_lla_enabled', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 1,
	));
	register_setting('ocasio_lla_settings_group', 'ocasio_lla_duration', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 20,
	));
	register_setting('ocasio_lla_settings_group', 'ocasio_lla_whitelist', array(
		'type'              => 'array',
		'sanitize_callback' => 'ocasio_lla_sanitize_whitelist',
		'default'           => array(),
	));
}
add_action('admin_init', 'ocasio_lla_init_settings');

/**
 * Activation: Set Defaults & Migrate
 */
function ocasio_lla_activate() {
	// Enabled setting
	if (get_option('ocasio_lla_enabled') === false) {
		$legacy = get_option('ko_lla_enabled');
		update_option('ocasio_lla_enabled', ($legacy !== false) ? (int) $legacy : 1);
	}
	// Duration setting
	if (get_option('ocasio_lla_duration') === false) {
		$legacy = get_option('ko_lla_duration');
		update_option('ocasio_lla_duration', ($legacy !== false) ? (int) $legacy : 20);
	}
	// Whitelist setting
	if (get_option('ocasio_lla_whitelist') === false) {
		$legacy = get_option('ko_lla_whitelist');
		update_option('ocasio_lla_whitelist', ($legacy !== false) ? $legacy : array());
	}
	// Total lockouts
	if (get_option('ocasio_lla_total_lockouts') === false) {
		$legacy = get_option('ko_lla_total_lockouts');
		update_option('ocasio_lla_total_lockouts', ($legacy !== false) ? (int) $legacy : 0);
	}
}
register_activation_hook(__FILE__, 'ocasio_lla_activate');

/**
 * Handle Whitelist, Unlock and Reset Actions
 */
function ocasio_lla_handle_actions() {
	if (!isset($_GET['page']) || $_GET['page'] !== 'ocasio-limit-login-attempts' || !current_user_can('manage_options')) {
		return;
	}

	// 1. Whitelist Current IP
	if (isset($_POST['ocasio_lla_whitelist_me']) && check_admin_referer('ocasio_lla_action', 'ocasio_lla_nonce')) {
		$ip        = ocasio_lla_get_ip();
		$whitelist = get_option('ocasio_lla_whitelist');
		if ($whitelist === false) {
			$whitelist = get_option('ko_lla_whitelist', array());
		}
		if (!in_array($ip, (array) $whitelist, true)) {
			$whitelist[] = $ip;
			update_option('ocasio_lla_whitelist', $whitelist);
		}
		wp_safe_redirect(admin_url('admin.php?page=ocasio-limit-login-attempts&status=whitelisted'));
		exit;
	}

	// 2. Remove IP from Whitelist
	if (isset($_GET['remove_whitelist']) && check_admin_referer('ocasio_lla_remove_' . $_GET['remove_whitelist'])) {
		$ip        = sanitize_text_field($_GET['remove_whitelist']);
		$whitelist = get_option('ocasio_lla_whitelist');
		if ($whitelist === false) {
			$whitelist = get_option('ko_lla_whitelist', array());
		}
		$key = array_search($ip, (array) $whitelist, true);
		if ($key !== false) {
			unset($whitelist[$key]);
			update_option('ocasio_lla_whitelist', array_values($whitelist));
		}
		wp_safe_redirect(admin_url('admin.php?page=ocasio-limit-login-attempts&status=removed'));
		exit;
	}

	// 3. Unlock Specific IP
	if (isset($_GET['unlock_ip']) && check_admin_referer('ocasio_lla_unlock_' . $_GET['unlock_ip'])) {
		$ip = sanitize_text_field($_GET['unlock_ip']);
		delete_transient('ocasio_lla_lockout_' . $ip);
		delete_transient('ocasio_lla_attempts_' . $ip);
		delete_transient('ko_lla_lockout_' . $ip);
		delete_transient('ko_lla_attempts_' . $ip);
		wp_safe_redirect(admin_url('admin.php?page=ocasio-limit-login-attempts&status=unlocked'));
		exit;
	}

	// 4. Reset Statistics Counter
	if (isset($_GET['reset_stats']) && check_admin_referer('ocasio_lla_reset_stats')) {
		update_option('ocasio_lla_total_lockouts', 0);
		update_option('ko_lla_total_lockouts', 0);
		wp_safe_redirect(admin_url('admin.php?page=ocasio-limit-login-attempts&status=reset'));
		exit;
	}
}
add_action('admin_init', 'ocasio_lla_handle_actions');

// -------------------------------------------------------------------------
// 3. DEDICATED SETTINGS PAGE (620px Centered Card)
// -------------------------------------------------------------------------

/**
 * Render Settings Screen
 */
function ocasio_lla_render_page() {
	$current_ip = ocasio_lla_get_ip();

	$is_enabled = get_option('ocasio_lla_enabled');
	if ($is_enabled === false) {
		$is_enabled = get_option('ko_lla_enabled', 1);
	}
	$is_enabled = (int) $is_enabled === 1;

	$duration = get_option('ocasio_lla_duration');
	if ($duration === false) {
		$duration = get_option('ko_lla_duration', 20);
	}
	$duration = (int) $duration;

	$whitelist = get_option('ocasio_lla_whitelist');
	if ($whitelist === false) {
		$whitelist = get_option('ko_lla_whitelist', array());
	}

	$total_lockouts = get_option('ocasio_lla_total_lockouts');
	if ($total_lockouts === false) {
		$total_lockouts = get_option('ko_lla_total_lockouts', 0);
	}
	$total_lockouts = (int) $total_lockouts;

	$author_url = ocasio_lla_brand_url('/');
	$hub_url    = ocasio_lla_brand_url('/wordpress-plugins/');
	?>
	<div class="wrap ko-plugin-wrap">
		<div class="ko-plugin-card" style="max-width:700px;">
			<!-- Header -->
			<div class="ko-plugin-header">
				<h1 class="ko-plugin-header-title">
					<span class="ko-logo-ocasio">OCASIO</span>
					<span class="ko-title-text">LIMIT LOGIN ATTEMPTS</span>
				</h1>
			</div>

			<!-- Body Stage -->
			<div class="ko-plugin-body">
				<p class="ko-plugin-intro">Protect your website against automated brute-force attacks by temporarily blocking IP addresses after 3 consecutive failed login attempts.</p>

				<form method="post" action="options.php">
					<?php settings_fields('ocasio_lla_settings_group'); ?>

					<div class="ko-setting-box">
						<!-- Row 1: Enable Protection -->
						<div class="ko-setting-row">
							<div class="ko-setting-info">
								<strong>Enable Protection</strong>
								<p>Immediately starts blocking malicious login attempts.</p>
							</div>
							<label class="ko-switch">
								<input type="hidden" name="ocasio_lla_enabled" value="0">
								<input type="checkbox" name="ocasio_lla_enabled" value="1" <?php checked($is_enabled, true); ?>>
								<span class="ko-slider"></span>
							</label>
						</div>

						<!-- Row 2: Lockout Duration -->
						<div class="ko-setting-row">
							<div class="ko-setting-info">
								<strong>Lockout Duration (Minutes)</strong>
								<p>How long an IP address stays blocked after 3 failed attempts.</p>
							</div>
							<div style="display:flex; align-items:center; gap:8px;">
								<input type="number" name="ocasio_lla_duration" value="<?php echo esc_attr($duration); ?>" min="1" max="1440" style="width:80px; padding:6px 10px; border-radius:6px; border:1px solid #cbd5e1; font-weight:600; text-align:center;">
								<span style="font-size:13px; color:#64748b; font-weight:500;">mins</span>
							</div>
						</div>
					</div>

					<div class="ko-submit-wrap">
						<?php
						$is_saved  = (isset($_GET['settings-updated']) && $_GET['settings-updated'] === 'true');
						$btn_text  = $is_saved ? 'Settings Saved!' : 'Save Settings';
						$btn_class = 'ko-btn-submit' . ($is_saved ? ' ko-btn-saved' : '');
						?>
						<button type="submit" name="submit" id="ko-save-btn" class="<?php echo esc_attr($btn_class); ?>">
							<?php echo esc_html($btn_text); ?>
						</button>
					</div>
				</form>

				<!-- Divider -->
				<div style="border-top:1px solid #e2e8f0; margin: 26px 0 20px 0;"></div>

				<!-- Stats & Management Header -->
				<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
					<h3 style="margin:0; font-size:14.5px; font-weight:700; color:#0f172a;">Security & IP Logs</h3>
					<div style="display:flex; align-items:center; gap:8px;">
						<span style="font-size:11.5px; font-weight:600; color:#64748b; text-transform:uppercase; letter-spacing:0.5px;">
							Attacks Blocked: <strong style="color:#0f172a;"><?php echo number_format($total_lockouts); ?></strong>
						</span>
						<a href="<?php echo wp_nonce_url(admin_url('admin.php?page=ocasio-limit-login-attempts&reset_stats=1'), 'ocasio_lla_reset_stats'); ?>"
							title="Reset Statistics Counter"
							style="color:#64748b; text-decoration:none; display:inline-flex; align-items:center; transition:color 0.15s ease;"
							onmouseover="this.style.color='#e11d48'" onmouseout="this.style.color='#64748b'">
							<span class="dashicons dashicons-update" style="font-size:14px; width:14px; height:14px;"></span>
						</a>
					</div>
				</div>

				<!-- 2-Column Grid for Whitelist and Locked IPs -->
				<div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
					<!-- Column 1: IP Whitelist -->
					<div style="background:#f8fafc; padding:18px 20px; border-radius:8px; border:1px solid #e2e8f0; display:flex; flex-direction:column;">
						<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
							<h4 style="margin:0; font-size:13.5px; font-weight:700; color:#0f172a;">IP Whitelist</h4>
							<form method="post" action="" style="margin:0;">
								<?php wp_nonce_field('ocasio_lla_action', 'ocasio_lla_nonce'); ?>
								<button type="submit" name="ocasio_lla_whitelist_me" style="background:#ffffff; color:#0f172a; border:1px solid #cbd5e1; padding:4px 10px; border-radius:6px; font-size:11.5px; font-weight:600; cursor:pointer; line-height:1.2; transition:all 0.15s ease;" onmouseover="this.style.borderColor='#94a3b8'; this.style.background='#f1f5f9';" onmouseout="this.style.borderColor='#cbd5e1'; this.style.background='#ffffff';">
									+ Whitelist My IP
								</button>
							</form>
						</div>
						<p style="margin:0 0 12px 0; font-size:12px; color:#64748b;">Never locked out.</p>

						<ul style="margin:0; padding:0; list-style:none; flex-grow:1;">
							<?php if (empty($whitelist)): ?>
								<li style="color:#94a3b8; font-size:12px; padding:6px 0;">0 whitelisted IPs.</li>
							<?php else: ?>
								<?php foreach ($whitelist as $ip): ?>
									<li style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-top:1px solid #e2e8f0;">
										<code style="background:none; padding:0; font-weight:600; color:#0f172a; font-size:12px;"><?php echo esc_html($ip); ?></code>
										<a href="<?php echo wp_nonce_url(admin_url('admin.php?page=ocasio-limit-login-attempts&remove_whitelist=' . urlencode($ip)), 'ocasio_lla_remove_' . $ip); ?>" style="color:#e11d48; font-size:11.5px; text-decoration:none; font-weight:600;">Remove</a>
									</li>
								<?php endforeach; ?>
							<?php endif; ?>
						</ul>
					</div>

					<!-- Column 2: Currently Locked IPs -->
					<div style="background:#f8fafc; padding:18px 20px; border-radius:8px; border:1px solid #e2e8f0; display:flex; flex-direction:column;">
						<h4 style="margin:0 0 6px 0; font-size:13.5px; font-weight:700; color:#0f172a;">Locked IPs</h4>
						<p style="margin:0 0 12px 0; font-size:12px; color:#64748b;">Blocked after 3 failed tries.</p>

						<ul style="margin:0; padding:0; list-style:none; flex-grow:1;">
							<?php
							global $wpdb;
							$locked_ips = $wpdb->get_results("SELECT option_name, option_value FROM $wpdb->options WHERE option_name LIKE '_transient_ocasio_lla_lockout_%' OR option_name LIKE '_transient_ko_lla_lockout_%'");

							if (empty($locked_ips)): ?>
								<li style="color:#94a3b8; font-size:12px; padding:6px 0;">0 currently locked IPs.</li>
							<?php else: ?>
								<?php foreach ($locked_ips as $locked):
									$ip = str_replace(array('_transient_ocasio_lla_lockout_', '_transient_ko_lla_lockout_'), '', $locked->option_name);
									$expiry    = (int) $locked->option_value;
									$remaining = round(($expiry - time()) / 60);
									if ($remaining <= 0) {
										continue;
									}
									?>
									<li style="display:flex; justify-content:space-between; align-items:center; padding:7px 0; border-top:1px solid #e2e8f0;">
										<div>
											<code style="background:none; padding:0; font-weight:600; color:#0f172a; font-size:12px;"><?php echo esc_html($ip); ?></code>
											<span style="display:block; font-size:11px; color:#64748b;"><?php echo esc_html($remaining); ?>m left</span>
										</div>
										<a href="<?php echo wp_nonce_url(admin_url('admin.php?page=ocasio-limit-login-attempts&unlock_ip=' . urlencode($ip)), 'ocasio_lla_unlock_' . $ip); ?>" style="background:#ffffff; color:#0f172a; border:1px solid #cbd5e1; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; text-decoration:none; display:inline-block; line-height:1.2; transition:all 0.15s ease;" onmouseover="this.style.borderColor='#94a3b8'; this.style.background='#f1f5f9';" onmouseout="this.style.borderColor='#cbd5e1'; this.style.background='#ffffff';">Unlock</a>
									</li>
								<?php endforeach; ?>
							<?php endif; ?>
						</ul>
					</div>
				</div>
			</div>

			<!-- Card Footer -->
			<div class="ko-plugin-footer">
				<p><a href="<?php echo esc_url($author_url); ?>" target="_blank" rel="noopener noreferrer">Kevin Ocasio</a> built this and other <a href="<?php echo esc_url($hub_url); ?>" target="_blank" rel="noopener noreferrer">WordPress plugins</a>.</p>
			</div>
		</div>
	</div>
	<?php
}

// -------------------------------------------------------------------------
// 4. MASTER OCASIO PLUGINS SUITE DASHBOARD CALLBACK (17-PLUGIN GRID)
// -------------------------------------------------------------------------

if (!function_exists('ocasio_plugins_suite_dashboard_html')) {
	function ocasio_plugins_suite_dashboard_html() {
		$all_plugins = array(
			'ocasio-admin-bar-hider' => array(
				'title'         => 'Admin Bar Hider',
				'desc'          => 'Hides the front-end WordPress admin bar for all users with a single toggle.',
				'file'          => 'ocasio-admin-bar-hider/ocasio-admin-bar-hider.php',
				'fallback_file' => 'ko-admin-bar-hider/ko-admin-bar-hider.php',
				'opt_toggle'    => 'ocasio_abh_enabled',
				'fallback_opt'  => 'ko_abh_enabled',
				'has_options'   => false,
			),
			'ocasio-admin-username-changer' => array(
				'title'         => 'Admin Username Changer',
				'desc'          => 'Safely changes the primary administrator username directly without touching phpMyAdmin.',
				'file'          => 'ocasio-admin-username-changer/ocasio-admin-username-changer.php',
				'fallback_file' => 'ko-admin-username-changer/ko-admin-username-changer.php',
				'fallback_slug' => 'ko-admin-username-changer',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
			'ocasio-auto-copyright-year' => array(
				'title'         => 'Auto Copyright Year',
				'desc'          => 'Displays the current year, symbol, or translated text via simple shortcodes.',
				'file'          => 'ocasio-auto-copyright-year/ocasio-auto-copyright-year.php',
				'fallback_file' => 'ko-auto-copyright-year/ko-auto-copyright-year.php',
				'fallback_slug' => 'ko-auto-copyright-year',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
			'ocasio-clean-image-filenames' => array(
				'title'         => 'Clean Image Filenames',
				'desc'          => 'Sanitizes uploaded media filenames into clean, lowercase, URL-friendly slugs.',
				'file'          => 'ocasio-clean-image-filenames/ocasio-clean-image-filenames.php',
				'fallback_file' => 'ko-clean-image-filenames/ko-clean-image-filenames.php',
				'opt_toggle'    => 'ocasio_cif_enabled',
				'fallback_opt'  => 'ko_cif_enabled',
				'has_options'   => false,
			),
			'ocasio-comment-link-remover' => array(
				'title'         => 'Comment Link Remover',
				'desc'          => 'Strips hyperlinked website URLs from author comments to eliminate backlink spam.',
				'file'          => 'ocasio-comment-link-remover/ocasio-comment-link-remover.php',
				'fallback_file' => 'ko-comment-link-remover/ko-comment-link-remover.php',
				'opt_toggle'    => 'ocasio_clr_enabled',
				'fallback_opt'  => 'ko_clr_enabled',
				'has_options'   => false,
			),
			'ocasio-disable-comments-globally' => array(
				'title'         => 'Disable Comments Globally',
				'desc'          => 'Closes comments and trackbacks across the entire site, posts, and media.',
				'file'          => 'ocasio-disable-comments-globally/ocasio-disable-comments-globally.php',
				'fallback_file' => 'ko-disable-comments-globally/ko-disable-comments-globally.php',
				'opt_toggle'    => 'ocasio_dcg_enabled',
				'fallback_opt'  => 'ko_dcg_enabled',
				'has_options'   => false,
			),
			'ocasio-disable-emojis' => array(
				'title'         => 'Disable Emojis',
				'desc'          => 'Removes WordPress core emoji scripts, styles, and DNS prefetch requests to boost page speed.',
				'file'          => 'ocasio-disable-emojis/ocasio-disable-emojis.php',
				'fallback_file' => 'ko-disable-emojis/ko-disable-emojis.php',
				'opt_toggle'    => 'ocasio_de_enabled',
				'fallback_opt'  => 'ko_de_enabled',
				'has_options'   => false,
			),
			'ocasio-disable-gutenberg' => array(
				'title'         => 'Disable Gutenberg',
				'desc'          => 'Restores the Classic Editor and removes block library CSS for a cleaner authoring workflow.',
				'file'          => 'ocasio-disable-gutenberg/ocasio-disable-gutenberg.php',
				'fallback_file' => 'ko-disable-gutenberg/ko-disable-gutenberg.php',
				'opt_toggle'    => 'ocasio_dg_enabled',
				'fallback_opt'  => 'ko_dg_enabled',
				'has_options'   => false,
			),
			'ocasio-disable-xml-rpc' => array(
				'title'         => 'Disable XML-RPC',
				'desc'          => 'Blocks XML-RPC API access to protect your site against brute-force attacks.',
				'file'          => 'ocasio-disable-xml-rpc/ocasio-disable-xml-rpc.php',
				'fallback_file' => 'ko-disable-xml-rpc/ko-disable-xml-rpc.php',
				'opt_toggle'    => 'ocasio_dxml_enabled',
				'fallback_opt'  => 'ko_dxml_enabled',
				'has_options'   => false,
			),
			'ocasio-duplicate-post-button' => array(
				'title'         => 'Duplicate Post Button',
				'desc'          => 'Adds a one-click Clone action to duplicate any post or page into a new draft.',
				'file'          => 'ocasio-duplicate-post-button/ocasio-duplicate-post-button.php',
				'fallback_file' => 'ko-duplicate-post-button/ko-duplicate-post-button.php',
				'fallback_slug' => 'ko-duplicate-post-button',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
			'ocasio-estimated-reading-time' => array(
				'title'         => 'Estimated Reading Time',
				'desc'          => 'Calculates and displays article read time above post content automatically.',
				'file'          => 'ocasio-estimated-reading-time/ocasio-estimated-reading-time.php',
				'fallback_file' => 'ko-estimated-reading-time/ko-estimated-reading-time.php',
				'opt_toggle'    => 'ocasio_ert_enabled',
				'fallback_opt'  => 'ko_ert_enabled',
				'has_options'   => false,
			),
			'ocasio-external-links-new-tab' => array(
				'title'         => 'External Links New Tab',
				'desc'          => 'Forces external links to open in a new tab with target="_blank" and rel="noopener".',
				'file'          => 'ocasio-external-links-new-tab/ocasio-external-links-new-tab.php',
				'fallback_file' => 'ko-external-links-new-tab/ko-external-links-new-tab.php',
				'opt_toggle'    => 'ocasio_elnt_enabled',
				'fallback_opt'  => 'ko_elnt_enabled',
				'has_options'   => false,
			),
			'ocasio-hide-version' => array(
				'title'         => 'Hide Version',
				'desc'          => 'Removes WordPress version generator tags and script query strings for security.',
				'file'          => 'ocasio-hide-version/ocasio-hide-version.php',
				'fallback_file' => 'ko-hide-version/ko-hide-version.php',
				'opt_toggle'    => 'ocasio_hv_enabled',
				'fallback_opt'  => 'ko_hv_enabled',
				'has_options'   => false,
			),
			'ocasio-limit-login-attempts' => array(
				'title'         => 'Limit Login Attempts',
				'desc'          => 'Throttles repeated failed login attempts by IP address to block brute-force attacks.',
				'file'          => 'ocasio-limit-login-attempts/ocasio-limit-login-attempts.php',
				'fallback_file' => 'ko-limit-login-attempts/ko-limit-login-attempts.php',
				'fallback_slug' => 'ko-limit-login-attempts',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
			'ocasio-show-current-template' => array(
				'title'         => 'Show Current Template',
				'desc'          => 'Displays active template hierarchy filename in the admin bar for developers.',
				'file'          => 'ocasio-show-current-template/ocasio-show-current-template.php',
				'fallback_file' => 'ko-show-current-template/ko-show-current-template.php',
				'opt_toggle'    => 'ocasio_sct_enabled',
				'fallback_opt'  => 'ko_sct_enabled',
				'has_options'   => false,
			),
			'ocasio-301-redirect-manager' => array(
				'title'         => '301 Redirect Manager',
				'desc'          => 'Manages 301 permanent redirects and fixes broken links cleanly inside WordPress.',
				'file'          => 'ocasio-301-redirect-manager/ocasio-301-redirect-manager.php',
				'fallback_file' => 'ko-simple-301-redirects/ko-simple-301-redirects.php',
				'fallback_slug' => 'ko-simple-301-redirects',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
			'ocasio-simple-maintenance-mode' => array(
				'title'         => 'Simple Maintenance Mode',
				'desc'          => 'Displays a clean splash page to visitors while admins work on the site.',
				'file'          => 'ocasio-simple-maintenance-mode/ocasio-simple-maintenance-mode.php',
				'fallback_file' => 'ko-simple-maintenance-mode/ko-simple-maintenance-mode.php',
				'fallback_slug' => 'ko-simple-maintenance-mode',
				'opt_toggle'    => null,
				'has_options'   => true,
			),
		);

		if (!function_exists('is_plugin_active')) {
			include_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed_plugins = get_plugins();
		$active_count      = 0;

		foreach ($all_plugins as $slug => $data) {
			$active_file = $data['file'];
			if (!is_plugin_active($active_file) && !empty($data['fallback_file']) && is_plugin_active($data['fallback_file'])) {
				$active_file = $data['fallback_file'];
			}
			if (is_plugin_active($active_file)) {
				$active_count++;
			}
		}

		$author_url = 'https://kevinocasio.com/';
		$hub_url    = 'https://kevinocasio.com/wordpress-plugins/';
		?>
		<div class="wrap ko-dash-wrap">
			<div class="ko-dash-hero">
				<div class="ko-dash-hero-left">
					<h1>
						<a href="<?php echo esc_url($hub_url); ?>" target="_blank" rel="noopener noreferrer" class="ko-dash-logo">
							<span class="ko-logo-ocasio">OCASIO</span>
							<span class="ko-logo-suite">PLUGINS SUITE</span>
						</a>
					</h1>
				</div>
				<div class="ko-dash-hero-right">
					<span class="ko-dash-count-pill"><?php echo esc_html($active_count); ?> of 17 Active</span>
				</div>
			</div>

			<div class="ko-dash-grid">
				<?php
				foreach ($all_plugins as $slug => $data):
					$active_file = $data['file'];
					if (!is_plugin_active($active_file) && !empty($data['fallback_file']) && is_plugin_active($data['fallback_file'])) {
						$active_file = $data['fallback_file'];
					}
					$is_installed = isset($installed_plugins[$active_file]) || isset($installed_plugins[$data['file']]) || (!empty($data['fallback_file']) && isset($installed_plugins[$data['fallback_file']]));
					$is_active    = is_plugin_active($active_file);
					$is_fallback  = ($active_file !== $data['file'] && !empty($data['fallback_file']));
					$page_slug    = ($is_fallback && !empty($data['fallback_slug'])) ? $data['fallback_slug'] : $slug;
					$settings_url = admin_url('admin.php?page=' . $page_slug);
					$activate_url = wp_nonce_url(admin_url('plugins.php?action=activate&plugin=' . urlencode($data['file'])), 'activate-plugin_' . $data['file']);
					?>
					<div class="ko-dash-card">
						<div class="ko-dash-card-header">
							<h3 class="ko-dash-card-title"><?php echo esc_html($data['title']); ?></h3>
							<?php if ($is_active): ?>
								<?php if (!empty($data['opt_toggle'])):
									$opt_key      = (!empty($data['fallback_opt']) && get_option($data['opt_toggle'], null) === null) ? $data['fallback_opt'] : $data['opt_toggle'];
									$toggle_state = (int) get_option($opt_key, 1);
									$b_class      = ($toggle_state === 1) ? 'badge-active' : 'badge-paused';
									$b_label      = ($toggle_state === 1) ? 'Active' : 'Paused';
									?>
									<span class="ko-dash-badge <?php echo esc_attr($b_class); ?>" id="badge-<?php echo esc_attr($slug); ?>"><?php echo esc_html($b_label); ?></span>
								<?php else: ?>
									<span class="ko-dash-badge badge-active">Active</span>
								<?php endif; ?>
							<?php elseif ($is_installed): ?>
								<span class="ko-dash-badge badge-inactive">Inactive</span>
							<?php else: ?>
								<span class="ko-dash-badge badge-available">Available</span>
							<?php endif; ?>
						</div>

						<p class="ko-dash-card-desc"><?php echo esc_html($data['desc']); ?></p>

						<div class="ko-dash-card-footer">
							<?php if ($is_active): ?>
								<?php if ($data['has_options']): ?>
									<a href="<?php echo esc_url($settings_url); ?>" class="ko-dash-btn-primary">Manage Settings</a>
								<?php elseif (!empty($data['opt_toggle'])):
									$opt_key    = (!empty($data['fallback_opt']) && get_option($data['opt_toggle'], null) === null) ? $data['fallback_opt'] : $data['opt_toggle'];
									$toggle_val = (int) get_option($opt_key, 1);
									?>
									<div class="ko-dash-card-toggle-row">
										<span class="ko-dash-toggle-label">Active on Site</span>
										<div class="ko-dash-toggle-action">
											<span class="ko-dash-saved-pill" id="saved-<?php echo esc_attr($slug); ?>" style="display:none;">Saved</span>
											<label class="ko-switch">
												<input type="checkbox"
													class="ko-ajax-toggle"
													data-slug="<?php echo esc_attr($slug); ?>"
													data-option="<?php echo esc_attr($opt_key); ?>"
													value="1" <?php checked($toggle_val, 1); ?>>
												<span class="ko-slider"></span>
											</label>
										</div>
									</div>
								<?php else: ?>
									<span class="ko-dash-badge badge-active">Active</span>
								<?php endif; ?>
							<?php elseif ($is_installed): ?>
								<a href="<?php echo esc_url($activate_url); ?>" class="ko-dash-btn-activate">Activate</a>
							<?php else: ?>
								<a href="<?php echo esc_url($hub_url); ?>" target="_blank" rel="noopener noreferrer" class="ko-dash-btn-outline">Learn More</a>
							<?php endif; ?>
						</div>
					</div>
				<?php endforeach; ?>
			</div>

			<div class="ko-dash-global-footer">
				<p>Built with pride by <a href="<?php echo esc_url($author_url); ?>" target="_blank" rel="noopener noreferrer">Kevin Ocasio</a>. Explore all <a href="<?php echo esc_url($hub_url); ?>" target="_blank" rel="noopener noreferrer">17 lightweight WordPress tools</a>.</p>
			</div>
		</div>
		<?php
	}
}

// -------------------------------------------------------------------------
// 5. MASTER AJAX HANDLER FOR DASHBOARD GRID IN-CARD TOGGLES
// -------------------------------------------------------------------------

if (!function_exists('ocasio_suite_save_toggle_ajax_callback')) {
	function ocasio_suite_save_toggle_ajax_callback() {
		check_ajax_referer('ocasio_suite_toggle_nonce', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error('Unauthorized', 403);
		}

		$option_name  = isset($_POST['option_name']) ? sanitize_key($_POST['option_name']) : '';
		$option_value = isset($_POST['option_value']) ? absint($_POST['option_value']) : 0;

		$allowed_options = array(
			'ko_abh_enabled',
			'ko_cif_enabled',
			'ko_clr_enabled',
			'ko_dcg_enabled',
			'ko_de_enabled',
			'ko_dg_enabled',
			'ko_dxml_enabled',
			'ko_elnt_enabled',
			'ko_ert_enabled',
			'ko_hv_enabled',
			'ko_sct_enabled',
			'ocasio_abh_enabled',
			'ocasio_cif_enabled',
			'ocasio_clr_enabled',
			'ocasio_dcg_enabled',
			'ocasio_de_enabled',
			'ocasio_dg_enabled',
			'ocasio_dxml_enabled',
			'ocasio_elnt_enabled',
			'ocasio_ert_enabled',
			'ocasio_hv_enabled',
			'ocasio_sct_enabled',
		);

		if (in_array($option_name, $allowed_options, true)) {
			update_option($option_name, $option_value);
			wp_send_json_success();
		}

		wp_send_json_error('Invalid option key');
	}
	add_action('wp_ajax_ocasio_suite_save_toggle', 'ocasio_suite_save_toggle_ajax_callback');
}
