<?php
/**
 * Plugin Name:       WP Anti Injection
 * Description:       Detecta e limpa, com quarentena e rollback, injeções maliciosas gravadas no banco (scripts externos, redirecionamentos, iframes ocultos, ClickFix/falso captcha). Ciente de dados serializados.
 * Version:           2.0.0
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Lygia Teixeira
 * License:           GPL-2.0-or-later
 * Text Domain:       wp-anti-injection
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

define( 'WPAI_VERSION', '2.0.0' );
define( 'WPAI_DB_VERSION', '1' );
define( 'WPAI_DIR', plugin_dir_path( __FILE__ ) );

require_once WPAI_DIR . 'includes/class-wpai-signatures.php';
require_once WPAI_DIR . 'includes/class-wpai-settings.php';
require_once WPAI_DIR . 'includes/class-wpai-cleaner.php';
require_once WPAI_DIR . 'includes/class-wpai-store.php';
require_once WPAI_DIR . 'includes/class-wpai-scanner.php';

/**
 * Ponto único de montagem: configurações -> assinaturas -> limpador -> scanner.
 */
final class WPAI_Plugin {

	/**
	 * Executa uma varredura (detect) ou limpeza (clean).
	 *
	 * @param string[]      $targets  Alvos validados.
	 * @param string        $mode     detect|clean.
	 * @param callable|null $progress Callback de progresso.
	 * @return array{summary: array, items: array}
	 */
	public static function run( array $targets, $mode, $progress = null ) {
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$settings = WPAI_Settings::get();
		$sigs     = WPAI_Signatures::enabled( WPAI_Signatures::all(), $settings['disabled_signatures'] );
		$cleaner  = new WPAI_Cleaner(
			$sigs,
			array(
				'threshold'     => $settings['threshold'],
				'trusted_hosts' => $settings['trusted_hosts'],
				'site_host'     => (string) wp_parse_url( home_url(), PHP_URL_HOST ),
			)
		);
		$scanner  = new WPAI_Scanner( $cleaner, $settings, WPAI_Signatures::needles( $sigs ) );
		$run_id   = WPAI_Store::new_run_id();
		$result   = $scanner->run( $targets, $mode, $run_id, $progress );

		WPAI_Store::record_run( $result['summary'] );
		return $result;
	}
}

register_activation_hook( __FILE__, array( 'WPAI_Store', 'activate' ) );

add_action( 'plugins_loaded', array( 'WPAI_Store', 'maybe_upgrade' ) );

// Novo site em multisite com o plugin ativo na rede.
add_action(
	'wp_initialize_site',
	function ( $site ) {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
			switch_to_blog( (int) $site->blog_id );
			WPAI_Store::install();
			restore_current_blog();
		}
	},
	20
);

if ( is_admin() ) {
	require_once WPAI_DIR . 'includes/class-wpai-admin.php';
	( new WPAI_Admin() )->hooks();
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once WPAI_DIR . 'includes/class-wpai-cli.php';
	WP_CLI::add_command( 'anti-injection', 'WPAI_CLI' );
}
