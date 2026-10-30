<?php
/**
 * Desinstalação: remove tabelas e opções do plugin em todos os sites.
 *
 * ATENÇÃO: a quarentena (valores originais) é apagada junto. Exporte-a
 * antes se ainda puder precisar de rollback:
 *   wp db export --tables=$(wp db prefix)wpai_quarantine quarentena.sql
 *
 * @package WP_Anti_Injection
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Limpa o site atual.
 */
function wpai_uninstall_current_site() {
	global $wpdb;
	foreach ( array( 'wpai_quarantine', 'wpai_log' ) as $suffix ) {
		$table = $wpdb->prefix . $suffix;
		$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
	}
	foreach ( array( 'wpai_settings', 'wpai_runs', 'wpai_db_version' ) as $option ) {
		delete_option( $option );
	}
}

if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $wpai_blog_id ) {
		switch_to_blog( $wpai_blog_id );
		wpai_uninstall_current_site();
		restore_current_blog();
	}
} else {
	wpai_uninstall_current_site();
}
