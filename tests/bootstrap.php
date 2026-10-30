<?php
/**
 * Stubs mínimos para rodar as classes puras sem WordPress.
 *
 * @package WP_Anti_Injection
 */

define( 'ABSPATH', __DIR__ . '/' );

if ( ! function_exists( 'is_serialized' ) ) {
	/**
	 * Equivalente funcional ao is_serialized() do core (modo estrito).
	 *
	 * @param mixed $data Valor.
	 * @return bool
	 */
	function is_serialized( $data ) {
		if ( ! is_string( $data ) ) {
			return false;
		}
		$data = trim( $data );
		if ( 'N;' === $data ) {
			return true;
		}
		if ( strlen( $data ) < 4 || ':' !== $data[1] ) {
			return false;
		}
		$last = substr( $data, -1 );
		if ( ';' !== $last && '}' !== $last ) {
			return false;
		}
		$token = $data[0];
		switch ( $token ) {
			case 's':
				return '"' === substr( $data, -2, 1 ) && (bool) preg_match( '/^s:[0-9]+:"/', $data );
			case 'a':
			case 'O':
			case 'E':
				return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
			case 'b':
			case 'i':
			case 'd':
				return (bool) preg_match( "/^{$token}:[0-9.E+-]+;$/", $data );
		}
		return false;
	}
}

$root = dirname( __DIR__ );
require_once $root . '/includes/class-wpai-signatures.php';
require_once $root . '/includes/class-wpai-settings.php';
require_once $root . '/includes/class-wpai-cleaner.php';
