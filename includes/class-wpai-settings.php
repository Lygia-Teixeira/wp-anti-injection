<?php
/**
 * Configurações (option `wpai_settings`, autoload desligado).
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Settings {

	const OPTION = 'wpai_settings';

	/**
	 * Valores padrão.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'threshold'           => 'high', // Severidade mínima para remover no modo limpar.
			'disabled_signatures' => array(),
			'allow_options'       => array(), // option_name exatos ou com curinga *.
			'allow_post_ids'      => array(),
			'trusted_hosts'       => array(), // Hosts de <script src> legítimos (subdomínios incluídos).
			'batch_size'          => 200,
		);
	}

	/**
	 * Configurações atuais mescladas com o padrão.
	 *
	 * @return array
	 */
	public static function get() {
		$saved = get_option( self::OPTION, array() );
		return self::sanitize( is_array( $saved ) ? $saved : array() );
	}

	/**
	 * Saneia entrada (formulário ou option salva). Tudo é whitelist.
	 *
	 * @param mixed $in Entrada bruta (já sem slashes).
	 * @return array
	 */
	public static function sanitize( $in ) {
		$out = self::defaults();
		if ( ! is_array( $in ) ) {
			return $out;
		}

		if ( isset( $in['threshold'] ) && WPAI_Signatures::is_severity( $in['threshold'] ) ) {
			$out['threshold'] = $in['threshold'];
		}

		if ( isset( $in['disabled_signatures'] ) && is_array( $in['disabled_signatures'] ) ) {
			$known                      = array_keys( WPAI_Signatures::all() );
			$out['disabled_signatures'] = array_values( array_intersect( $known, array_map( 'strval', $in['disabled_signatures'] ) ) );
		}

		if ( isset( $in['allow_options'] ) ) {
			$out['allow_options'] = array_values(
				array_unique(
					array_filter(
						self::split( $in['allow_options'] ),
						function ( $v ) {
							return (bool) preg_match( '/^[A-Za-z0-9_\-.:*]{1,191}$/', $v );
						}
					)
				)
			);
		}

		if ( isset( $in['allow_post_ids'] ) ) {
			$ids = array();
			foreach ( self::split( $in['allow_post_ids'] ) as $v ) {
				if ( ctype_digit( $v ) && (int) $v > 0 ) {
					$ids[] = (int) $v;
				}
			}
			$out['allow_post_ids'] = array_values( array_unique( $ids ) );
		}

		if ( isset( $in['trusted_hosts'] ) ) {
			$hosts = array();
			foreach ( self::split( $in['trusted_hosts'] ) as $v ) {
				$h = self::normalize_host( $v );
				if ( '' !== $h ) {
					$hosts[] = $h;
				}
			}
			$out['trusted_hosts'] = array_values( array_unique( $hosts ) );
		}

		if ( isset( $in['batch_size'] ) ) {
			$out['batch_size'] = max( 10, min( 2000, (int) $in['batch_size'] ) );
		}

		return $out;
	}

	/**
	 * Aceita lista (array) ou texto separado por vírgula/quebra de linha.
	 *
	 * @param mixed $v Valor.
	 * @return string[]
	 */
	public static function split( $v ) {
		if ( is_array( $v ) ) {
			$v = implode( "\n", array_map( 'strval', $v ) );
		}
		if ( ! is_string( $v ) ) {
			return array();
		}
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\s,]+/', $v ) ), 'strlen' ) );
	}

	/**
	 * Reduz "https://cdn.exemplo.test/x.js" a "cdn.exemplo.test".
	 *
	 * @param string $v Host ou URL.
	 * @return string Host em minúsculas ou '' se inválido.
	 */
	public static function normalize_host( $v ) {
		$v = strtolower( trim( (string) $v ) );
		$v = preg_replace( '#^[a-z][a-z0-9+.\-]*://#', '', $v );
		$v = ltrim( $v, '/' );
		$v = preg_replace( '#[/?\#:].*$#', '', $v );
		return preg_match( '/^[a-z0-9](?:[a-z0-9\-.]{0,251}[a-z0-9])?$/', $v ) ? $v : '';
	}

	/**
	 * Casa um nome com uma lista de padrões (curinga * apenas).
	 *
	 * @param string   $name     Nome (ex.: option_name).
	 * @param string[] $patterns Padrões.
	 * @return bool
	 */
	public static function name_matches( $name, array $patterns ) {
		foreach ( $patterns as $p ) {
			$re = '/^' . str_replace( '\*', '.*', preg_quote( $p, '/' ) ) . '$/';
			if ( preg_match( $re, $name ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Host confiável? (igual ou subdomínio de um host da lista).
	 *
	 * @param string   $host    Host a verificar.
	 * @param string[] $trusted Lista.
	 * @return bool
	 */
	public static function host_trusted( $host, array $trusted ) {
		$host = strtolower( $host );
		foreach ( $trusted as $t ) {
			$t = strtolower( $t );
			if ( '' === $t ) {
				continue;
			}
			if ( $host === $t ) {
				return true;
			}
			$suffix = '.' . $t;
			if ( strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix ) {
				return true;
			}
		}
		return false;
	}
}
