<?php
/**
 * Assinaturas de detecção.
 *
 * Classe pura (sem dependência do WordPress, exceto o filtro opcional),
 * para poder ser testada isoladamente em tests/run.php.
 *
 * Estrutura de uma assinatura:
 *   label    string   Descrição legível.
 *   scope    string   'script' (avaliada em cada elemento <script>),
 *                     'iframe' (avaliada em cada elemento <iframe>) ou
 *                     'any'    (avaliada no texto restante; sempre só reporta).
 *   severity string   low | medium | high | critical.
 *   type     string   'regex' (padrão) ou 'external_src' (lógica de host).
 *   pattern  string   Regex PCRE (quando type = regex).
 *   all      string[] Alternativa a pattern: TODAS as regex precisam casar.
 *   needles  string[] Literais usados no pré-filtro SQL (LIKE). Só desempenho:
 *                     a decisão final é sempre da regex em PHP.
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Signatures {

	const SEVERITY = array(
		'low'      => 1,
		'medium'   => 2,
		'high'     => 3,
		'critical' => 4,
	);

	const SCOPES = array( 'script', 'iframe', 'any' );

	/**
	 * Assinaturas embutidas.
	 *
	 * @return array<string, array>
	 */
	public static function defaults() {
		return array(
			'script_external_src'      => array(
				'label'    => '<script> carregando JS de host externo não confiável',
				'scope'    => 'script',
				'type'     => 'external_src',
				'severity' => 'high',
				'needles'  => array( '<script' ),
			),
			'script_eval'              => array(
				'label'    => 'eval( dentro de <script>',
				'scope'    => 'script',
				'pattern'  => '/\beval\s*\(/i',
				'severity' => 'high',
				'needles'  => array( '<script' ),
			),
			'script_location_redirect' => array(
				'label'    => 'Redirecionamento via document/window.location',
				'scope'    => 'script',
				'pattern'  => '/\b(?:document|window|top|self|parent)\s*\.\s*location(?:\s*\.\s*href)?\s*=(?!=)|\blocation\s*\.\s*(?:replace|assign)\s*\(/i',
				'severity' => 'high',
				'needles'  => array( '<script' ),
			),
			'script_clickfix'          => array(
				'label'    => 'ClickFix / falso captcha: copia comando para a área de transferência',
				'scope'    => 'script',
				'all'      => array(
					'/navigator\s*\.\s*clipboard\s*\.\s*writeText/i',
					'/\b(?:powershell|pwsh|mshta|rundll32|cmd(?:\.exe)?\s+\/c|curl\s[^\n]*\|\s*(?:ba)?sh)\b/i',
				),
				'severity' => 'critical',
				'needles'  => array( '<script' ),
			),
			'script_fromcharcode'      => array(
				'label'    => 'String.fromCharCode (ofuscação comum)',
				'scope'    => 'script',
				'pattern'  => '/\bString\s*\.\s*fromCharCode\s*\(/i',
				'severity' => 'medium',
				'needles'  => array( '<script' ),
			),
			'script_atob_unescape'     => array(
				'label'    => 'atob( / unescape( (decodificação em tempo de execução)',
				'scope'    => 'script',
				'pattern'  => '/\b(?:atob|unescape)\s*\(/i',
				'severity' => 'medium',
				'needles'  => array( '<script' ),
			),
			'script_hex_obfuscation'   => array(
				'label'    => 'Sequência longa de escapes \\xNN',
				'scope'    => 'script',
				'pattern'  => '/(?:\\\\x[0-9a-f]{2}){16,}/i',
				'severity' => 'medium',
				'needles'  => array( '<script' ),
			),
			'iframe_hidden'            => array(
				'label'    => '<iframe> oculto (0/1px, display:none, visibility:hidden, fora da tela)',
				'scope'    => 'iframe',
				'pattern'  => '/\b(?:width|height)\s*=\s*\\\\?["\']?0*[01](?:px)?(?:\\\\?["\']|[\s>\/])|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|\\\\?["\'])|(?:left|top)\s*:\s*-\d{3,}/i',
				'severity' => 'high',
				'needles'  => array( '<iframe' ),
			),
			'php_eval_payload'         => array(
				'label'    => 'eval(base64_decode/gzinflate/str_rot13(...)) no conteúdo',
				'scope'    => 'any',
				'pattern'  => '/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/i',
				'severity' => 'critical',
				'needles'  => array( 'eval' ),
			),
			'php_base64_decode'        => array(
				'label'    => 'base64_decode( no conteúdo',
				'scope'    => 'any',
				'pattern'  => '/\bbase64_decode\s*\(/i',
				'severity' => 'medium',
				'needles'  => array( 'base64_decode' ),
			),
			'meta_refresh'             => array(
				'label'    => '<meta http-equiv="refresh"> com URL (redirecionamento)',
				'scope'    => 'any',
				'pattern'  => '/<meta\b[^>]*http-equiv\s*=\s*\\\\?["\']?refresh[^>]*url\s*=/i',
				'severity' => 'high',
				'needles'  => array( 'http-equiv' ),
			),
			'fake_captcha_text'        => array(
				'label'    => 'Texto de falso captcha pedindo Win+R / Ctrl+V',
				'scope'    => 'any',
				'all'      => array(
					'/(?:captcha|human|humano|rob[oô]t?)/iu',
					'/\b(?:win(?:dows)?\s*(?:key\s*)?\+\s*r\b|ctrl\s*\+\s*v\b)/i',
				),
				'severity' => 'high',
				'needles'  => array( 'captcha', 'human', 'robô', 'robot' ),
			),
		);
	}

	/**
	 * Assinaturas embutidas + filtro `wpai_signatures`, já validadas.
	 *
	 * Assinaturas personalizadas entram SOMENTE por código (filtro), nunca
	 * por formulário: regex arbitrária vinda da interface é vetor de ReDoS.
	 *
	 * @return array<string, array>
	 */
	public static function all() {
		$sigs = self::defaults();
		if ( function_exists( 'apply_filters' ) ) {
			$sigs = apply_filters( 'wpai_signatures', $sigs );
		}
		$valid = self::validate( is_array( $sigs ) ? $sigs : array() );
		return $valid['valid'];
	}

	/**
	 * Remove as desativadas pelo administrador.
	 *
	 * @param array    $sigs     Assinaturas.
	 * @param string[] $disabled IDs desativados.
	 * @return array
	 */
	public static function enabled( array $sigs, array $disabled ) {
		return array_diff_key( $sigs, array_flip( $disabled ) );
	}

	/**
	 * Valida estrutura, severidade, escopo e compilação das regex.
	 *
	 * @param array $sigs Assinaturas candidatas.
	 * @return array{valid: array, errors: string[]}
	 */
	public static function validate( array $sigs ) {
		$valid  = array();
		$errors = array();

		foreach ( $sigs as $id => $sig ) {
			$id = (string) $id;
			if ( ! preg_match( '/^[a-z0-9_]{1,64}$/', $id ) ) {
				$errors[] = "id inválido: {$id}";
				continue;
			}
			if ( ! is_array( $sig ) || empty( $sig['label'] ) || ! is_string( $sig['label'] ) ) {
				$errors[] = "{$id}: label ausente";
				continue;
			}
			if ( ! isset( $sig['severity'] ) || ! self::is_severity( $sig['severity'] ) ) {
				$errors[] = "{$id}: severidade inválida";
				continue;
			}
			if ( ! isset( $sig['scope'] ) || ! in_array( $sig['scope'], self::SCOPES, true ) ) {
				$errors[] = "{$id}: escopo inválido";
				continue;
			}
			$type = isset( $sig['type'] ) ? $sig['type'] : 'regex';
			if ( 'external_src' === $type ) {
				$sig['scope'] = 'script';
			} elseif ( 'regex' === $type ) {
				$patterns = self::patterns( $sig );
				if ( empty( $patterns ) ) {
					$errors[] = "{$id}: sem pattern/all";
					continue;
				}
				foreach ( $patterns as $p ) {
					if ( ! is_string( $p ) || false === @preg_match( $p, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$errors[] = "{$id}: regex inválida";
						continue 2;
					}
				}
			} else {
				$errors[] = "{$id}: tipo desconhecido";
				continue;
			}
			$sig['type']    = $type;
			$sig['needles'] = isset( $sig['needles'] ) && is_array( $sig['needles'] )
				? array_values( array_filter( array_map( 'strval', $sig['needles'] ), 'strlen' ) )
				: array();
			$valid[ $id ] = $sig;
		}

		return array(
			'valid'  => $valid,
			'errors' => $errors,
		);
	}

	/**
	 * Lista de regex de uma assinatura.
	 *
	 * @param array $sig Assinatura.
	 * @return string[]
	 */
	public static function patterns( array $sig ) {
		if ( isset( $sig['all'] ) && is_array( $sig['all'] ) ) {
			return array_values( $sig['all'] );
		}
		return isset( $sig['pattern'] ) ? array( $sig['pattern'] ) : array();
	}

	/**
	 * Literais únicos para o pré-filtro SQL.
	 *
	 * @param array $sigs Assinaturas ativas.
	 * @return string[]
	 */
	public static function needles( array $sigs ) {
		$out = array();
		foreach ( $sigs as $sig ) {
			foreach ( $sig['needles'] as $n ) {
				$out[ strtolower( $n ) ] = $n;
			}
		}
		return array_values( $out );
	}

	/**
	 * Nível numérico de uma severidade.
	 *
	 * @param string $severity Nome.
	 * @return int
	 */
	public static function level( $severity ) {
		return self::is_severity( $severity ) ? self::SEVERITY[ $severity ] : self::SEVERITY['high'];
	}

	/**
	 * Nome de severidade válido?
	 *
	 * @param mixed $severity Valor.
	 * @return bool
	 */
	public static function is_severity( $severity ) {
		return is_string( $severity ) && array_key_exists( $severity, self::SEVERITY );
	}
}
