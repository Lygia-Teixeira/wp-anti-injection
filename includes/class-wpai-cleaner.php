<?php
/**
 * Análise e limpeza de UM valor do banco, ciente de serialização.
 *
 * Regras de ouro:
 *  1. Nunca aplicar regex direto num blob serializado: s:N:"..." guarda o
 *     tamanho em bytes, e qualquer remoção quebra o unserialize() (a opção
 *     inteira passa a ser lida como false). Em vez disso:
 *     unserialize -> percorre recursivamente -> limpa strings -> serialize.
 *  2. unserialize() com allowed_classes = [stdClass]: o conteúdo pode ter
 *     sido escrito por um atacante, e desserializar objetos arbitrários é
 *     injeção de objeto PHP (__wakeup/__destruct). Objetos de outras classes
 *     viram __PHP_Incomplete_Class e o valor é marcado como "bloqueado".
 *  3. Tudo ou nada por valor: se qualquer parte não puder ser limpa com
 *     segurança (serializado corrompido, objeto, referência, JSON, erro
 *     PCRE), nada é escrito; os achados são só reportados.
 *  4. Remover apenas o elemento malicioso inteiro (<script>...</script>,
 *     <iframe>...</iframe>) cuja severidade atinja o limiar. <script>
 *     legítimo (sem assinatura) permanece.
 *
 * Classe pura: depende apenas de is_serialized() (WordPress ou stub).
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Cleaner {

	const MAX_DEPTH   = 32;
	const EXCERPT_LEN = 160;

	const RE_SCRIPT = '#<script\b[^>]*>(?:.*?<\\\\?/script\s*>)?#is';
	const RE_IFRAME = '#<iframe\b[^>]*>(?:.*?<\\\\?/iframe\s*>)?#is';

	/** @var array */
	private $sigs_by_scope = array(
		'script' => array(),
		'iframe' => array(),
		'any'    => array(),
	);

	/** @var int */
	private $threshold;

	/** @var string[] */
	private $trusted_hosts;

	/** @var array */
	private $findings = array();

	/** @var string|null */
	private $blocked = null;

	/** @var int */
	private $changes = 0;

	/**
	 * @param array $signatures Assinaturas ativas (validadas).
	 * @param array $opts       threshold, trusted_hosts, site_host.
	 */
	public function __construct( array $signatures, array $opts = array() ) {
		foreach ( $signatures as $id => $sig ) {
			$sig['id'] = $id;
			$this->sigs_by_scope[ $sig['scope'] ][ $id ] = $sig;
		}
		$this->threshold = WPAI_Signatures::level( isset( $opts['threshold'] ) ? $opts['threshold'] : 'high' );

		$hosts = isset( $opts['trusted_hosts'] ) ? (array) $opts['trusted_hosts'] : array();
		if ( ! empty( $opts['site_host'] ) ) {
			$hosts[] = $opts['site_host'];
		}
		$this->trusted_hosts = array_values( array_filter( array_map( 'strtolower', $hosts ), 'strlen' ) );
	}

	/**
	 * Analisa um valor bruto.
	 *
	 * @param mixed $raw Valor da coluna.
	 * @return array{findings: array, cleaned: string|null, serialized: bool, blocked: string|null}
	 */
	public function analyze( $raw ) {
		$this->findings = array();
		$this->blocked  = null;
		$this->changes  = 0;

		$result = array(
			'findings'   => array(),
			'cleaned'    => null,
			'serialized' => false,
			'blocked'    => null,
		);

		if ( ! is_string( $raw ) || '' === $raw ) {
			return $result;
		}

		$new = $this->process_string( $raw, '', 0 );

		if ( null !== $this->blocked ) {
			foreach ( $this->findings as $i => $f ) {
				$this->findings[ $i ]['action'] = 'report';
			}
		}

		$result['findings']   = $this->findings;
		$result['serialized'] = is_serialized( $raw );
		$result['blocked']    = $this->blocked;
		if ( null === $this->blocked && $this->changes > 0 && $new !== $raw ) {
			$result['cleaned'] = $new;
		}
		return $result;
	}

	/**
	 * Severidade máxima de uma lista de achados.
	 *
	 * @param array $findings Achados.
	 * @return string
	 */
	public static function max_severity( array $findings ) {
		$max  = 0;
		$name = '';
		foreach ( $findings as $f ) {
			$l = WPAI_Signatures::level( $f['severity'] );
			if ( $l > $max ) {
				$max  = $l;
				$name = $f['severity'];
			}
		}
		return $name;
	}

	/**
	 * Processa uma string: serializada (recursão), JSON (só reporta) ou texto.
	 *
	 * @param string $s     Valor.
	 * @param string $path  Caminho dentro da estrutura (para o relatório).
	 * @param int    $depth Profundidade.
	 * @return string
	 */
	private function process_string( $s, $path, $depth ) {
		if ( $depth > self::MAX_DEPTH ) {
			$this->block( 'profundidade máxima excedida' );
			return $s;
		}

		if ( is_serialized( $s ) ) {
			return $this->process_serialized( $s, $path, $depth );
		}

		if ( $this->looks_like_json( $s ) ) {
			$before = $this->changes;
			$this->clean_text( $s, $path );
			if ( $this->changes !== $before ) {
				// Remover texto de dentro de JSON (ex.: dados de construtores de
				// página) exigiria re-encode com flags que o plugin dono espera.
				$this->changes = $before;
				$this->block( 'JSON em ' . $this->label_path( $path ) . ': limpeza manual' );
			}
			return $s;
		}

		return $this->clean_text( $s, $path );
	}

	/**
	 * Valor serializado: desserializa com segurança, percorre e re-serializa
	 * somente se algo mudou.
	 *
	 * @param string $s     Valor serializado.
	 * @param string $path  Caminho.
	 * @param int    $depth Profundidade.
	 * @return string
	 */
	private function process_serialized( $s, $path, $depth ) {
		$mark         = count( $this->findings );
		$changes_mark = $this->changes;
		$blocked_mark = $this->blocked;
		$where        = $this->label_path( $path );

		if ( preg_match( '/(?:^|[;{])[Rr]:\d+;/', $s ) ) {
			$this->block( "referências serializadas em {$where}" );
			$this->scan_only( $s, $path, $mark );
			return $s;
		}

		$trimmed = trim( $s );
		if ( 'b:0;' === $trimmed ) {
			return $s;
		}

		$data = @unserialize( $trimmed, array( 'allowed_classes' => array( 'stdClass' ) ) ); // phpcs:ignore
		if ( false === $data ) {
			$this->block( "serializado corrompido em {$where}" );
			$this->scan_only( $s, $path, $mark );
			return $s;
		}

		$data = $this->walk( $data, $path, $depth + 1 );

		if ( $this->blocked !== $blocked_mark ) {
			// Algo interno não é limpável: descarta o que foi feito neste
			// valor e reporta varrendo o texto bruto.
			$this->changes = $changes_mark;
			$this->scan_only( $s, $path, $mark );
			return $s;
		}

		if ( $this->changes === $changes_mark ) {
			return $s; // Nada mudou: devolve os bytes originais.
		}

		return serialize( $data ); // phpcs:ignore
	}

	/**
	 * Percorre arrays/stdClass recursivamente limpando strings.
	 *
	 * @param mixed  $node  Nó.
	 * @param string $path  Caminho.
	 * @param int    $depth Profundidade.
	 * @return mixed
	 */
	private function walk( $node, $path, $depth ) {
		if ( $depth > self::MAX_DEPTH ) {
			$this->block( 'profundidade máxima excedida' );
			return $node;
		}
		if ( is_string( $node ) ) {
			return $this->process_string( $node, $path, $depth );
		}
		if ( is_array( $node ) ) {
			foreach ( $node as $k => $v ) {
				$node[ $k ] = $this->walk( $v, $path . '[' . $k . ']', $depth + 1 );
			}
			return $node;
		}
		if ( $node instanceof stdClass ) {
			foreach ( get_object_vars( $node ) as $k => $v ) {
				$node->$k = $this->walk( $v, $path . '->' . $k, $depth + 1 );
			}
			return $node;
		}
		if ( is_object( $node ) ) {
			$this->block( 'objeto serializado de classe não permitida em ' . $this->label_path( $path ) );
		}
		return $node;
	}

	/**
	 * Varre sem alterar (para valores bloqueados), descartando achados
	 * parciais a partir de $mark.
	 *
	 * @param string $s    Texto.
	 * @param string $path Caminho.
	 * @param int    $mark Índice a partir do qual descartar achados.
	 */
	private function scan_only( $s, $path, $mark ) {
		array_splice( $this->findings, $mark );
		$changes = $this->changes;
		$this->clean_text( $s, $path );
		$this->changes = $changes;
	}

	/**
	 * Texto simples: remove elementos maliciosos e reporta padrões soltos.
	 *
	 * @param string $s    Texto.
	 * @param string $path Caminho.
	 * @return string
	 */
	private function clean_text( $s, $path ) {
		$out = $this->process_elements( $s, 'script', self::RE_SCRIPT, $path );
		if ( null !== $out ) {
			$out = $this->process_elements( $out, 'iframe', self::RE_IFRAME, $path );
		}
		if ( null === $out ) {
			$this->block( 'erro PCRE (valor muito grande ou complexo)' );
			return $s;
		}

		foreach ( $this->sigs_by_scope['any'] as $sig ) {
			$offset = $this->match( $sig, $out );
			if ( false !== $offset ) {
				$this->add_finding( $sig, $path, 'report', $this->excerpt( $out, $offset ) );
			}
		}

		if ( $out !== $s ) {
			$this->changes++;
		}
		return $out;
	}

	/**
	 * Avalia cada elemento <script>/<iframe>; remove os que atingem o limiar.
	 *
	 * @param string $s       Texto.
	 * @param string $scope   script|iframe.
	 * @param string $regex   Regex do elemento.
	 * @param string $path    Caminho.
	 * @return string|null Null em erro PCRE.
	 */
	private function process_elements( $s, $scope, $regex, $path ) {
		if ( empty( $this->sigs_by_scope[ $scope ] ) || false === stripos( $s, '<' . $scope ) ) {
			return $s;
		}

		$out = preg_replace_callback(
			$regex,
			function ( $m ) use ( $scope, $path ) {
				return $this->evaluate_element( $m[0], $scope, $path );
			},
			$s
		);

		return is_string( $out ) ? $out : null;
	}

	/**
	 * Avalia um elemento contra as assinaturas do escopo.
	 *
	 * @param string $el    Elemento completo.
	 * @param string $scope Escopo.
	 * @param string $path  Caminho.
	 * @return string Elemento original ou '' se removido.
	 */
	private function evaluate_element( $el, $scope, $path ) {
		$hits = array();
		$max  = 0;
		foreach ( $this->sigs_by_scope[ $scope ] as $sig ) {
			if ( false !== $this->match( $sig, $el ) ) {
				$hits[] = $sig;
				$max    = max( $max, WPAI_Signatures::level( $sig['severity'] ) );
			}
		}
		if ( empty( $hits ) ) {
			return $el;
		}
		$remove = $max >= $this->threshold;
		foreach ( $hits as $sig ) {
			$this->add_finding( $sig, $path, $remove ? 'remove' : 'report', $this->excerpt( $el, 0 ) );
		}
		return $remove ? '' : $el;
	}

	/**
	 * A assinatura casa? Retorna o offset do primeiro casamento ou false.
	 *
	 * @param array  $sig  Assinatura.
	 * @param string $text Texto.
	 * @return int|false
	 */
	private function match( array $sig, $text ) {
		if ( 'external_src' === $sig['type'] ) {
			return $this->has_untrusted_src( $text ) ? 0 : false;
		}
		$first = false;
		foreach ( WPAI_Signatures::patterns( $sig ) as $p ) {
			if ( 1 !== @preg_match( $p, $text, $m, PREG_OFFSET_CAPTURE ) ) { // phpcs:ignore
				return false;
			}
			if ( false === $first ) {
				$first = (int) $m[0][1];
			}
		}
		return $first;
	}

	/**
	 * <script src> aponta para host fora da lista confiável?
	 *
	 * @param string $el Elemento <script ...>.
	 * @return bool
	 */
	private function has_untrusted_src( $el ) {
		if ( ! preg_match( '#^<script\b[^>]*>#i', $el, $open ) ) {
			return false;
		}
		if ( ! preg_match( '#\bsrc\s*=\s*\\\\?["\']?\s*([^"\'\s>\\\\]+)#i', $open[0], $src ) ) {
			return false;
		}
		$url = html_entity_decode( $src[1], ENT_QUOTES, 'UTF-8' );

		if ( preg_match( '#^\s*(?:data|javascript|vbscript):#i', $url ) ) {
			return true;
		}
		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'http:' . $url;
		} elseif ( ! preg_match( '#^[a-z][a-z0-9+.\-]*://#i', $url ) ) {
			return false; // Caminho relativo: mesmo host.
		}
		$host = parse_url( $url, PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! is_string( $host ) || '' === $host ) {
			return true; // URL absoluta sem host legível: suspeita.
		}
		return ! WPAI_Settings::host_trusted( $host, $this->trusted_hosts );
	}

	/**
	 * Registra um achado.
	 *
	 * @param array  $sig     Assinatura.
	 * @param string $path    Caminho.
	 * @param string $action  remove|report.
	 * @param string $excerpt Trecho.
	 */
	private function add_finding( array $sig, $path, $action, $excerpt ) {
		$this->findings[] = array(
			'signature' => $sig['id'],
			'label'     => $sig['label'],
			'severity'  => $sig['severity'],
			'action'    => $action,
			'path'      => $this->label_path( $path ),
			'excerpt'   => $excerpt,
		);
	}

	/**
	 * Trecho curto e inofensivo para relatório: sem caracteres de controle
	 * (evita injeção de sequências ANSI no terminal do WP-CLI) e UTF-8 válido.
	 *
	 * @param string $text   Texto.
	 * @param int    $offset Posição do casamento.
	 * @return string
	 */
	private function excerpt( $text, $offset ) {
		$start = max( 0, $offset - 20 );
		$cut   = function_exists( 'mb_strcut' )
			? mb_strcut( $text, $start, self::EXCERPT_LEN, 'UTF-8' )
			: substr( $text, $start, self::EXCERPT_LEN );
		$cut   = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $cut );
		if ( function_exists( 'mb_convert_encoding' ) ) {
			$cut = mb_convert_encoding( $cut, 'UTF-8', 'UTF-8' );
		}
		return (string) $cut;
	}

	/**
	 * Marca o valor como não limpável (mantém o primeiro motivo).
	 *
	 * @param string $reason Motivo.
	 */
	private function block( $reason ) {
		if ( null === $this->blocked ) {
			$this->blocked = $reason;
		}
	}

	/**
	 * JSON objeto/array válido?
	 *
	 * @param string $s Texto.
	 * @return bool
	 */
	private function looks_like_json( $s ) {
		$t = ltrim( $s );
		if ( '' === $t || ( '{' !== $t[0] && '[' !== $t[0] ) ) {
			return false;
		}
		$d = json_decode( $s, true );
		return JSON_ERROR_NONE === json_last_error() && is_array( $d );
	}

	/**
	 * @param string $path Caminho.
	 * @return string
	 */
	private function label_path( $path ) {
		return '' === $path ? '(valor)' : $path;
	}
}
