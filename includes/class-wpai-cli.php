<?php
/**
 * Comandos WP-CLI: wp anti-injection <scan|clean|restore|quarantine|signatures>
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detecta e limpa injeções maliciosas gravadas no banco do WordPress.
 */
class WPAI_CLI {

	const FIELDS = array( 'target', 'row_id', 'column', 'context', 'severity', 'signatures', 'status', 'quarantine_id', 'note' );

	/**
	 * Varre o banco em modo somente leitura.
	 *
	 * ## OPTIONS
	 *
	 * [--tables=<tables>]
	 * : Alvos separados por vírgula: posts,postmeta,options,widgets,comments,usermeta. Padrão: todos.
	 *
	 * [--format=<format>]
	 * : Formato da saída.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp anti-injection scan
	 *     wp anti-injection scan --tables=options,widgets --format=json
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Posicionais.
	 * @param array $assoc_args Nomeados.
	 */
	public function scan( $args, $assoc_args ) {
		$this->execute( WPAI_Scanner::MODE_DETECT, $assoc_args );
	}

	/**
	 * Remove os elementos maliciosos, com backup de cada valor na quarentena.
	 *
	 * ## OPTIONS
	 *
	 * [--tables=<tables>]
	 * : Alvos separados por vírgula. Padrão: todos.
	 *
	 * [--format=<format>]
	 * : Formato da saída.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * [--yes]
	 * : Confirma sem perguntar.
	 *
	 * ## EXAMPLES
	 *
	 *     wp db export antes-da-limpeza.sql && wp anti-injection clean --yes
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Posicionais.
	 * @param array $assoc_args Nomeados.
	 */
	public function clean( $args, $assoc_args ) {
		$s = WPAI_Settings::get();
		WP_CLI::confirm(
			sprintf(
				'Remover elementos com severidade >= %s? Cada valor original vai para a quarentena. Recomenda-se "wp db export" antes.',
				$s['threshold']
			),
			$assoc_args
		);
		$this->execute( WPAI_Scanner::MODE_CLEAN, $assoc_args );
	}

	/**
	 * Restaura um item da quarentena.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : ID do item na quarentena.
	 *
	 * [--force]
	 * : Restaura mesmo que o valor tenha mudado depois da limpeza.
	 *
	 * ## EXAMPLES
	 *
	 *     wp anti-injection restore 42
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Posicionais.
	 * @param array $assoc_args Nomeados.
	 */
	public function restore( $args, $assoc_args ) {
		$id = isset( $args[0] ) ? absint( $args[0] ) : 0;
		if ( $id < 1 ) {
			WP_CLI::error( 'Informe um ID válido.' );
		}
		$res = WPAI_Store::restore( $id, (bool) \WP_CLI\Utils\get_flag_value( $assoc_args, 'force', false ) );
		if ( $res['ok'] ) {
			WP_CLI::success( "Item #{$id} restaurado." );
			return;
		}
		$hint = 'changed_since_clean' === $res['code'] ? ' Use --force se tiver certeza.' : '';
		WP_CLI::error( "Falha ao restaurar #{$id}: {$res['code']}.{$hint}" );
	}

	/**
	 * Lista a quarentena.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : quarantined, restored ou conflict.
	 *
	 * [--format=<format>]
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Posicionais.
	 * @param array $assoc_args Nomeados.
	 */
	public function quarantine( $args, $assoc_args ) {
		$status = isset( $assoc_args['status'] ) ? sanitize_key( $assoc_args['status'] ) : '';
		$items  = WPAI_Store::quarantine_list( $status, 1000 );
		\WP_CLI\Utils\format_items(
			$this->format( $assoc_args ),
			$items,
			array( 'id', 'created_at', 'target', 'row_id', 'column_name', 'context', 'signatures', 'status', 'restored_at' )
		);
	}

	/**
	 * Lista as assinaturas ativas e desativadas.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Posicionais.
	 * @param array $assoc_args Nomeados.
	 */
	public function signatures( $args, $assoc_args ) {
		$s    = WPAI_Settings::get();
		$rows = array();
		foreach ( WPAI_Signatures::all() as $id => $sig ) {
			$rows[] = array(
				'id'       => $id,
				'scope'    => $sig['scope'],
				'severity' => $sig['severity'],
				'enabled'  => in_array( $id, $s['disabled_signatures'], true ) ? 'no' : 'yes',
				'label'    => $sig['label'],
			);
		}
		\WP_CLI\Utils\format_items( $this->format( $assoc_args ), $rows, array( 'id', 'scope', 'severity', 'enabled', 'label' ) );
	}

	/**
	 * Executa e imprime. Em json/csv o stdout contém só os dados; o resumo
	 * vai para stderr (pipes e parsers não quebram).
	 *
	 * @param string $mode       Modo.
	 * @param array  $assoc_args Nomeados.
	 */
	private function execute( $mode, array $assoc_args ) {
		$format  = $this->format( $assoc_args );
		$targets = WPAI_Scanner::parse_targets( isset( $assoc_args['tables'] ) ? (string) $assoc_args['tables'] : '' );

		if ( isset( $assoc_args['tables'] ) ) {
			$asked   = array_filter( array_map( 'trim', explode( ',', (string) $assoc_args['tables'] ) ), 'strlen' );
			$unknown = array_diff( $asked, array_keys( WPAI_Scanner::targets() ) );
			if ( $unknown ) {
				WP_CLI::error( 'Alvos desconhecidos: ' . implode( ', ', $unknown ) );
			}
		}

		$progress = null;
		if ( 'table' === $format ) {
			$progress = function ( $target, $rows ) {
				WP_CLI::log( "  {$target}: {$rows} linhas candidatas lidas" );
			};
		}

		$result = WPAI_Plugin::run( $targets, $mode, $progress );
		$sum    = $result['summary'];

		if ( 'json' === $format ) {
			WP_CLI::line( wp_json_encode( $result['items'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ) );
		} elseif ( ! empty( $result['items'] ) ) {
			\WP_CLI\Utils\format_items( $format, $result['items'], self::FIELDS );
		}

		$line = sprintf(
			'[%s] %s: %d linhas lidas, %d itens com achados, %d limpos, %d a limpar, %d bloqueados (só reporte), %d conflitos, %d erros, %d na allowlist.',
			$sum['run_id'],
			WPAI_Scanner::MODE_CLEAN === $mode ? 'clean' : 'scan',
			$sum['rows_read'],
			$sum['items'],
			$sum['cleaned'],
			$sum['would_clean'],
			$sum['blocked'],
			$sum['conflicts'],
			$sum['errors'],
			$sum['allowlisted']
		);

		if ( 'table' === $format ) {
			WP_CLI::success( $line );
		} else {
			fwrite( STDERR, $line . PHP_EOL ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * @param array $assoc_args Nomeados.
	 * @return string
	 */
	private function format( array $assoc_args ) {
		$f = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		return in_array( $f, array( 'table', 'json', 'csv' ), true ) ? $f : 'table';
	}
}
