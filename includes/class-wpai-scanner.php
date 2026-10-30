<?php
/**
 * Varredura das tabelas com paginação por keyset.
 *
 * Por que keyset e não OFFSET: no modo limpar, as linhas limpas deixam de
 * casar com o pré-filtro, o conjunto de resultados "encolhe" e um OFFSET
 * crescente pula registros. Com `WHERE pk > :ultimo ORDER BY pk` cada
 * linha é visitada exatamente uma vez, alterada ou não.
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Scanner {

	const MODE_DETECT = 'detect';
	const MODE_CLEAN  = 'clean';

	/** @var WPAI_Cleaner */
	private $cleaner;

	/** @var array */
	private $settings;

	/** @var string[] */
	private $needles;

	/**
	 * @param WPAI_Cleaner $cleaner  Limpador configurado.
	 * @param array        $settings Configurações saneadas.
	 * @param string[]     $needles  Literais do pré-filtro SQL.
	 */
	public function __construct( WPAI_Cleaner $cleaner, array $settings, array $needles ) {
		$this->cleaner  = $cleaner;
		$this->settings = $settings;
		$this->needles  = $needles;
	}

	/**
	 * Alvos fixos: tabela, chave primária REAL, colunas de conteúdo e
	 * colunas de contexto. Nunca derivados de entrada do usuário.
	 *
	 * @return array<string, array>
	 */
	public static function targets() {
		global $wpdb;

		$own_options = array( WPAI_Settings::OPTION, WPAI_Store::RUNS_OPTION, WPAI_Store::DB_VERSION_OPTION );
		$widget_like = $wpdb->esc_like( 'widget_' ) . '%';

		return array(
			'posts'    => array(
				'label'      => 'Posts e páginas',
				'table'      => $wpdb->posts,
				'pk'         => 'ID',
				'columns'    => array( 'post_content', 'post_excerpt', 'post_title' ),
				'context'    => array( 'post_type' ),
				'post_col'   => 'ID',
				'where'      => '',
				'where_args' => array(),
			),
			'postmeta' => array(
				'label'      => 'Metadados de posts',
				'table'      => $wpdb->postmeta,
				'pk'         => 'meta_id',
				'columns'    => array( 'meta_value' ),
				'context'    => array( 'post_id', 'meta_key' ),
				'post_col'   => 'post_id',
				'where'      => '',
				'where_args' => array(),
			),
			'options'  => array(
				'label'      => 'Opções (exceto widgets)',
				'table'      => $wpdb->options,
				'pk'         => 'option_id',
				'columns'    => array( 'option_value' ),
				'context'    => array( 'option_name' ),
				'option_col' => 'option_name',
				'where'      => 'option_name NOT LIKE %s AND option_name <> %s AND option_name NOT IN (%s, %s, %s)',
				'where_args' => array_merge( array( $widget_like, 'sidebars_widgets' ), $own_options ),
			),
			'widgets'  => array(
				'label'      => 'Widgets',
				'table'      => $wpdb->options,
				'pk'         => 'option_id',
				'columns'    => array( 'option_value' ),
				'context'    => array( 'option_name' ),
				'option_col' => 'option_name',
				'where'      => '(option_name LIKE %s OR option_name = %s)',
				'where_args' => array( $widget_like, 'sidebars_widgets' ),
			),
			'comments' => array(
				'label'      => 'Comentários',
				'table'      => $wpdb->comments,
				'pk'         => 'comment_ID',
				'columns'    => array( 'comment_content', 'comment_author', 'comment_author_url' ),
				'context'    => array( 'comment_post_ID' ),
				'post_col'   => 'comment_post_ID',
				'where'      => '',
				'where_args' => array(),
			),
			'usermeta' => array(
				'label'      => 'Metadados de usuários',
				'table'      => $wpdb->usermeta,
				'pk'         => 'umeta_id',
				'columns'    => array( 'meta_value' ),
				'context'    => array( 'user_id', 'meta_key' ),
				'where'      => '',
				'where_args' => array(),
			),
		);
	}

	/**
	 * Valida uma lista de alvos ('' ou vazio = todos).
	 *
	 * @param string|string[] $list Lista.
	 * @return string[] Alvos válidos.
	 */
	public static function parse_targets( $list ) {
		$all = array_keys( self::targets() );
		if ( is_string( $list ) ) {
			$list = '' === trim( $list ) ? array() : explode( ',', $list );
		}
		$list = array_map( 'trim', array_map( 'strval', (array) $list ) );
		$list = array_values( array_intersect( $all, $list ) );
		return empty( $list ) ? $all : $list;
	}

	/**
	 * Executa a varredura.
	 *
	 * @param string[]      $target_keys Alvos.
	 * @param string        $mode        detect|clean.
	 * @param string        $run_id      ID da execução.
	 * @param callable|null $progress    fn(string $target, int $rows) opcional.
	 * @return array Resumo + itens.
	 */
	public function run( array $target_keys, $mode, $run_id, $progress = null ) {
		global $wpdb;

		$mode    = self::MODE_CLEAN === $mode ? self::MODE_CLEAN : self::MODE_DETECT;
		$targets = self::targets();
		$batch   = (int) $this->settings['batch_size'];

		$summary = array(
			'run_id'       => $run_id,
			'mode'         => $mode,
			'started_at'   => gmdate( 'Y-m-d H:i:s' ),
			'targets'      => $target_keys,
			'rows_read'    => 0,
			'items'        => 0,
			'findings'     => 0,
			'cleaned'      => 0,
			'would_clean'  => 0,
			'blocked'      => 0,
			'conflicts'    => 0,
			'errors'       => 0,
			'allowlisted'  => 0,
			'by_severity'  => array(),
			'finished_at'  => '',
		);
		$items = array();

		if ( empty( $this->needles ) ) {
			$summary['finished_at'] = gmdate( 'Y-m-d H:i:s' );
			return array( 'summary' => $summary, 'items' => $items );
		}

		foreach ( $target_keys as $key ) {
			if ( ! isset( $targets[ $key ] ) ) {
				continue;
			}
			$t    = $targets[ $key ];
			$last = 0;

			$select = array_unique( array_merge( array( $t['pk'] ), $t['context'], $t['columns'] ) );
			$select = '`' . implode( '`, `', $select ) . '`';

			// Pré-filtro: (col1 LIKE %s OR col1 LIKE %s ... OR colN LIKE %s).
			$likes      = array();
			$like_args  = array();
			foreach ( $t['columns'] as $col ) {
				foreach ( $this->needles as $n ) {
					$likes[]     = "`{$col}` LIKE %s";
					$like_args[] = '%' . $wpdb->esc_like( $n ) . '%';
				}
			}
			$where_extra = '' !== $t['where'] ? ' AND (' . $t['where'] . ')' : '';

			$sql = "SELECT {$select} FROM `{$t['table']}`"
				. " WHERE `{$t['pk']}` > %d{$where_extra} AND (" . implode( ' OR ', $likes ) . ')'
				. " ORDER BY `{$t['pk']}` ASC LIMIT %d";

			while ( true ) {
				$args = array_merge( array( $last ), $t['where_args'], $like_args, array( $batch ) );
				$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
				if ( empty( $rows ) ) {
					break;
				}

				foreach ( $rows as $row ) {
					$last = (int) $row[ $t['pk'] ];
					$summary['rows_read']++;

					if ( $this->allowlisted( $t, $row ) ) {
						$summary['allowlisted']++;
						continue;
					}

					foreach ( $t['columns'] as $col ) {
						$item = $this->process_cell( $key, $t, $row, $col, $mode, $run_id, $summary );
						if ( null !== $item ) {
							$items[] = $item;
						}
					}
				}

				if ( is_callable( $progress ) ) {
					call_user_func( $progress, $key, $summary['rows_read'] );
				}
				if ( count( $rows ) < $batch ) {
					break;
				}
			}
		}

		$summary['finished_at'] = gmdate( 'Y-m-d H:i:s' );
		return array( 'summary' => $summary, 'items' => $items );
	}

	/**
	 * Analisa (e, no modo limpar, corrige) uma célula.
	 *
	 * @param string $key     Alvo.
	 * @param array  $t       Definição.
	 * @param array  $row     Linha.
	 * @param string $col     Coluna.
	 * @param string $mode    Modo.
	 * @param string $run_id  Execução.
	 * @param array  $summary Resumo (por referência).
	 * @return array|null Item ou null se nada encontrado.
	 */
	private function process_cell( $key, array $t, array $row, $col, $mode, $run_id, array &$summary ) {
		$original = isset( $row[ $col ] ) ? (string) $row[ $col ] : '';
		$res      = $this->cleaner->analyze( $original );
		if ( empty( $res['findings'] ) ) {
			return null;
		}

		$row_id  = (int) $row[ $t['pk'] ];
		$context = $this->context( $t, $row );
		$sigs    = array_values( array_unique( wp_list_pluck( $res['findings'], 'signature' ) ) );
		$qid     = 0;

		if ( null !== $res['blocked'] ) {
			$status = 'blocked';
			$summary['blocked']++;
		} elseif ( null === $res['cleaned'] ) {
			$status = 'reported';
		} elseif ( self::MODE_DETECT === $mode ) {
			$status = 'would_clean';
			$summary['would_clean']++;
		} else {
			// 1) backup do original; 2) só então altera; 3) se outra escrita
			// chegou antes, não sobrescreve e marca conflito.
			$qid = WPAI_Store::quarantine_add(
				array(
					'run_id'     => $run_id,
					'target'     => $key,
					'table'      => $t['table'],
					'pk'         => $t['pk'],
					'row_id'     => $row_id,
					'column'     => $col,
					'context'    => $context,
					'signatures' => $sigs,
					'original'   => $original,
					'cleaned'    => $res['cleaned'],
				)
			);
			if ( 0 === $qid ) {
				$status = 'error';
				$summary['errors']++;
			} elseif ( WPAI_Store::compare_and_set( $t, $row_id, $col, $original, $res['cleaned'] ) ) {
				$status = 'cleaned';
				$summary['cleaned']++;
				WPAI_Store::flush_cache( $key, $row_id );
			} else {
				$status = 'conflict';
				$summary['conflicts']++;
				WPAI_Store::quarantine_set_status( $qid, 'conflict' );
			}
		}

		$severity = WPAI_Cleaner::max_severity( $res['findings'] );
		$summary['items']++;
		$summary['findings'] += count( $res['findings'] );
		if ( ! isset( $summary['by_severity'][ $severity ] ) ) {
			$summary['by_severity'][ $severity ] = 0;
		}
		$summary['by_severity'][ $severity ]++;

		$item = array(
			'target'        => $key,
			'row_id'        => $row_id,
			'column'        => $col,
			'context'       => $context,
			'severity'      => $severity,
			'signatures'    => implode( ',', $sigs ),
			'status'        => $status,
			'quarantine_id' => $qid,
			'note'          => null !== $res['blocked'] ? $res['blocked'] : '',
		);

		WPAI_Store::log_findings( $run_id, $mode, $item, $res['findings'] );
		$item['findings'] = $res['findings'];
		return $item;
	}

	/**
	 * Linha na allowlist (option_name ou post_id)?
	 *
	 * @param array $t   Definição.
	 * @param array $row Linha.
	 * @return bool
	 */
	private function allowlisted( array $t, array $row ) {
		if ( isset( $t['option_col'] ) && ! empty( $this->settings['allow_options'] ) ) {
			if ( WPAI_Settings::name_matches( (string) $row[ $t['option_col'] ], $this->settings['allow_options'] ) ) {
				return true;
			}
		}
		if ( isset( $t['post_col'] ) && ! empty( $this->settings['allow_post_ids'] ) ) {
			if ( in_array( (int) $row[ $t['post_col'] ], $this->settings['allow_post_ids'], true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * "option_name=foo" / "post_id=12 meta_key=_bar".
	 *
	 * @param array $t   Definição.
	 * @param array $row Linha.
	 * @return string
	 */
	private function context( array $t, array $row ) {
		$parts = array();
		foreach ( $t['context'] as $c ) {
			$parts[] = $c . '=' . ( isset( $row[ $c ] ) ? $row[ $c ] : '' );
		}
		return implode( ' ', $parts );
	}
}
