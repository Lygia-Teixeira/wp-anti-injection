<?php
/**
 * Persistência: tabelas próprias, quarentena (backup + rollback) e log.
 *
 * Nada é gravado em arquivo: resultados e log ficam no banco, fora do
 * alcance de uma requisição HTTP anônima.
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Store {

	const DB_VERSION_OPTION = 'wpai_db_version';
	const RUNS_OPTION       = 'wpai_runs';
	const KEEP_RUNS         = 20;

	/** @return string */
	public static function quarantine_table() {
		global $wpdb;
		return $wpdb->prefix . 'wpai_quarantine';
	}

	/** @return string */
	public static function log_table() {
		global $wpdb;
		return $wpdb->prefix . 'wpai_log';
	}

	/* ------------------------------------------------------------------ */
	/* Instalação                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Hook de ativação (suporta ativação de rede).
	 *
	 * @param bool $network_wide Ativação em toda a rede.
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			foreach ( get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			) as $blog_id ) {
				switch_to_blog( $blog_id );
				self::install();
				restore_current_blog();
			}
			return;
		}
		self::install();
	}

	/**
	 * Cria/atualiza tabelas via dbDelta.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$q       = self::quarantine_table();
		$l       = self::log_table();

		// dbDelta exige: uma coluna por linha, dois espaços após PRIMARY KEY.
		dbDelta(
			"CREATE TABLE {$q} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id varchar(40) NOT NULL DEFAULT '',
  created_at datetime NOT NULL,
  created_by bigint(20) unsigned NOT NULL DEFAULT 0,
  target varchar(20) NOT NULL DEFAULT '',
  table_name varchar(64) NOT NULL DEFAULT '',
  pk_column varchar(64) NOT NULL DEFAULT '',
  row_id bigint(20) unsigned NOT NULL DEFAULT 0,
  column_name varchar(64) NOT NULL DEFAULT '',
  context varchar(255) NOT NULL DEFAULT '',
  signatures text NOT NULL,
  original_value longtext NOT NULL,
  original_hash char(32) NOT NULL DEFAULT '',
  cleaned_hash char(32) NOT NULL DEFAULT '',
  status varchar(20) NOT NULL DEFAULT 'quarantined',
  restored_at datetime NULL DEFAULT NULL,
  restored_by bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY run_id (run_id),
  KEY status (status),
  KEY target_row (target,row_id)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$l} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id varchar(40) NOT NULL DEFAULT '',
  created_at datetime NOT NULL,
  mode varchar(10) NOT NULL DEFAULT '',
  target varchar(20) NOT NULL DEFAULT '',
  row_id bigint(20) unsigned NOT NULL DEFAULT 0,
  column_name varchar(64) NOT NULL DEFAULT '',
  context varchar(255) NOT NULL DEFAULT '',
  signature varchar(64) NOT NULL DEFAULT '',
  severity varchar(10) NOT NULL DEFAULT '',
  action varchar(10) NOT NULL DEFAULT '',
  status varchar(20) NOT NULL DEFAULT '',
  path varchar(255) NOT NULL DEFAULT '',
  excerpt text NOT NULL,
  quarantine_id bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY run_id (run_id),
  KEY severity (severity)
) {$charset};"
		);

		// Autoload: é lido em toda requisição por maybe_upgrade().
		update_option( self::DB_VERSION_OPTION, WPAI_DB_VERSION, true );
		add_option( WPAI_Settings::OPTION, WPAI_Settings::defaults(), '', 'no' );
	}

	/**
	 * Recria as tabelas se a versão do esquema mudou.
	 */
	public static function maybe_upgrade() {
		if ( get_option( self::DB_VERSION_OPTION ) !== WPAI_DB_VERSION ) {
			self::install();
		}
	}

	/* ------------------------------------------------------------------ */
	/* Execuções e log                                                     */
	/* ------------------------------------------------------------------ */

	/** @return string */
	public static function new_run_id() {
		return gmdate( 'Ymd-His' ) . '-' . bin2hex( random_bytes( 4 ) );
	}

	/**
	 * Grava os achados de um item.
	 *
	 * @param string $run_id Execução.
	 * @param string $mode   detect|clean.
	 * @param array  $item   Item do Scanner (target, row_id, column, context, status, quarantine_id).
	 * @param array  $findings Achados do Cleaner.
	 */
	public static function log_findings( $run_id, $mode, array $item, array $findings ) {
		global $wpdb;
		$now = current_time( 'mysql', true );
		foreach ( $findings as $f ) {
			$wpdb->insert(
				self::log_table(),
				array(
					'run_id'        => $run_id,
					'created_at'    => $now,
					'mode'          => $mode,
					'target'        => $item['target'],
					'row_id'        => (int) $item['row_id'],
					'column_name'   => $item['column'],
					'context'       => self::cut( $item['context'], 255 ),
					'signature'     => $f['signature'],
					'severity'      => $f['severity'],
					'action'        => $f['action'],
					'status'        => $item['status'],
					'path'          => self::cut( $f['path'], 255 ),
					'excerpt'       => $f['excerpt'],
					'quarantine_id' => (int) $item['quarantine_id'],
				),
				array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d' )
			);
		}
	}

	/**
	 * Guarda o resumo da execução e poda o log de execuções antigas.
	 *
	 * @param array $summary Resumo (sem a lista de itens).
	 */
	public static function record_run( array $summary ) {
		global $wpdb;
		$runs = get_option( self::RUNS_OPTION, array() );
		$runs = is_array( $runs ) ? $runs : array();
		array_unshift( $runs, $summary );

		$drop = array_slice( $runs, self::KEEP_RUNS );
		$runs = array_slice( $runs, 0, self::KEEP_RUNS );
		update_option( self::RUNS_OPTION, $runs, false );

		foreach ( $drop as $old ) {
			if ( ! empty( $old['run_id'] ) ) {
				$wpdb->delete( self::log_table(), array( 'run_id' => (string) $old['run_id'] ), array( '%s' ) );
			}
		}
	}

	/** @return array */
	public static function runs() {
		$runs = get_option( self::RUNS_OPTION, array() );
		return is_array( $runs ) ? $runs : array();
	}

	/**
	 * Achados de uma execução.
	 *
	 * @param string $run_id Execução.
	 * @param int    $limit  Limite.
	 * @param int    $offset Deslocamento (só leitura; nada muda entre páginas).
	 * @return array
	 */
	public static function run_findings( $run_id, $limit = 200, $offset = 0 ) {
		global $wpdb;
		$t = self::log_table();
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, target, row_id, column_name, context, signature, severity, action, status, path, excerpt, quarantine_id
				 FROM `{$t}` WHERE run_id = %s ORDER BY id ASC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$run_id,
				$limit,
				$offset
			),
			ARRAY_A
		);
	}

	/* ------------------------------------------------------------------ */
	/* Quarentena                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Salva o valor original ANTES de qualquer alteração.
	 *
	 * @param array $d Dados.
	 * @return int ID da quarentena ou 0 em falha.
	 */
	public static function quarantine_add( array $d ) {
		global $wpdb;
		$ok = $wpdb->insert(
			self::quarantine_table(),
			array(
				'run_id'         => $d['run_id'],
				'created_at'     => current_time( 'mysql', true ),
				'created_by'     => get_current_user_id(),
				'target'         => $d['target'],
				'table_name'     => $d['table'],
				'pk_column'      => $d['pk'],
				'row_id'         => (int) $d['row_id'],
				'column_name'    => $d['column'],
				'context'        => self::cut( $d['context'], 255 ),
				'signatures'     => implode( ',', $d['signatures'] ),
				'original_value' => $d['original'],
				'original_hash'  => md5( $d['original'] ),
				'cleaned_hash'   => md5( $d['cleaned'] ),
				'status'         => 'quarantined',
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * @param int    $id     ID.
	 * @param string $status Novo status.
	 */
	public static function quarantine_set_status( $id, $status ) {
		global $wpdb;
		$wpdb->update( self::quarantine_table(), array( 'status' => $status ), array( 'id' => (int) $id ), array( '%s' ), array( '%d' ) );
	}

	/**
	 * Lista sem o valor original (pode ser grande).
	 *
	 * @param string $status Filtro ('' = todos).
	 * @param int    $limit  Limite.
	 * @return array
	 */
	public static function quarantine_list( $status = '', $limit = 100 ) {
		global $wpdb;
		$t    = self::quarantine_table();
		$cols = 'id, run_id, created_at, target, row_id, column_name, context, signatures, status, restored_at';
		if ( '' !== $status ) {
			return $wpdb->get_results(
				$wpdb->prepare( "SELECT {$cols} FROM `{$t}` WHERE status = %s ORDER BY id DESC LIMIT %d", $status, $limit ), // phpcs:ignore
				ARRAY_A
			);
		}
		return $wpdb->get_results(
			$wpdb->prepare( "SELECT {$cols} FROM `{$t}` ORDER BY id DESC LIMIT %d", $limit ), // phpcs:ignore
			ARRAY_A
		);
	}

	/**
	 * @param int $id ID.
	 * @return object|null
	 */
	public static function quarantine_get( $id ) {
		global $wpdb;
		$t = self::quarantine_table();
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", $id ) ); // phpcs:ignore
	}

	/**
	 * Atualiza a coluna SOMENTE se o valor atual ainda for o que foi lido
	 * (controle otimista: evita sobrescrever uma edição concorrente).
	 *
	 * @param array  $t        Definição do alvo (table, pk).
	 * @param int    $row_id   Linha.
	 * @param string $column   Coluna (validada contra o alvo).
	 * @param string $expected Valor lido.
	 * @param string $new      Novo valor.
	 * @return bool
	 */
	public static function compare_and_set( array $t, $row_id, $column, $expected, $new ) {
		global $wpdb;
		if ( ! in_array( $column, $t['columns'], true ) ) {
			return false;
		}
		$affected = $wpdb->query(
			$wpdb->prepare(
				"UPDATE `{$t['table']}` SET `{$column}` = %s WHERE `{$t['pk']}` = %d AND MD5(`{$column}`) = %s", // phpcs:ignore
				$new,
				$row_id,
				md5( $expected )
			)
		);
		return 1 === $affected;
	}

	/**
	 * Rollback de um item da quarentena.
	 *
	 * Não confia nos nomes de tabela/coluna gravados na linha: resolve o
	 * alvo pela lista fixa do Scanner. Recusa se o valor mudou depois da
	 * limpeza (a menos que $force), para não apagar edições legítimas.
	 *
	 * @param int  $id    ID da quarentena.
	 * @param bool $force Restaurar mesmo se o valor atual mudou.
	 * @return array{ok: bool, code: string}
	 */
	public static function restore( $id, $force = false ) {
		global $wpdb;
		$item = self::quarantine_get( $id );
		if ( ! $item ) {
			return array( 'ok' => false, 'code' => 'not_found' );
		}
		if ( 'restored' === $item->status && ! $force ) {
			return array( 'ok' => false, 'code' => 'already_restored' );
		}

		$targets = WPAI_Scanner::targets();
		if ( ! isset( $targets[ $item->target ] ) ) {
			return array( 'ok' => false, 'code' => 'bad_target' );
		}
		$t = $targets[ $item->target ];
		if ( $t['table'] !== $item->table_name || $t['pk'] !== $item->pk_column || ! in_array( $item->column_name, $t['columns'], true ) ) {
			return array( 'ok' => false, 'code' => 'bad_target' );
		}

		$col     = $item->column_name;
		$current = $wpdb->get_var(
			$wpdb->prepare( "SELECT `{$col}` FROM `{$t['table']}` WHERE `{$t['pk']}` = %d", (int) $item->row_id ) // phpcs:ignore
		);
		if ( null === $current ) {
			return array( 'ok' => false, 'code' => 'row_missing' );
		}
		if ( ! $force && md5( $current ) !== $item->cleaned_hash ) {
			return array( 'ok' => false, 'code' => 'changed_since_clean' );
		}

		$ok = $wpdb->update(
			$t['table'],
			array( $col => $item->original_value ),
			array( $t['pk'] => (int) $item->row_id ),
			array( '%s' ),
			array( '%d' )
		);
		if ( false === $ok ) {
			return array( 'ok' => false, 'code' => 'db_error' );
		}

		$wpdb->update(
			self::quarantine_table(),
			array(
				'status'      => 'restored',
				'restored_at' => current_time( 'mysql', true ),
				'restored_by' => get_current_user_id(),
			),
			array( 'id' => (int) $item->id ),
			array( '%s', '%s', '%d' ),
			array( '%d' )
		);
		self::flush_cache( $item->target, (int) $item->row_id );

		return array( 'ok' => true, 'code' => 'restored' );
	}

	/**
	 * Invalida o object cache do registro alterado por SQL direto.
	 *
	 * @param string $target Alvo.
	 * @param int    $row_id Linha.
	 */
	public static function flush_cache( $target, $row_id ) {
		global $wpdb;
		switch ( $target ) {
			case 'posts':
				clean_post_cache( $row_id );
				break;
			case 'postmeta':
				$post_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT post_id FROM {$wpdb->postmeta} WHERE meta_id = %d", $row_id ) );
				wp_cache_delete( $post_id, 'post_meta' );
				break;
			case 'options':
			case 'widgets':
				$name = $wpdb->get_var( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_id = %d", $row_id ) );
				if ( $name ) {
					wp_cache_delete( $name, 'options' );
				}
				wp_cache_delete( 'alloptions', 'options' );
				wp_cache_delete( 'notoptions', 'options' );
				break;
			case 'comments':
				clean_comment_cache( $row_id );
				break;
			case 'usermeta':
				$user_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE umeta_id = %d", $row_id ) );
				wp_cache_delete( $user_id, 'user_meta' );
				break;
		}
	}

	/**
	 * Corta em limite de caractere UTF-8.
	 *
	 * @param string $s   Texto.
	 * @param int    $len Bytes.
	 * @return string
	 */
	private static function cut( $s, $len ) {
		$s = (string) $s;
		return function_exists( 'mb_strcut' ) ? mb_strcut( $s, 0, $len, 'UTF-8' ) : substr( $s, 0, $len );
	}
}
