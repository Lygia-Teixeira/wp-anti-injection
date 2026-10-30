<?php
/**
 * Tela em Ferramentas -> Anti Injection.
 *
 * Toda ação passa por admin-post.php com capability + nonce + referer;
 * a tela só lê. Mensagens vêm de uma lista fixa (nada de texto refletido
 * da URL) e toda saída é escapada.
 *
 * @package WP_Anti_Injection
 */

defined( 'ABSPATH' ) || exit;

final class WPAI_Admin {

	const SLUG    = 'wp-anti-injection';
	const CAP     = 'manage_options';
	const CONFIRM = 'LIMPAR';

	/** Registra hooks. */
	public function hooks() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_wpai_scan', array( $this, 'handle_scan' ) );
		add_action( 'admin_post_wpai_clean', array( $this, 'handle_clean' ) );
		add_action( 'admin_post_wpai_restore', array( $this, 'handle_restore' ) );
		add_action( 'admin_post_wpai_settings', array( $this, 'handle_settings' ) );
	}

	/** Menu. */
	public function menu() {
		add_management_page(
			'WP Anti Injection',
			'Anti Injection',
			self::CAP,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/* ------------------------------------------------------------------ */
	/* Handlers (POST)                                                     */
	/* ------------------------------------------------------------------ */

	/** Varredura somente leitura. */
	public function handle_scan() {
		$this->guard( 'wpai_scan' );
		$result = WPAI_Plugin::run( $this->posted_targets(), WPAI_Scanner::MODE_DETECT );
		$this->redirect( 'scanned', array( 'run' => $result['summary']['run_id'] ) );
	}

	/** Limpeza: exige caixa marcada + palavra digitada. */
	public function handle_clean() {
		$this->guard( 'wpai_clean' );

		$ack  = ! empty( $_POST['wpai_ack'] );
		$word = isset( $_POST['wpai_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['wpai_confirm'] ) ) : '';
		if ( ! $ack || self::CONFIRM !== $word ) {
			$this->redirect( 'confirm_missing' );
		}

		$result = WPAI_Plugin::run( $this->posted_targets(), WPAI_Scanner::MODE_CLEAN );
		$this->redirect( 'cleaned', array( 'run' => $result['summary']['run_id'] ) );
	}

	/** Rollback de um item. */
	public function handle_restore() {
		$id = isset( $_POST['quarantine_id'] ) ? absint( $_POST['quarantine_id'] ) : 0;
		$this->guard( 'wpai_restore_' . $id );
		$res = WPAI_Store::restore( $id, false );
		$this->redirect( $res['ok'] ? 'restored' : 'restore_' . $res['code'] );
	}

	/** Configurações. */
	public function handle_settings() {
		$this->guard( 'wpai_settings' );
		$raw = isset( $_POST['wpai'] ) && is_array( $_POST['wpai'] ) ? wp_unslash( $_POST['wpai'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- saneado em WPAI_Settings::sanitize().
		if ( ! isset( $raw['disabled_signatures'] ) ) {
			$raw['disabled_signatures'] = array();
		}
		update_option( WPAI_Settings::OPTION, WPAI_Settings::sanitize( $raw ), false );
		$this->redirect( 'saved' );
	}

	/**
	 * Capability + nonce + referer. Morre em qualquer falha.
	 *
	 * @param string $action Ação do nonce.
	 */
	private function guard( $action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Sem permissão.', 'wp-anti-injection' ), 403 );
		}
		check_admin_referer( $action );
	}

	/** @return string[] */
	private function posted_targets() {
		$raw = isset( $_POST['wpai_targets'] ) && is_array( $_POST['wpai_targets'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['wpai_targets'] ) )
			: array();
		return WPAI_Scanner::parse_targets( $raw );
	}

	/**
	 * @param string $notice Código da mensagem.
	 * @param array  $extra  Parâmetros extras.
	 */
	private function redirect( $notice, array $extra = array() ) {
		$url = add_query_arg(
			array_merge(
				array(
					'page'   => self::SLUG,
					'notice' => $notice,
				),
				$extra
			),
			admin_url( 'tools.php' )
		);
		wp_safe_redirect( $url );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Tela                                                                */
	/* ------------------------------------------------------------------ */

	/** Renderiza a página. */
	public function render() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$settings = WPAI_Settings::get();
		$runs     = WPAI_Store::runs();
		$run_id   = isset( $_GET['run'] ) ? preg_replace( '/[^0-9a-f\-]/', '', sanitize_text_field( wp_unslash( $_GET['run'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $run_id && ! empty( $runs[0]['run_id'] ) ) {
			$run_id = $runs[0]['run_id'];
		}

		echo '<div class="wrap"><h1>WP Anti Injection</h1>';
		$this->render_notice();

		echo '<p>' . esc_html__( 'Detecta e limpa injeções gravadas no banco. A varredura padrão é somente leitura; a limpeza grava o valor original na quarentena antes de alterar qualquer coisa.', 'wp-anti-injection' ) . '</p>';
		echo '<p><em>' . esc_html__( 'Em bancos grandes, prefira o WP-CLI: wp anti-injection scan', 'wp-anti-injection' ) . '</em></p>';

		$this->render_scan_forms();
		$this->render_run( $run_id, $runs );
		$this->render_quarantine();
		$this->render_settings( $settings );

		echo '</div>';
	}

	/** Mensagem a partir de lista fixa. */
	private function render_notice() {
		$code = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map  = array(
			'scanned'                    => array( 'success', 'Varredura concluída (somente leitura).' ),
			'cleaned'                    => array( 'success', 'Limpeza concluída. Originais salvos na quarentena.' ),
			'confirm_missing'            => array( 'error', 'Limpeza não executada: marque a confirmação e digite LIMPAR.' ),
			'restored'                   => array( 'success', 'Valor original restaurado.' ),
			'restore_not_found'          => array( 'error', 'Item de quarentena não encontrado.' ),
			'restore_already_restored'   => array( 'warning', 'Item já havia sido restaurado.' ),
			'restore_bad_target'         => array( 'error', 'Item de quarentena com alvo inválido; restauração recusada.' ),
			'restore_row_missing'        => array( 'error', 'O registro original não existe mais.' ),
			'restore_changed_since_clean' => array( 'warning', 'O valor mudou depois da limpeza. Use o WP-CLI com --force se tiver certeza.' ),
			'restore_db_error'           => array( 'error', 'Erro de banco ao restaurar.' ),
			'saved'                      => array( 'success', 'Configurações salvas.' ),
		);
		if ( isset( $map[ $code ] ) ) {
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				esc_attr( $map[ $code ][0] ),
				esc_html( $map[ $code ][1] )
			);
		}
	}

	/** Formulários de detectar e limpar. */
	private function render_scan_forms() {
		$targets = WPAI_Scanner::targets();
		$post    = esc_url( admin_url( 'admin-post.php' ) );

		$checks = '';
		foreach ( $targets as $key => $t ) {
			$checks .= sprintf(
				'<label style="margin-right:12px"><input type="checkbox" name="wpai_targets[]" value="%1$s" checked> %2$s</label>',
				esc_attr( $key ),
				esc_html( $t['label'] )
			);
		}

		echo '<h2>' . esc_html__( '1. Detectar (somente leitura)', 'wp-anti-injection' ) . '</h2>';
		echo '<form method="post" action="' . $post . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url acima.
		wp_nonce_field( 'wpai_scan' );
		echo '<input type="hidden" name="action" value="wpai_scan"><p>' . $checks . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- montado com esc_*.
		submit_button( __( 'Detectar agora', 'wp-anti-injection' ), 'primary', 'submit', false );
		echo '</form>';

		echo '<h2>' . esc_html__( '2. Limpar', 'wp-anti-injection' ) . '</h2>';
		echo '<form method="post" action="' . $post . '" style="border-left:4px solid #d63638;padding-left:12px">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		wp_nonce_field( 'wpai_clean' );
		echo '<input type="hidden" name="action" value="wpai_clean"><p>' . $checks . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<p><label><input type="checkbox" name="wpai_ack" value="1"> '
			. esc_html__( 'Revisei o relatório de detecção e tenho backup completo do banco. Entendo que só serão removidos elementos com severidade igual ou acima do limiar configurado.', 'wp-anti-injection' )
			. '</label></p>';
		echo '<p><label>' . esc_html__( 'Digite', 'wp-anti-injection' ) . ' <code>' . esc_html( self::CONFIRM ) . '</code>: '
			. '<input type="text" name="wpai_confirm" autocomplete="off" class="regular-text"></label></p>';
		submit_button( __( 'Limpar com quarentena', 'wp-anti-injection' ), 'delete', 'submit', false );
		echo '</form>';
	}

	/**
	 * Resultado de uma execução.
	 *
	 * @param string $run_id Execução.
	 * @param array  $runs   Execuções recentes.
	 */
	private function render_run( $run_id, array $runs ) {
		echo '<h2>' . esc_html__( 'Resultados', 'wp-anti-injection' ) . '</h2>';
		if ( '' === $run_id ) {
			echo '<p>' . esc_html__( 'Nenhuma execução ainda.', 'wp-anti-injection' ) . '</p>';
			return;
		}

		$summary = null;
		foreach ( $runs as $r ) {
			if ( isset( $r['run_id'] ) && $r['run_id'] === $run_id ) {
				$summary = $r;
				break;
			}
		}
		if ( $summary ) {
			printf(
				'<p><strong>%1$s</strong> · %2$s · %3$s UTC · linhas lidas: %4$d · itens: %5$d · limpos: %6$d · a limpar: %7$d · bloqueados: %8$d · conflitos: %9$d · allowlist: %10$d</p>',
				esc_html( $summary['run_id'] ),
				esc_html( 'clean' === $summary['mode'] ? 'limpar' : 'detectar' ),
				esc_html( $summary['started_at'] ),
				(int) $summary['rows_read'],
				(int) $summary['items'],
				(int) $summary['cleaned'],
				(int) $summary['would_clean'],
				(int) $summary['blocked'],
				(int) $summary['conflicts'],
				(int) $summary['allowlisted']
			);
		}

		$rows = WPAI_Store::run_findings( $run_id, 500, 0 );
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'Nenhum achado nesta execução.', 'wp-anti-injection' ) . '</p>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( 'Severidade', 'Alvo', 'Linha', 'Coluna', 'Contexto', 'Assinatura', 'Ação', 'Status', 'Caminho', 'Trecho', 'Quarentena' ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $r ) {
			echo '<tr>'
				. '<td>' . esc_html( $r['severity'] ) . '</td>'
				. '<td>' . esc_html( $r['target'] ) . '</td>'
				. '<td>' . (int) $r['row_id'] . '</td>'
				. '<td>' . esc_html( $r['column_name'] ) . '</td>'
				. '<td>' . esc_html( $r['context'] ) . '</td>'
				. '<td>' . esc_html( $r['signature'] ) . '</td>'
				. '<td>' . esc_html( $r['action'] ) . '</td>'
				. '<td>' . esc_html( $r['status'] ) . '</td>'
				. '<td><code>' . esc_html( $r['path'] ) . '</code></td>'
				. '<td><code>' . esc_html( $r['excerpt'] ) . '</code></td>'
				. '<td>' . ( $r['quarantine_id'] ? '#' . (int) $r['quarantine_id'] : '' ) . '</td>'
				. '</tr>';
		}
		echo '</tbody></table>';
	}

	/** Lista da quarentena com rollback por item. */
	private function render_quarantine() {
		echo '<h2>' . esc_html__( 'Quarentena', 'wp-anti-injection' ) . '</h2>';
		$items = WPAI_Store::quarantine_list( '', 100 );
		if ( empty( $items ) ) {
			echo '<p>' . esc_html__( 'Vazia.', 'wp-anti-injection' ) . '</p>';
			return;
		}
		$post = esc_url( admin_url( 'admin-post.php' ) );

		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( '#', 'Data (UTC)', 'Alvo', 'Linha', 'Coluna', 'Contexto', 'Assinaturas', 'Status', '' ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $items as $q ) {
			$id = (int) $q['id'];
			echo '<tr>'
				. '<td>' . $id . '</td>'
				. '<td>' . esc_html( $q['created_at'] ) . '</td>'
				. '<td>' . esc_html( $q['target'] ) . '</td>'
				. '<td>' . (int) $q['row_id'] . '</td>'
				. '<td>' . esc_html( $q['column_name'] ) . '</td>'
				. '<td>' . esc_html( $q['context'] ) . '</td>'
				. '<td>' . esc_html( $q['signatures'] ) . '</td>'
				. '<td>' . esc_html( $q['status'] ) . '</td><td>';
			if ( 'quarantined' === $q['status'] ) {
				echo '<form method="post" action="' . $post . '" style="margin:0">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				wp_nonce_field( 'wpai_restore_' . $id );
				echo '<input type="hidden" name="action" value="wpai_restore">';
				echo '<input type="hidden" name="quarantine_id" value="' . esc_attr( $id ) . '">';
				submit_button( __( 'Restaurar', 'wp-anti-injection' ), 'small', 'submit', false );
				echo '</form>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * Configurações.
	 *
	 * @param array $s Configurações atuais.
	 */
	private function render_settings( array $s ) {
		echo '<h2>' . esc_html__( 'Configurações', 'wp-anti-injection' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'wpai_settings' );
		echo '<input type="hidden" name="action" value="wpai_settings"><table class="form-table" role="presentation">';

		echo '<tr><th scope="row">' . esc_html__( 'Severidade mínima para remover', 'wp-anti-injection' ) . '</th><td><select name="wpai[threshold]">';
		foreach ( array_keys( WPAI_Signatures::SEVERITY ) as $sev ) {
			printf( '<option value="%1$s"%2$s>%1$s</option>', esc_attr( $sev ), selected( $s['threshold'], $sev, false ) );
		}
		echo '</select><p class="description">' . esc_html__( 'Abaixo do limiar o achado é só reportado.', 'wp-anti-injection' ) . '</p></td></tr>';

		echo '<tr><th scope="row">' . esc_html__( 'Assinaturas desativadas', 'wp-anti-injection' ) . '</th><td>';
		foreach ( WPAI_Signatures::all() as $id => $sig ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="wpai[disabled_signatures][]" value="%1$s"%2$s> <code>%1$s</code> (%3$s, %4$s) %5$s</label>',
				esc_attr( $id ),
				checked( in_array( $id, $s['disabled_signatures'], true ), true, false ),
				esc_html( $sig['scope'] ),
				esc_html( $sig['severity'] ),
				esc_html( $sig['label'] )
			);
		}
		echo '</td></tr>';

		$this->textarea_row( 'allow_options', __( 'Allowlist de option_name (um por linha, aceita *)', 'wp-anti-injection' ), $s['allow_options'] );
		$this->textarea_row( 'allow_post_ids', __( 'Allowlist de IDs de post', 'wp-anti-injection' ), $s['allow_post_ids'] );
		$this->textarea_row( 'trusted_hosts', __( 'Hosts confiáveis para <script src> (inclui subdomínios)', 'wp-anti-injection' ), $s['trusted_hosts'] );

		printf(
			'<tr><th scope="row">%1$s</th><td><input type="number" min="10" max="2000" name="wpai[batch_size]" value="%2$d"></td></tr>',
			esc_html__( 'Tamanho do lote', 'wp-anti-injection' ),
			(int) $s['batch_size']
		);

		echo '</table>';
		submit_button( __( 'Salvar configurações', 'wp-anti-injection' ) );
		echo '</form>';
	}

	/**
	 * @param string $key    Chave.
	 * @param string $label  Rótulo.
	 * @param array  $values Valores.
	 */
	private function textarea_row( $key, $label, array $values ) {
		printf(
			'<tr><th scope="row">%1$s</th><td><textarea name="wpai[%2$s]" rows="4" cols="50" class="large-text code">%3$s</textarea></td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			esc_textarea( implode( "\n", array_map( 'strval', $values ) ) )
		);
	}
}
