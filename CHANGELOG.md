# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versionamento semântico.

## [2.0.0] - 2026-10-30

Reescrita completa. Nenhum código das versões 1.x foi reaproveitado.

### Adicionado
- Modo **detectar** (padrão, somente leitura) separado do modo **limpar**.
- Confirmação explícita para limpar: caixa + palavra `LIMPAR` no painel, `--yes` no WP-CLI.
- Tabela `{prefix}wpai_quarantine` (criada via `dbDelta` na ativação) com o valor original de cada célula alterada e **rollback por item**.
- Tabela `{prefix}wpai_log` com os achados de cada execução (últimas 20 execuções mantidas).
- Limpeza **ciente de serialização**: desserializa, percorre arrays/`stdClass` recursivamente (incluindo dupla serialização), limpa strings e re-serializa só se algo mudou.
- `unserialize` com `allowed_classes => ['stdClass']`; objetos de outras classes, referências `R:`, serializados corrompidos e JSON são apenas reportados.
- Assinaturas com severidade: `<script>` externo, `eval(`, redirecionamento por `location`, ClickFix (`clipboard.writeText` + `powershell`), falso captcha (`Win + R`), `String.fromCharCode`, `atob`/`unescape`, ofuscação `\xNN`, `<iframe>` oculto, `eval(base64_decode(`, `base64_decode(`, `<meta refresh>`.
- Limiar de severidade configurável; desativação de assinaturas; filtro `wpai_signatures` com validação.
- Allowlist por `option_name` (curinga `*`), ID de post e host confiável de `<script src>`.
- Novos alvos: widgets (separados de options) e usermeta/comments com PK correta.
- Paginação por **keyset** com pré-filtro `LIKE` e lotes configuráveis.
- `UPDATE` condicional (`MD5(col) = hash lido`) para não sobrescrever edições concorrentes.
- Invalidação de object cache após alterações e restaurações.
- WP-CLI: `scan`, `clean`, `restore`, `quarantine`, `signatures` com `--format=table|json|csv`.
- Suporte a multisite (ativação de rede e novos sites).
- `uninstall.php` remove tabelas e opções.
- Testes sem dependências (`php tests/run.php`).

### Corrigido (em relação às 1.x)
- CSRF: ações sem nonce.
- Corrupção de dados serializados por `str_ireplace`/`preg_replace` direto no valor.
- Remoção de qualquer `<script>`, inclusive legítimo.
- `SELECT *` em tabelas inteiras.
- `UPDATE` em options usando a coluna inexistente `ID`.
- Registros pulados por `OFFSET` enquanto as linhas eram alteradas.
- Log público em `wp-content/wpais-log.txt`.
- Ausência de dry-run e de backup.

### Removido
- Arquivo de log em disco.

## [1.1.0]

Versão "Safer": nonce e lotes, mas ainda com `preg_replace` direto em `option_value`, remoção de qualquer `<script>`, paginação por `OFFSET` e log em arquivo público. Descontinuada.

## [1.0.0]

Versões "Basic" e "Advanced": varredura e substituição por `str_ireplace` em todas as colunas, sem nonce, sem backup. Descontinuadas.
