#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: show_indexer_tables.sh [--db PATH] [--limit N]

Displays snapshot views of the indexer-related SQLite tables (user operations,
reverts, deployments, sponsorships, cursors, etc).

Options:
  --db PATH     Path to the SQLite database file. Defaults to the value of
                SQLITE_DSN in .env (if present) or ./data/app.db.
  --limit N     Number of rows to display per table (default: 10).
  -h, --help    Show this help message and exit.
EOF
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Error: required command '$1' not found in PATH" >&2
		exit 1
	fi
}

extract_env_value() {
	local key="$1"
	if [[ -f "${ROOT_DIR}/.env" ]]; then
		grep -E "^${key}=" "${ROOT_DIR}/.env" | tail -n1 | cut -d= -f2-
	fi
}

DB_PATH=""
ROW_LIMIT=10

while [[ $# -gt 0 ]]; do
	case "$1" in
		--db)
			shift
			if [[ $# -eq 0 ]]; then
				echo "Error: --db requires a value" >&2
				exit 1
			fi
			DB_PATH="$1"
			;;
		--limit)
			shift
			if [[ $# -eq 0 ]]; then
				echo "Error: --limit requires a value" >&2
				exit 1
			fi
			if ! [[ "$1" =~ ^[0-9]+$ ]]; then
				echo "Error: --limit expects a positive integer" >&2
				exit 1
			fi
			ROW_LIMIT="$1"
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Error: unknown option '$1'" >&2
			usage
			exit 1
			;;
	esac
	shift
done

if [[ -z "${DB_PATH}" ]]; then
	DB_PATH="$(extract_env_value "SQLITE_DSN")"
fi
if [[ -z "${DB_PATH}" ]]; then
	DB_PATH="${ROOT_DIR}/data/app.db"
elif [[ "${DB_PATH}" != /* ]]; then
	DB_PATH="${ROOT_DIR}/${DB_PATH}"
fi

if [[ ! -f "${DB_PATH}" ]]; then
	echo "Error: SQLite database not found at '${DB_PATH}'" >&2
	exit 1
fi

require_cmd sqlite3

run_query() {
	local title="$1"
	local sql="$2"
	echo
	echo "=== ${title} (limit ${ROW_LIMIT}) ==="
	sqlite3 -readonly -header -column "${DB_PATH}" "${sql} LIMIT ${ROW_LIMIT};"
}

echo "Using database: ${DB_PATH}"

run_query "user_operation_events" \
	"SELECT * FROM user_operation_events ORDER BY block_number DESC, log_index DESC"

run_query "user_operation_reverts" \
	"SELECT * FROM user_operation_reverts ORDER BY block_number DESC, log_index DESC"

run_query "account_deployments" \
	"SELECT * FROM account_deployments ORDER BY block_number DESC, log_index DESC"

run_query "simple_account_initializations" \
	"SELECT * FROM simple_account_initializations ORDER BY block_number DESC, log_index DESC"

run_query "sponsorships" \
	"SELECT * FROM sponsorships ORDER BY block_number DESC, log_index DESC"

run_query "user_operation_traces" \
	"SELECT * FROM user_operation_traces ORDER BY id DESC"

run_query "nft_tokens" \
	"SELECT * FROM nft_tokens ORDER BY contract, token_id"

run_query "log_cursors" \
	"SELECT * FROM log_cursors ORDER BY chain_id, address"
