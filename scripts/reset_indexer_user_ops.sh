#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: reset_indexer_user_ops.sh [--db PATH] [--yes]

Clears indexer-managed user operation state (events, reverts, deployments,
sponsorships, cursors) from the SQLite database so the indexer can refetch
everything from scratch.

This is DESTRUCTIVE. All historical user operation records managed by the
indexer will be removed.

Options:
  --db PATH   Path to the SQLite database file. Defaults to SQLITE_DSN in .env
              (if present) or ./data/app.db.
  --yes       Skip confirmation prompt.
  -h, --help  Show this help message and exit.
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
SKIP_CONFIRM="false"

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
		--yes)
			SKIP_CONFIRM="true"
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

echo "Using database: ${DB_PATH}"
echo "The following tables will be truncated:"
echo "  - user_operation_events"
echo "  - user_operation_reverts"
echo "  - account_deployments"
echo "  - simple_account_initializations"
echo "  - sponsorships"
echo "  - log_cursors"

if [[ "${SKIP_CONFIRM}" != "true" ]]; then
	read -r -p "Proceed? (y/N) " reply
	if [[ ! "${reply}" =~ ^[Yy]$ ]]; then
		echo "Aborted."
		exit 0
	fi
fi

SQL=$(cat <<'EOF'
PRAGMA foreign_keys = ON;
BEGIN TRANSACTION;
DELETE FROM user_operation_events;
DELETE FROM user_operation_reverts;
DELETE FROM account_deployments;
DELETE FROM simple_account_initializations;
DELETE FROM sponsorships;
DELETE FROM log_cursors;
COMMIT;
VACUUM;
EOF
)

sqlite3 "${DB_PATH}" "${SQL}"

echo "Indexer user operation data cleared."
