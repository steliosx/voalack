#!/bin/sh
# Provision a disposable guest for T03b: PostgreSQL 18 (PGDG) and Alerta 9.1.0 in a venv.
# Synthetic data only; nothing listens beyond localhost.
#   WORK  scratch directory (default /work)
set -eu
WORK="${WORK:-/work}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg lsb-release >/dev/null
install -d /usr/share/postgresql-common/pgdg
curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq
apt-get install -y -qq --no-install-recommends postgresql-18 >/dev/null
pg_ctlcluster 18 main start
su postgres -c "psql -q -c \"CREATE ROLE alerta LOGIN PASSWORD 'lab-only-synthetic'\""
# The database is owned by a separate role, not by Alerta's runtime login (review: M2 topology).
su postgres -c "psql -q -c \"CREATE ROLE alerta_dbowner NOLOGIN\""
su postgres -c "createdb -O alerta_dbowner alerta"
su postgres -c "psql -q alerta -c 'GRANT CREATE, USAGE ON SCHEMA public TO alerta'"
# Lab roles (design "Database ownership and privacy"). alerta is Alerta's runtime login and owns
# Alerta's own tables (Alerta 9.1.0 alters its schema at startup and fails without ownership);
# it is not a superuser. voalack_admin (no login) owns the voalack schema, tables and functions.
# voalack_app (no login) holds only the grants the capture path needs; alerta is a member of it,
# never of voalack_admin. lab_admin is a lab-only superuser for fixtures and observation.
su postgres -c "psql -q" <<'SQL'
CREATE ROLE lab_admin LOGIN SUPERUSER PASSWORD 'lab-only-admin';
CREATE ROLE voalack_admin NOLOGIN;
-- coexistence 3a S3: owner of the voalack_guard schema (DDL protector and permits); no login, no members.
CREATE ROLE voalack_guard_owner NOLOGIN;
-- coexistence 3a S3b recovery prerequisite (operator-provisioned; checked by open_window): the protector reads the
-- registered coordinator's exact backend start from pg_stat_activity.
GRANT pg_read_all_stats TO voalack_guard_owner;
CREATE ROLE voalack_app NOLOGIN;
GRANT voalack_app TO alerta;
CREATE ROLE voalack_verifier NOLOGIN;
CREATE ROLE lab_verifier LOGIN PASSWORD 'lab-only-verifier' IN ROLE voalack_verifier;
CREATE ROLE voalack_sender NOLOGIN;
CREATE ROLE lab_sender LOGIN PASSWORD 'lab-only-sender' IN ROLE voalack_sender;
CREATE ROLE voalack_settler NOLOGIN;
CREATE ROLE lab_settler LOGIN PASSWORD 'lab-only-settler' IN ROLE voalack_settler;
CREATE ROLE voalack_projector NOLOGIN;
CREATE ROLE lab_projector LOGIN PASSWORD 'lab-only-projector' IN ROLE voalack_projector;
SQL
su postgres -c "psql -At -c 'SELECT version()'"
python3 -m venv "$WORK/venv"
# Dependencies resolve only to the reviewed setup profile (lab/profiles); the venv keeps the image's bundled pip
# (no upgrade), whose version is recorded and asserted. A mismatch stops provisioning before any test runs.
LAB=$(dirname "$0")
"$WORK/venv/bin/pip" --version > "${OUT:-/tmp}/pip-version.txt"
grep -q '^pip 25\.0\.1 ' "${OUT:-/tmp}/pip-version.txt" || { echo "venv pip is not 25.0.1"; exit 1; }
"$WORK/venv/bin/pip" install -q -c "$LAB/profiles/qualified-setup.txt" \
  "alerta-server==9.1.0" "psycopg2-binary==2.9.10" "pytest==9.0.3"
"$WORK/venv/bin/pip" freeze > "${OUT:-/tmp}/pip-freeze-lab.txt"
python3 -I "$LAB/check_profile.py" "$LAB/profiles/qualified-setup.txt" "${OUT:-/tmp}/pip-freeze-lab.txt" \
  "${OUT:-/tmp}/profile-check-setup.txt"
