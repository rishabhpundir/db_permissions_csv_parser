import csv
import uuid
import time
import pytest
import logging
import psycopg2
from pathlib import Path
from argparse import Namespace

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Import the functions to be tested from the user_creation_basic.py script
from postgres_Latest import (
    load_parameters,
    create_user,
    create_role,
    create_schema,
    alter_database_owner,
    grant_role_to_user,
    grant_role_cr,
    grant_role_ro,
    grant_role_rw,
    grant_role_tr,
    main
)

# Import PostgreSQL container from testcontainers library
from testcontainers.postgres import PostgresContainer


######################################
# FIXTURES FOR TESTS
######################################

@pytest.fixture(autouse=True)
def set_pgpassword(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "mysecretpassword")
    logging.info("Set environment variable PGPASSWORD = mysecretpassword")


@pytest.fixture(scope="session")
def postgres_container():
    """
    A fixture that starts a container with PostgreSQL.
    It uses the 'postgres:14' image with the following parameters:
    - username: 'postgres'
    - password: 'mysecretpassword'
    - dbname: 'test_db'
    The container is stopped at the end of the test session.
    """
    logging.info("Starting PostgreSQL container with image postgres:14")
    with PostgresContainer("postgres:14",
                           username="postgres",
                           password="mysecretpassword",
                           dbname="test_db") as postgres:
        logging.info("Waiting for container to be ready...")
        time.sleep(10)  # Ждём 10 секунд для инициализации
        logging.info("Container is ready.")
        yield postgres


@pytest.fixture(scope="module")
def db_conn(postgres_container):
    """
    A fixture for establishing a connection to a database running in a container.
    """
    conn_url = postgres_container.get_connection_url().replace("+psycopg2", "")
    logging.info(f"Connecting to database using DSN: {conn_url}")
    conn = psycopg2.connect(conn_url)
    conn.autocommit = True
    yield conn
    logging.info("Closing database connection.")
    conn.close()


@pytest.fixture
def cursor(db_conn):
    """
    A fixture that provides a cursor for executing SQL queries.
    """
    cur = db_conn.cursor()
    yield cur
    cur.close()


@pytest.fixture
def temp_csv_file(tmp_path: Path):
    """
    A fixture that creates a temporary CSV file with parameters for the main() function.
    """
    params = [
        ("user", "role"),
        ("user_owner", "postgres"),
        ("another_users", "test_user_main2,test_user_main"),
        ("role_list", "test_role_main"),
        ("role_cr", "test_role_cr_main"),
        ("role_ro", "test_role_ro_main"),
        ("role_rw", "test_role_rw_main"),
        ("role_tr", "test_role_tr_main"),
        ("users_to_receive_role_ro", "test_user_main"),
        ("users_to_receive_role_rw", "test_user_main2"),
        ("users_to_receive_role_tr", "test_user_main"),
        ("users_to_receive_role_cr", "test_user_main2"),
        ("schema_list", "test_schema_main"),
        ("schema_cr_list", "test_schema_main"),
        ("schema_ro_list", "test_schema_main"),
        ("schema_rw_list", "test_schema_main"),
        ("schema_tr_list", "test_schema_main")
    ]
    file_path = tmp_path / "params.csv"
    with file_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        for key, value in params:
            writer.writerow([key, value])
    logging.info(f"Temporary CSV file created at {file_path} with parameters: {params}")
    return file_path


########################################
# TESTS FOR INDIVIDUAL FUNCTIONS
#########################################
def test_load_parameters(temp_csv_file):
    """
    Test for the load_parameters function.
    The test checks:
    1. Old format (dictionary output)
    2. New format (list of tuples output)
    3. Empty cases (ensuring {} or [] is returned correctly)
    """
    logging.info("Starting test_load_parameters")

    # Test Case 1: Old Format (Dictionary Output)
    test_data_old = [
        ["user_owner", "admin"],
        ["role_list", "role1, role2"],
        ["schema_list", "schema1"],
    ]
    with temp_csv_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(test_data_old)

    params = load_parameters(str(temp_csv_file))
    expected = {
        "role_list": ["role1", "role2"],
        "schema_list": ["schema1"]
    }
    logging.info(f"Old Format - Loaded parameters: {params}, expected: {expected}")
    assert params == expected, "Failed old format test"

    # Test Case 2: New Format (List of Tuples Output)
    test_data_new = [
        ["permissions", "tables", "role"],
        ["select", "table1, table2", "role_reader"],
        ["update", "table3", "role_writer"],
    ]
    with temp_csv_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(test_data_new)

    params = load_parameters(str(temp_csv_file))
    expected = [
        ("select", ["table1", "table2"], "role_reader"),
        ("update", ["table3"], "role_writer"),
    ]
    logging.info(f"New Format - Loaded parameters: {params}, expected: {expected}")
    assert params == expected, "Failed new format test"
    logging.info("test_load_parameters completed successfully!")



def test_create_user(cursor):
    """
    Test for create_user function.
    A unique user is created, its existence is checked, then it is deleted.
    """
    test_user = "test_user_" + uuid.uuid4().hex[:8]
    logging.info(f"Starting test_create_user: creating user {test_user}")
    try:
        create_user(cursor, test_user)
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (test_user,))
        result = cursor.fetchone()
        logging.info(f"User {test_user} creation result: {result}")
        assert result is not None
    finally:
        logging.info(f"Dropping user {test_user}")
        cursor.execute(f"DROP USER IF EXISTS {test_user};")


def test_create_role(cursor):
    """
    Test for create_role function.
    Creates a unique role, checks if it exists, then deletes it.
    """
    test_role = "test_role_" + uuid.uuid4().hex[:8]
    logging.info(f"Starting test_create_role: creating role {test_role}")
    try:
        create_role(cursor, test_role)
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (test_role,))
        result = cursor.fetchone()
        logging.info(f"Role {test_role} creation result: {result}")
        assert result is not None
    finally:
        logging.info(f"Dropping role {test_role}")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


def test_create_schema(cursor):
    """
    Test for create_schema function.
    Creates temporary schema with owner 'postgres', checks for its existence, then deletes the schema.
    """
    test_schema = "test_schema_" + uuid.uuid4().hex[:8]
    owner = "postgres"
    logging.info(f"Starting test_create_schema: creating schema {test_schema} with owner {owner}")
    try:
        create_schema(cursor, test_schema, owner)
        cursor.execute("SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s", (test_schema,))
        result = cursor.fetchone()
        logging.info(f"Schema {test_schema} creation result: {result}")
        assert result is not None
    finally:
        logging.info(f"Dropping schema {test_schema}")
        cursor.execute(f"DROP SCHEMA IF EXISTS {test_schema} CASCADE;")


def test_alter_database_owner(cursor, db_conn):
    """
    Test for the alter_database_owner function.
    A temporary role is created, then the database owner is changed and the change is checked.
    After the test, the database owner is restored.
    """
    # Get the name of the current database
    cursor.execute("SELECT current_database();")
    dbname = cursor.fetchone()[0]
    # Get the current owner of the database
    cursor.execute("SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (dbname,))
    original_owner = cursor.fetchone()[0]
    temp_owner = "temp_owner_" + uuid.uuid4().hex[:8]
    try:
        create_role(cursor, temp_owner)
        alter_database_owner(cursor, dbname, temp_owner)
        cursor.execute("SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (dbname,))
        new_owner = cursor.fetchone()[0]
        logging.info(f"Database owner changed from {original_owner} to {new_owner}")
        assert new_owner == temp_owner
    finally:
        # Restore the original owner
        alter_database_owner(cursor, dbname, original_owner)
        cursor.execute(f"DROP ROLE IF EXISTS {temp_owner};")


def test_grant_role_to_user(cursor):
    """
    Test for grant_role_to_user function.
    A temporary role and user are created, then GRANT is performed and role membership is checked.
    """
    test_role = "test_role_" + uuid.uuid4().hex[:8]
    test_user = "test_user_" + uuid.uuid4().hex[:8]
    try:
        create_role(cursor, test_role)
        create_user(cursor, test_user)
        grant_role_to_user(cursor, test_role, test_user)
        cursor.execute("""
            SELECT 1 FROM pg_auth_members 
            WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)
            AND member = (SELECT oid FROM pg_roles WHERE rolname = %s)
        """, (test_role, test_user))
        result = cursor.fetchone()
        logging.info(f"Granting role {test_role} to user {test_user} result: {result}")
        assert result is not None
    finally:
        cursor.execute(f"DROP USER IF EXISTS {test_user};")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


def test_grant_role_cr(cursor):
    """
    Test for grant_role_cr function.
    A temporary schema and role are created, then GRANT CREATE is executed and the presence of this privilege is checked via has_schema_privilege.
    """
    test_schema = "test_schema_" + uuid.uuid4().hex[:8]
    test_role = "test_role_cr_" + uuid.uuid4().hex[:8]
    owner = "postgres"
    try:
        create_schema(cursor, test_schema, owner)
        create_role(cursor, test_role)
        grant_role_cr(cursor, [test_schema], test_role)
        cursor.execute("SELECT has_schema_privilege(%s, %s, 'CREATE');", (test_role, test_schema))
        has_create = cursor.fetchone()[0]
        logging.info(f"Role {test_role} has CREATE privilege on schema {test_schema}: {has_create}")
        assert has_create
    finally:
        cursor.execute(f"DROP SCHEMA IF EXISTS {test_schema} CASCADE;")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


def test_grant_role_ro(cursor):
    """
    Test for grant_role_ro_sequences function.
    Creates temporary schema and sequence, then GRANT USAGE and SELECT,
    then checks for those privileges using has_sequence_privilege.
    """
    test_schema = "test_schema_" + uuid.uuid4().hex[:8]
    test_role = "test_role_ro_" + uuid.uuid4().hex[:8]
    owner = "postgres"
    try:
        create_schema(cursor, test_schema, owner)
        create_role(cursor, test_role)
        # CREATE SEQUENCE and TABLE
        cursor.execute(f"CREATE TABLE {test_schema}.test_table (id SERIAL PRIMARY KEY, name TEXT);")
        cursor.execute(f"CREATE SEQUENCE {test_schema}.test_seq;")
        grant_role_ro(cursor, [test_schema], test_role)
        cursor.execute("SELECT has_table_privilege(%s, %s, 'SELECT');", (test_role, f"{test_schema}.test_table"))
        has_select = cursor.fetchone()[0]
        logging.info(f"Role {test_role} privileges on table {test_schema}.test_table: SELECT={has_select}")
        cursor.execute("SELECT has_sequence_privilege(%s, %s, 'USAGE');", (test_role, f"{test_schema}.test_seq"))
        has_usage = cursor.fetchone()[0]
        cursor.execute("SELECT has_sequence_privilege(%s, %s, 'SELECT');", (test_role, f"{test_schema}.test_seq"))
        has_select = cursor.fetchone()[0]
        logging.info(f"Role {test_role} privileges on sequence {test_schema}.test_seq: USAGE={has_usage}, SELECT={has_select}")
        assert has_usage and has_select
    finally:
        cursor.execute(f"DROP SCHEMA IF EXISTS {test_schema} CASCADE;")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


def test_grant_role_rw(cursor):
    """
    Test for the grant_role_rw_tables function.
    A temporary schema and table are created, then GRANT privileges are performed on the table,
    after which the presence of SELECT, INSERT, UPDATE, DELETE privileges is checked via has_table_privilege.
    """
    test_schema = "test_schema_" + uuid.uuid4().hex[:8]
    test_role = "test_role_rw_" + uuid.uuid4().hex[:8]
    owner = "postgres"
    try:
        create_schema(cursor, test_schema, owner)
        create_role(cursor, test_role)
        cursor.execute(f"CREATE TABLE {test_schema}.test_table (id SERIAL PRIMARY KEY, name TEXT);")
        cursor.execute(f"CREATE SEQUENCE {test_schema}.test_seq;")
        grant_role_rw(cursor, [test_schema], test_role)
        cursor.execute("SELECT has_table_privilege(%s, %s, 'SELECT');", (test_role, f"{test_schema}.test_table"))
        has_select = cursor.fetchone()[0]
        cursor.execute("SELECT has_table_privilege(%s, %s, 'INSERT');", (test_role, f"{test_schema}.test_table"))
        has_insert = cursor.fetchone()[0]
        cursor.execute("SELECT has_table_privilege(%s, %s, 'UPDATE');", (test_role, f"{test_schema}.test_table"))
        has_update = cursor.fetchone()[0]
        cursor.execute("SELECT has_table_privilege(%s, %s, 'DELETE');", (test_role, f"{test_schema}.test_table"))
        has_delete = cursor.fetchone()[0]
        cursor.execute("SELECT has_sequence_privilege(%s, %s, 'USAGE');", (test_role, f"{test_schema}.test_seq"))
        has_usage = cursor.fetchone()[0]
        cursor.execute("SELECT has_sequence_privilege(%s, %s, 'SELECT');", (test_role, f"{test_schema}.test_seq"))
        has_select = cursor.fetchone()[0]
        cursor.execute("SELECT has_sequence_privilege(%s, %s, 'UPDATE');", (test_role, f"{test_schema}.test_seq"))
        has_update = cursor.fetchone()[0]
        logging.info(f"Role {test_role} privileges on table {test_schema}.test_table: SELECT={has_select}, INSERT={has_insert}, UPDATE={has_update}, DELETE={has_delete}")
        assert all([has_select, has_insert, has_update, has_delete, has_usage])
    finally:
        cursor.execute(f"DROP SCHEMA IF EXISTS {test_schema} CASCADE;")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


def test_grant_role_tr(cursor):
    """
    Test for grant_role_tr function.
    Creates temporary schema and table, then GRANTs TRUNCATE privilege,
    then checks for presence of this privilege via has_table_privilege.
    """
    test_schema = "test_schema_" + uuid.uuid4().hex[:8]
    test_role = "test_role_tr_" + uuid.uuid4().hex[:8]
    owner = "postgres"
    try:
        create_schema(cursor, test_schema, owner)
        create_role(cursor, test_role)
        cursor.execute(f"CREATE TABLE {test_schema}.test_table (id SERIAL PRIMARY KEY, name TEXT);")
        grant_role_tr(cursor, [test_schema], test_role)
        cursor.execute("SELECT has_table_privilege(%s, %s, 'TRUNCATE');", (test_role, f"{test_schema}.test_table"))
        has_truncate = cursor.fetchone()[0]
        logging.info(f"Role {test_role} TRUNCATE privilege on table {test_schema}.test_table: {has_truncate}")
        assert has_truncate
    finally:
        cursor.execute(f"DROP SCHEMA IF EXISTS {test_schema} CASCADE;")
        cursor.execute(f"DROP ROLE IF EXISTS {test_role};")


#########################################
# INTEGRATION TEST FOR main()
#########################################

def test_main(monkeypatch, temp_csv_file, db_conn):
    """
    Integration test for the main() function.
    The command line is emulated using monkeypatch, after which main() is executed.
    It is checked that the created users, roles, schema and privileges match the parameters from the CSV file.
    """
    import sys
    # Extracting connection parameters from the connection object
    dsn_parts = dict(item.split("=") for item in db_conn.dsn.split())
    host = dsn_parts.get("host", "localhost")
    port = dsn_parts.get("port", "5432")
    dbname = dsn_parts.get("dbname", "test_db")
    user = dsn_parts.get("user", "postgres")

    monkeypatch.setattr(sys, 'argv', [
        "script_name",
        "--host", host,
        "--port", port,
        "-U", user,
        "-d", dbname,
        "--parameter_file", str(temp_csv_file)
    ])

    # Running main()
    args = Namespace(
        host=host,
        port=port,
        username=user,
        dbname=dbname,
        parameter_file=str(temp_csv_file),
        task="create_users",  # Set an appropriate task (or read from test parameters)
        useDatadog="Disabled"  # Adjust based on test conditions
    )

    # Running main() with arguments
    main(args)

    # We check that the main objects are created in the database according to the parameters from the CSV
    cursor = db_conn.cursor()
    try:
        # Checking users
        for u in ["test_user_main", "test_user_main2"]:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (u,))
            assert cursor.fetchone() is not None

        # Checking roles
        for r in ["test_role_main", "test_role_cr_main", "test_role_ro_main", "test_role_rw_main", "test_role_tr_main"]:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (r,))
            assert cursor.fetchone() is not None

        # Checking schemas
        cursor.execute("SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s", ("test_schema_main",))
        assert cursor.fetchone() is not None

        # Check that the privilege has been granted (e.g. role test_role_ro_main granted to user test_user_main)
        cursor.execute("""
            SELECT 1 FROM pg_auth_members
            WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)
            AND member = (SELECT oid FROM pg_roles WHERE rolname = %s)
        """, ("test_role_ro_main", "test_user_main"))
        assert cursor.fetchone() is not None

    finally:
        cursor.close()
