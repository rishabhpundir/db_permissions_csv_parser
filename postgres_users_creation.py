import argparse
import psycopg2
import csv
import logging

# Configure logging with a specific format and set the log level to INFO
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_parameters(csv_file_path):
    """
    Load parameters from a CSV file into a structured format.
    Supports two formats:
    1. Old Format (Key-Value): { "key": ["value1", "value2"] }
    2. New Format (Permissions, Tables, Roles): [("permission_type", ["table1", "table2"], "role")]

    Returns:
        - Dictionary for old format
        - List of tuples for new format
    """
    parameters = {}
    structured_data = []
    try:
        with open(csv_file_path, "r", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            header = next(reader, None)  # Read header if exists

            for row in reader:
                if len(row) < 2:  # Skip invalid rows
                    continue

                key = row[0].strip().lower()
                values = row[1:]

                if len(values) == 1:  # Old format (single value or comma-separated)
                    value = values[0].strip()
                    if "," in value:
                        parameters[key] = [v.strip() for v in value.split(",") if v.strip()]
                    else:
                        parameters[key] = [value]
                else:  # New format (permissions, tables, roles)
                    permission_type = key  # First column as permission type
                    tables = [table.strip() for table in values[:-1] if table.strip()]  # Middle columns as tables
                    role = values[-1].strip()  # Last column as role

                    structured_data.append((permission_type, tables, role))
        logging.info("Loaded parameters successfully.")
        return parameters if parameters else structured_data
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        return {} if parameters else []
    
    
def grant_full_permissions(cursor, role, tables):
    """ Grants SELECT, INSERT, UPDATE, DELETE permissions on tables. """
    queries = [f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table.strip()} TO {role};" for table in tables]
    for query in queries:
        logging.info("executing %s...", query)
        cursor.execute(query)


def grant_select_usage_permissions(cursor, role, tables):
    """ Grants SELECT and USAGE permissions (for schemas or sequences). """
    queries = [f"GRANT SELECT, USAGE ON {table.strip()} TO {role};" for table in tables]
    for query in queries:
        logging.info("executing %s...", query)
        cursor.execute(query)


def grant_select_permissions(cursor, role, tables):
    """ Grants only SELECT permission on tables. """
    queries = [f"GRANT SELECT ON {table.strip()} TO {role};" for table in tables]
    for query in queries:
        logging.info("executing %s...", query)
        cursor.execute(query)


def process_grants(cursor, grant_parameters):
    """
    Execute grant queries based on the structured grant parameters loaded from CSV.

    The `grant_parameters` should be a list of dictionaries when a 'role' column exists,
    each containing:
    - permissions: The type of access to grant (e.g., 'select', 'insert', 'update', etc.).
    - tables: A list of tables on which the permissions will be applied.
    - role: The role to which the permissions will be granted.

    If `grant_parameters` is a dictionary (old format), it will log a message and return.
    """

    # Ensure we are working with structured grant data
    if isinstance(grant_parameters, dict):
        logging.error("Grant parameters are not in structured format. Skipping grants execution.")
        return

    # Loop through each row in structured grant parameters
    if isinstance(grant_parameters, list):
        for row in grant_parameters:
            permission_parts = row[0].split('_')
            tables = row[1][0].split(',')
            role = row[2]
            if 'full' in permission_parts:
                grant_full_permissions(cursor, role, tables)
            elif 'select' in permission_parts and 'usage' in permission_parts:
                grant_select_usage_permissions(cursor, role, tables)
            elif 'select' in permission_parts:
                grant_select_permissions(cursor, role, tables)
    logging.info(f"Total {len(grant_parameters)} grant statements executed successfully.")
    

def create_database(cursor_postgres,args):
    """
    Check if the database exists, and create it if it doesn't.
    """
    logging.info("Checking for database %s on server %s", args.dbname, args.host)
    try:
        cursor_postgres.execute("SELECT 1 FROM pg_database WHERE datname = %s", (args.dbname,))
        if cursor_postgres.fetchone():
            logging.info("Database %s already exists", args.dbname)
        else:
            logging.info("Creating database %s", args.dbname)
            cursor_postgres.execute(f"CREATE DATABASE {args.dbname};")
    except Exception as e:
        logging.error("Error checking or creating database: %s", e)


def create_datadog_role(cursor, cursor_postgres, args):
    """
    Function to create Datadog role and assign required permissions.
    """
    logging.info("Checking if 'datadog' user exists...")
    cursor_postgres.execute("SELECT 1 FROM pg_user WHERE usename = 'datadog';")
    if cursor_postgres.fetchone() is None:
        logging.info("Creating 'datadog' user...")
        cursor_postgres.execute("CREATE USER datadog;")
    else:
        logging.info("User 'datadog' already exists.")

    # Enable pg_stat_statements in the postgres database
    logging.info("Creating EXTENSION pg_stat_statements in postgres database")
    cursor_postgres.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements;")

    # Enable pg_stat_statements in the application database
    logging.info(f"Creating EXTENSION pg_stat_statements in {args.dbname} database")
    cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements;")

    # Grant permissions and set up Datadog schema
    logging.info("Granting permissions to Datadog user...")
    cursor.execute(f"GRANT datadog TO {args.username};")
    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS datadog;")
    cursor.execute(f"GRANT USAGE ON SCHEMA datadog TO datadog;")
    cursor.execute(f"GRANT USAGE ON SCHEMA public TO datadog;")
    cursor.execute(f"GRANT pg_monitor TO datadog;")
    cursor.execute(f"GRANT CONNECT ON DATABASE {args.dbname} TO datadog;")

    # Create or replace function for Datadog
    cursor.execute("""
        CREATE OR REPLACE FUNCTION datadog.explain_statement(
            l_query TEXT,
            OUT explain JSON
        )
        RETURNS SETOF JSON AS
        $$
        DECLARE
            curs REFCURSOR;
            plan JSON;
        BEGIN
            OPEN curs FOR EXECUTE pg_catalog.concat('EXPLAIN (FORMAT JSON) ', l_query);
            FETCH curs INTO plan;
            CLOSE curs;
            RETURN QUERY SELECT plan;
        END;
        $$
        LANGUAGE 'plpgsql'
        RETURNS NULL ON NULL INPUT
        SECURITY DEFINER;
    """)

    logging.info("Datadog role setup completed successfully.")

def create_user(cursor, user):
    """
    Create a PostgreSQL user if it does not already exist.

    Checks the pg_roles catalog to see if the user exists, and if not, creates the user.
    """
    if not user:
        return
    # Check if user already exists
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (user,))
    if cursor.fetchone():
        logging.info("User %s already exists. Skipping.", user)
    else:
        logging.info("Creating user %s...", user)
        # Create the user
        cursor.execute(f"CREATE USER {user};")

def create_role(cursor, role):
    """
    Create a PostgreSQL role if it does not already exist.

    Checks the pg_roles catalog to see if the role exists, and if not, creates the role.
    """
    if not role:
        return
    # Check if role already exists
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
    if cursor.fetchone():
        logging.info("Role %s already exists. Skipping.", role)
    else:
        logging.info("Creating role %s...", role)
        # Create the role
        cursor.execute(f"CREATE ROLE {role};")

def create_schema(cursor, schema, owner):
    """
    Create a database schema if it does not already exist.

    The schema is created with the specified owner.
    """
    # Check if the schema already exists in the database
    cursor.execute("SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s", (schema,))
    if cursor.fetchone():
        logging.info("Schema %s already exists. Skipping.", schema)
    else:
        logging.info("Creating schema %s with owner %s...", schema, owner)
        # Create the schema with the given owner
        cursor.execute(f"CREATE SCHEMA {schema} AUTHORIZATION {owner};")

def alter_database_owner(cursor, database, owner):
    # Determine the current user of the session
    cursor.execute("SELECT session_user;")
    session_user = cursor.fetchone()[0]

    # If the current user does not match the owner, we execute GRANT
    if session_user != owner:
        logging.info("Granting access %s to session user.", database)
        cursor.execute(f"GRANT {owner} TO SESSION_USER;")

    logging.info("Setting owner of database %s to %s...", database, owner)
    cursor.execute(f"ALTER DATABASE {database} OWNER TO {owner};")

def is_role_assigned(cursor, role, user):
    """
    Check if a user already has a specific role.
    """
    cursor.execute("""
        SELECT 1 FROM pg_roles r
        JOIN pg_auth_members m ON r.oid = m.roleid
        JOIN pg_roles u ON m.member = u.oid
        WHERE r.rolname = %s AND u.rolname = %s
    """, (role, user))
    return cursor.fetchone() is not None

def grant_role_to_user(cursor, role, user):
    """
    Grant a specific role to a user if it is not already assigned.
    """
    if role and user:
        if is_role_assigned(cursor, role, user):
            logging.info("Role %s is already assigned to user %s. Skipping.", role, user)
        else:
            logging.info("Granting role %s to user %s...", role, user)
            cursor.execute(f"GRANT {role} TO {user};")

def grant_usage_on_schema(cursor, schema, role):
    logging.info("Granting USAGE on schema %s to %s...", schema, role)
    cursor.execute(f"GRANT USAGE ON SCHEMA {schema} TO {role};")

def grant_usage_on_sequence(cursor, schema, role):
    logging.info("Granting USAGE on all sequences in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT USAGE ON SEQUENCES TO {role};")

def grant_create_on_schema(cursor, schema, role):
    logging.info("Granting CREATE on schema %s to %s...", schema, role)
    cursor.execute(f"GRANT CREATE ON SCHEMA {schema} TO {role};")

def grant_select_on_tables(cursor, schema, role):
    logging.info("Granting SELECT on all tables in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT SELECT ON TABLES TO {role};")

def grant_select_on_sequences(cursor, schema, role):
    logging.info("Granting SELECT on all sequences in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT SELECT ON SEQUENCES TO {role};")

def grant_insert_update_delete_on_tables(cursor, schema, role):
    logging.info("Granting INSERT, UPDATE, DELETE on all tables in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT INSERT, UPDATE, DELETE ON TABLES TO {role};")

def grant_update_on_sequences(cursor, schema, role):
    logging.info("Granting UPDATE on all sequences in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT UPDATE ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT UPDATE ON SEQUENCES TO {role};")

def grant_truncate_on_tables(cursor, schema, role):
    logging.info("Granting TRUNCATE on all tables in schema %s to %s...", schema, role)
    cursor.execute(f"GRANT TRUNCATE ON ALL TABLES IN SCHEMA {schema} TO {role};")
    cursor.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT TRUNCATE ON TABLES TO {role};")

def grant_role_cr(cursor, schemas, role):
    for schema in schemas:
        grant_usage_on_schema(cursor, schema, role)
        grant_create_on_schema(cursor, schema, role)

def grant_role_ro(cursor, schemas, role):
    for schema in schemas:
        grant_usage_on_schema(cursor, schema, role)
        grant_select_on_tables(cursor, schema, role)
        grant_usage_on_sequence(cursor, schema, role)
        grant_select_on_sequences(cursor, schema, role)

def grant_role_rw(cursor, schemas, role):
    for schema in schemas:
        grant_usage_on_schema(cursor, schema, role)
        grant_select_on_tables(cursor, schema, role)
        grant_insert_update_delete_on_tables(cursor, schema, role)
        grant_usage_on_sequence(cursor, schema, role)
        grant_select_on_sequences(cursor, schema, role)
        grant_update_on_sequences(cursor, schema, role)

def grant_role_tr(cursor, schemas, role):
    for schema in schemas:
        grant_usage_on_schema(cursor, schema, role)
        grant_truncate_on_tables(cursor, schema, role)

def set_role_to_session_user(cursor):
    """
    Set the role to the current session user and log the session user.
    """
    # Logging the session user
    cursor.execute("SELECT session_user;")
    session_user = cursor.fetchone()[0]  # Fetch the session user
    logging.info("Current session user: %s", session_user)

# Execute the task based on the parameters loaded from the CSV file
def execute_task(cursor, parameters, args):
    # Create users along with db owner
    user_list = parameters.get("user_owner", []) + parameters.get("another_users", [])
    for user in user_list:
        create_user(cursor, user)

    # Change the database owner to 'user_owner' if specified
    owner = parameters["user_owner"][0]
    if parameters.get("user_owner"):
        alter_database_owner(cursor, args.dbname, owner)

    # Create schemas as specified in the 'schema_list' parameter with the owner from 'user_owner'
    for schema in parameters.get("schema_list", []):
        create_schema(cursor, schema, owner)

    # Create roles
    # Combine various role parameters into a single list and create each role
    role_list = parameters.get("role_list", []) + [
        parameters.get("role_cr", [None])[0],
        parameters.get("role_ro", [None])[0],
        parameters.get("role_rw", [None])[0],
        parameters.get("role_tr", [None])[0],
        parameters.get("role_pg_monitor", [None])[0]
    ]
    for role in role_list:
        create_role(cursor, role)

    # Extract values, handling missing keys
    role_pg_monitor = parameters.get("role_pg_monitor", [None])[0]
    users_to_receive_pg_monitor = parameters.get("users_to_receive_pg_monitor", [])

    # Log notice if values are missing or empty
    if not role_pg_monitor:
        logging.info("Notice: 'role_pg_monitor' is not set or is empty in the CSV. Skipping related operations.")
    if not users_to_receive_pg_monitor:
        logging.info("Notice: 'users_to_receive_pg_monitor' is not set or is empty in the CSV. Skipping role grants.")

    # Grant roles to users based on mappings defined in the parameters.
    # The mapping is defined as: {role: list of users to receive the role}
    for role, users in {
        parameters.get("role_ro", [None])[0]: parameters.get("users_to_receive_role_ro", []),
        parameters.get("role_rw", [None])[0]: parameters.get("users_to_receive_role_rw", []),
        parameters.get("role_tr", [None])[0]: parameters.get("users_to_receive_role_tr", []),
        parameters.get("role_cr", [None])[0]: parameters.get("users_to_receive_role_cr", []),
    }.items():
        for user in users:
            grant_role_to_user(cursor, role, user)

    # Grant owner roles to users_to_receive_role_tr users.
    users_to_receive_role_tr = parameters.get("users_to_receive_role_tr", [])
    for user in users_to_receive_role_tr:
        grant_role_to_user(cursor, owner, user)

    # Grant the pg_monitor role to users specified in the 'users_to_receive_pg_monitor' parameter
    if users_to_receive_pg_monitor and role_pg_monitor:
        for role, users in {
            role_pg_monitor: users_to_receive_pg_monitor,
        }.items():
            for user in users:
                grant_role_to_user(cursor, role, user)

    cursor.execute(f"SET ROLE {parameters['user_owner'][0]};")

    # Continue with other grant operations
    grant_role_cr(cursor, parameters.get("schema_cr_list", []), parameters.get("role_cr", [None])[0])
    grant_role_ro(cursor, parameters.get("schema_ro_list", []), parameters.get("role_ro", [None])[0])
    grant_role_rw(cursor, parameters.get("schema_rw_list", []), parameters.get("role_rw", [None])[0])
    grant_role_tr(cursor, parameters.get("schema_tr_list", []), parameters.get("role_tr", [None])[0])

def main(args):
    """
    Main function that parses command-line arguments, loads parameters from a CSV file,
    connects to the PostgreSQL database, and executes a series of operations to create users,
    roles, schemas, alter database ownership, and grant various privileges.
    """
    # Connect to the PostgreSQL database using the provided credentials
    """
    Main function to handle database setup and operations.
    """
    # Connect to the PostgreSQL Application database using the provided credentials
    conn = psycopg2.connect(host=args.host, port=args.port, user=args.username, dbname=args.dbname)
    conn.autocommit = True
    cursor = conn.cursor()

    # Connect to the PostgreSQL database using the provided credentials
    conn_postgres = psycopg2.connect(host=args.host, port=args.port, user=args.username, dbname='postgres')
    conn_postgres.autocommit = True
    cursor_postgres = conn_postgres.cursor()

    # Check if the task is to update user passwords and store them in Key Vault
    if args.task == "create_database":
        create_database(cursor_postgres, args)
        
    elif args.task == "create_datadog_role":
        if args.useDatadog == 'Enabled':
            create_datadog_role(cursor, cursor_postgres, args)
        else:
            logging.info("Datadog role creation is disabled. Skipping.")
    else:
        parameters = load_parameters(args.parameter_file)
        if args.task == "execute_grants":
            process_grants(cursor, parameters)
            logging.info("Grants applied successfully!")
        else:
            set_role_to_session_user(cursor)
            execute_task(cursor, parameters, args)
            logging.info("Parameters execution completed.")
    
    cursor_postgres.close()
    conn_postgres.close()
    logging.info("Script execution completed.")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True, help="Database host")
    parser.add_argument("-p", "--port", type=int, required=True, help="Database port")
    parser.add_argument("-U", "--username", type=str, required=True, help="PostgreSQL user")
    parser.add_argument("-d", "--dbname", type=str, required=True, help="Database name")
    parser.add_argument("--password", type=str, required=True, help="Database password")
    parser.add_argument("--parameter_file", type=str, required=True, help="CSV parameter file")
    parser.add_argument("--task", type=str, required=True, help="Specify a task to run")
    parser.add_argument("--useDatadog", type=str, required=True, help="Enable or disable Datadog role creation")
    args = parser.parse_args()
    main(args)