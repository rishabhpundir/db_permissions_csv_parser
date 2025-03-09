import argparse
import psycopg2
import csv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

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

# Grant Functions
def grant_select_on_table(cursor, table, role):
    cursor.execute(f"GRANT SELECT ON {table} TO {role};")
    logging.info(f"Granted SELECT on {table} to {role}.")

def grant_select_usage_on_table(cursor, table, role):
    cursor.execute(f"GRANT SELECT, USAGE ON {table} TO {role};")
    logging.info(f"Granted SELECT, USAGE on {table} to {role}.")

def grant_select_insert_update_delete_on_table(cursor, table, role):
    cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role};")
    logging.info(f"Granted SELECT, INSERT, UPDATE, DELETE on {table} to {role}.")

# Function to execute grants based on CSV data
def execute_grants(data, cursor):
    for permission_type, tables, role in data:
        for table in tables:
            if permission_type == "tables_to_receive_grant_select":
                grant_select_on_table(cursor, table, role)
            elif permission_type == "tables_to_receive_grant_select_usage":
                grant_select_usage_on_table(cursor, table, role)
            elif permission_type == "tables_to_receive_grant_full":
                grant_select_insert_update_delete_on_table(cursor, table, role)
            else:
                logging.warning(f"Unknown permission type: {permission_type}")

# Function to execute original script functionalities
def execute_task(cursor, parameters, args):
    """
    This function executes the existing PostgreSQL role, user, and schema management tasks.
    """

    # Create Users
    user_list = parameters.get("user_owner", []) + parameters.get("another_users", [])
    for user in user_list:
        create_user(cursor, user)

    # Change Database Owner
    if parameters.get("user_owner"):
        alter_database_owner(cursor, args.dbname, parameters["user_owner"][0])

    # Create Schemas
    for schema in parameters.get("schema_list", []):
        create_schema(cursor, schema, parameters["user_owner"][0])

    # Create Roles
    role_list = parameters.get("role_list", []) + [
        parameters.get("role_cr", [None])[0],
        parameters.get("role_ro", [None])[0],
        parameters.get("role_rw", [None])[0],
        parameters.get("role_tr", [None])[0],
        parameters.get("role_pg_monitor", [None])[0]
    ]
    for role in role_list:
        create_role(cursor, role)

    # Assign Roles to Users
    for role, users in {
        parameters.get("role_ro", [None])[0]: parameters.get("users_to_receive_role_ro", []),
        parameters.get("role_rw", [None])[0]: parameters.get("users_to_receive_role_rw", []),
        parameters.get("role_tr", [None])[0]: parameters.get("users_to_receive_role_tr", []),
        parameters.get("role_cr", [None])[0]: parameters.get("users_to_receive_role_cr", []),
    }.items():
        for user in users:
            grant_role_to_user(cursor, role, user)

def main(args):
    """
    Main function to handle database setup, grants execution, and operations.
    """

    # Connect to PostgreSQL
    conn = psycopg2.connect(host=args.host, port=args.port, user=args.username, dbname=args.dbname)
    conn.autocommit = True
    cursor = conn.cursor()

    conn_postgres = psycopg2.connect(host=args.host, port=args.port, user=args.username, dbname='postgres')
    conn_postgres.autocommit = True
    cursor_postgres = conn_postgres.cursor()

    # Handle Different Tasks
    if args.task == "create_database":
        create_database(cursor_postgres, args)
    elif args.task == "create_datadog_role":
        create_datadog_role(cursor, cursor_postgres, args)
    elif args.task == "execute_grants":
        data = load_parameters(args.parameter_file)
        if isinstance(data, dict):  # Old format detected
            logging.info("Old format detected. Skipping grants execution.")
        elif not data:
            logging.error("No valid grant data found in CSV file.")
        else:
            execute_grants(data, cursor)
            logging.info("Grants applied successfully!")
    else:
        parameters = load_parameters(args.parameter_file)
        execute_task(cursor, parameters, args)

    # Close connections
    cursor.close()
    conn.close()
    cursor_postgres.close()
    conn_postgres.close()
    logging.info("Script execution completed.")

# Run the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True, help="Database host")
    parser.add_argument("-p", "--port", type=int, required=True, help="Database port")
    parser.add_argument("-U", "--username", type=str, required=True, help="PostgreSQL user")
    parser.add_argument("-d", "--dbname", type=str, required=True, help="Database name")
    parser.add_argument("--parameter_file", type=str, required=True, help="CSV parameter file")
    parser.add_argument("--task", type=str, required=True, help="Specify a task to run")
    parser.add_argument("--useDatadog", type=str, required=True, help="Enable or disable Datadog role creation")
    args = parser.parse_args()
    main(args)
