import csv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to load parameters from CSV
# Function to load parameters from CSV
def load_parameters(csv_file_path):
    parameters = {}
    with open(csv_file_path, "r", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if len(row) < 2:
                continue
            key, value = row[0].strip().lower(), row[1].strip()
            if "," in value:
                parameters[key] = [v.strip() for v in value.split(",") if v.strip()]
            else:
                parameters[key] = [value.strip()]
    logging.info("Loaded parameters: %s", parameters)
    return parameters

    

# Function for SELECT, INSERT, UPDATE, DELETE permissions
def grant_select_insert_update_delete(table, role):
    return f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role};"

# Function for SELECT, USAGE permissions
def grant_select_usage(table, role):
    return f"GRANT SELECT, USAGE ON {table} TO {role};"

# Function for SELECT permissions
def grant_select(table, role):
    return f"GRANT SELECT ON {table} TO {role};"

# Function to process grants and output to a file
def process_grants(parameters, output_file):
    with open(output_file, "w", encoding="utf-8") as out_file:
        for param in parameters:
            tables = param['tables']
            roles = param['roles']
            permissions = param['permissions']
            
            # Ensure we are processing only relevant permissions
            if not permissions:
                logging.warning(f"No permissions specified for {tables} and roles {roles}")
                continue

            # Iterate through tables and generate grants for each role for each table
            for table in tables:
                for role in roles:
                    # Determine which permission function to call
                    if set(permissions) == {"select", "insert", "update", "delete"}:
                        grant_statement = grant_select_insert_update_delete(table, role)
                    elif set(permissions) == {"select", "usage"}:
                        grant_statement = grant_select_usage(table, role)
                    elif set(permissions) == {"select"}:
                        grant_statement = grant_select(table, role)
                    else:
                        logging.warning(f"Unsupported permissions: {permissions} for {tables} and roles {roles}")
                        continue

                    # Write the GRANT statement to the file
                    out_file.write(grant_statement + "\n")
                    logging.info(f"Generated SQL: {grant_statement}")

# Main function to tie everything together
def main():
    csv_file_path = "grants.csv"  # Make sure the file is in the same directory
    output_file_path = "grants_output.txt"  # Output file for SQL statements
    
    parameters = load_parameters(csv_file_path)  # Load data from the CSV
    process_grants(parameters, output_file_path)  # Process the grants and output to file
    logging.info(f"Grant statements written to {output_file_path}")

if __name__ == "__main__":
    main()
