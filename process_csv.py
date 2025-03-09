import csv
import logging

# Define valid action permissions
ACTIONS = ['select', 'insert', 'update', 'delete']

def load_parameters(csv_file_path):
    """
    Load parameters from a CSV file. Supports:
    - Two-column format (returns a dictionary like before).
    - Three-column format (if the third column is 'role', it returns structured data for optimal processing).
    """
    with open(csv_file_path, "r", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        headers = next(reader, [])
        has_role = len(headers) >= 3 and headers[2].strip().lower() == "role"

        if has_role:
            # If 'role' exists, process it in the most optimal way
            structured_data = []
            for row in reader:
                if len(row) < 3:
                    continue
                structured_data.append({
                    "permissions": row[0].strip().lower(),
                    "tables": [t.strip() for t in row[1].split(",") if t.strip()],
                    "role": row[2].strip()
                })
            logging.info("Loaded structured data: %s", structured_data)
            return structured_data

        else:
            # Otherwise, fall back to the original dictionary-based approach
            parameters = {}
            for row in reader:
                if len(row) < 2:
                    continue
                key, value = row[0].strip().lower(), row[1].strip()
                if "," in value:
                    parameters[key] = [v.strip() for v in value.split(",") if v.strip()]
                else:
                    parameters[key] = [value.strip()]
            logging.info("Loaded parameters: %s", parameters)
            return parameters  # Return dictionary-based parameters


def grant_full_permissions(role, tables):
    """ Grants SELECT, INSERT, UPDATE, DELETE permissions on tables. """
    return [f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role};" for table in tables]

def grant_select_usage_permissions(role, tables):
    """ Grants SELECT and USAGE permissions (for schemas or sequences). """
    return [f"GRANT SELECT, USAGE ON {table} TO {role};" for table in tables]

def grant_select_permissions(role, tables):
    """ Grants only SELECT permission on tables. """
    return [f"GRANT SELECT ON {table} TO {role};" for table in tables]

def process_grants(data):
    """
    Processes either structured data (list) or dictionary-based parameters.
    """
    grant_statements = []

    # If 'data' is a list, process optimized structured format
    if isinstance(data, list):
        for row in data:
            permission_parts = row["permissions"].split('_')
            tables = row["tables"]
            role = row["role"]

            if 'full' in permission_parts:
                grant_statements.extend(grant_full_permissions(role, tables))
            elif 'select' in permission_parts and 'usage' in permission_parts:
                grant_statements.extend(grant_select_usage_permissions(role, tables))
            elif 'select' in permission_parts:
                grant_statements.extend(grant_select_permissions(role, tables))

    # # If 'data' is a dictionary (old method)
    # elif isinstance(data, dict):
    #     for permission, tables in data.items():
    #         if permission == "permissions":  # Skip header row
    #             continue

    #         permission_parts = permission.lower().split('_')
    #         role = permission  # Assume permission name as role (since no explicit role column)

    #         if 'full' in permission_parts:
    #             grant_statements.extend(grant_full_permissions(role, tables))
    #         elif 'select' in permission_parts and 'usage' in permission_parts:
    #             grant_statements.extend(grant_select_usage_permissions(role, tables))
    #         elif 'select' in permission_parts:
    #             grant_statements.extend(grant_select_permissions(role, tables))

    return grant_statements


def main():
    """
    Main function to execute the script.
    """



    csv_file_path = "csv_db_cmds.csv"  # Make sure the file is in the same directory
   
    
    # Load parameters
    data = load_parameters(csv_file_path)
    
    # Process grants
    grant_statements = process_grants(data)

    # Print output
    print("\n".join(grant_statements))


# Run the script
if __name__ == "__main__":
    main()

