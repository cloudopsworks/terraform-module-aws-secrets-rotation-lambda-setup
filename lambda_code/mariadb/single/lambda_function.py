# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import pymysql
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager RDS MariaDB Handler

    This handler uses the single-user rotation scheme to rotate an RDS MariaDB user credential. This rotation scheme
    logs into the database as the user and rotates the user's own password, immediately invalidating the user's
    previous password.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'mariadb'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name>,
        'port': <optional: if not specified, default port 3306 will be used>
    }

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the secret json does not contain the expected keys

    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if "RotationEnabled" in metadata and not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # Call the appropriate step
    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(service_client, arn, token):
    """Generate a new secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ValueError: If the current secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        random_pass = get_random_password(service_client)
        current_dict['password'] = random_pass
        # Check if connection_string is present, if not do nothing
        if 'connection_string' in current_dict:
            current_dict['connection_string'] = generate_connection_string(current_dict, random_pass)
        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the pending secret in the database

    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING password
    as the user password in the database. Else, it throws a ValueError.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or valid credentials are found to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    try:
        previous_dict = get_secret_dict(service_client, arn, "AWSPREVIOUS")
    except (service_client.exceptions.ResourceNotFoundException, KeyError):
        previous_dict = None
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info("setSecret: AWSPENDING secret is already set as password in MariaDB DB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match
    if current_dict['username'] != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user %s" % (pending_dict['username'], current_dict['username']))
        raise ValueError("Attempting to modify user %s other than current user %s" % (pending_dict['username'], current_dict['username']))

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))

    # Now try the current password
    conn = get_connection(current_dict)

    # If both current and pending do not work, try previous
    if not conn and previous_dict:
        # Update previous_dict to leverage current SSL settings
        previous_dict.pop('ssl', None)
        if 'ssl' in current_dict:
            previous_dict['ssl'] = current_dict['ssl']

        conn = get_connection(previous_dict)

        # Make sure the user and host from previous and pending match
        if previous_dict['username'] != pending_dict['username']:
            logger.error("setSecret: Attempting to modify user %s other than last valid user %s" % (pending_dict['username'], previous_dict['username']))
            raise ValueError("Attempting to modify user %s other than last valid user %s" % (pending_dict['username'], previous_dict['username']))
        if previous_dict['host'] != pending_dict['host']:
            logger.error("setSecret: Attempting to modify user for host %s other than previous host %s" % (pending_dict['host'], previous_dict['host']))
            raise ValueError("Attempting to modify user for host %s other than previous host %s" % (pending_dict['host'], previous_dict['host']))

    # If we still don't have a connection, raise a ValueError
    if not conn:
        logger.error("setSecret: Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)
        raise ValueError("Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)

    # Now set the password to the pending password
    try:
        with conn.cursor() as cur:
            cur.execute("SET PASSWORD = PASSWORD(%s)", pending_dict['password'])
            conn.commit()
            logger.info("setSecret: Successfully set password for user %s in MariaDB DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        conn.close()


def test_secret(service_client, arn, token):
    """Test the pending secret against the database

    This method tries to log into the database with the secrets staged with AWSPENDING and runs
    a permissions check to ensure the user has the corrrect permissions.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or valid credentials are found to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    # Try to login with the pending secret, if it succeeds, return
    conn = get_connection(get_secret_dict(service_client, arn, "AWSPENDING", token))
    if conn:
        # This is where the lambda will validate the user's permissions. Uncomment/modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW()")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into MariaDB DB with AWSPENDING secret in %s." % arn)
        return
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % arn)
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current

    This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=token)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def get_connection(secret_dict):
    """Gets a connection to MariaDB DB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database. Will attempt a fallback, non-SSL connection when
    initial connection fails using SSL and fall_back is True.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pymysql.connections.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 3306
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else None

    # Get SSL connectivity configuration
    use_ssl, fall_back = get_ssl_config(secret_dict)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to non-SSL on failure
    conn = connect_and_authenticate(secret_dict, port, dbname, use_ssl)
    if conn or not fall_back:
        return conn
    else:
        return connect_and_authenticate(secret_dict, port, dbname, False)


def get_ssl_config(secret_dict):
    """Gets the desired SSL and fall back behavior using a secret dictionary

    This helper function uses the existance and value the 'ssl' key in a secret dictionary
    to determine desired SSL connectivity configuration. Its behavior is as follows:
        - 'ssl' key DNE or invalid type/value: return True, True
        - 'ssl' key is bool: return secret_dict['ssl'], False
        - 'ssl' key equals "true" ignoring case: return True, False
        - 'ssl' key equals "false" ignoring case: return False, False

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Tuple(use_ssl, fall_back): SSL configuration
            - use_ssl (bool): Flag indicating if an SSL connection should be attempted
            - fall_back (bool): Flag indicating if non-SSL connection should be attempted if SSL connection fails

    """
    # Default to True for SSL and fall_back mode if 'ssl' key DNE
    if 'ssl' not in secret_dict:
        return True, True

    # Handle type bool
    if isinstance(secret_dict['ssl'], bool):
        return secret_dict['ssl'], False

    # Handle type string
    if isinstance(secret_dict['ssl'], str):
        ssl = secret_dict['ssl'].lower()
        if ssl == "true":
            return True, False
        elif ssl == "false":
            return False, False
        else:
            # Invalid string value, default to True for both SSL and fall_back mode
            return True, True

    # Invalid type, default to True for both SSL and fall_back mode
    return True, True


def connect_and_authenticate(secret_dict, port, dbname, use_ssl):
    """Attempt to connect and authenticate to a MariaDB instance

    This helper function tries to connect to the database using connectivity info passed in.
    If successful, it returns the connection, else None

    Args:
        - secret_dict (dict): The Secret Dictionary
        - port (int): The databse port to connect to
        - dbname (str): Name of the database
        - use_ssl (bool): Flag indicating whether connection should use SSL/TLS

    Returns:
        Connection: The pymongo.database.Database object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    ssl = {'ca': '/etc/pki/tls/cert.pem'} if use_ssl else None

    # Try to obtain a connection to the db
    try:
        # Checks hostname and verifies server certificate implictly when 'ca' key is in 'ssl' dictionary
        conn = pymysql.connect(host=secret_dict['host'], user=secret_dict['username'], password=secret_dict['password'], port=port, database=dbname, connect_timeout=5, ssl=ssl)
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", secret_dict['username'], secret_dict['host']))
        return conn
    except pymysql.OperationalError as e:
        if 'certificate verify failed: IP address mismatch' in e.args[1]:
            logger.error("Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secret_dict['host'])
        return None


def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

    """
    required_fields = ['host', 'username', 'password']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Run validations against the secret
    if 'engine' not in secret_dict or secret_dict['engine'] != 'mariadb':
        raise KeyError("Database engine must be set to 'mariadb' in order to use this rotation lambda")
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secret_dict


def get_environment_bool(variable_name, default_value):
    """Loads the environment variable and converts it to the boolean.

    Args:
        variable_name (string): Name of environment variable

        default_value (bool): The result will fallback to the default_value when the environment variable with the given name doesn't exist.

    Returns:
        bool: True when the content of environment variable contains either 'true', '1', 'y' or 'yes'
    """
    variable = os.environ.get(variable_name, str(default_value))
    return variable.lower() in ['true', '1', 'y', 'yes']


def get_random_password(service_client):
    """ Generates a random new password. Generator loads parameters that affects the content of the resulting password from the environment
    variables. When environment variable is missing sensible defaults are chosen.

    Supported environment variables:
        - EXCLUDE_CHARACTERS
        - PASSWORD_LENGTH
        - EXCLUDE_NUMBERS
        - EXCLUDE_PUNCTUATION
        - EXCLUDE_UPPERCASE
        - EXCLUDE_LOWERCASE
        - REQUIRE_EACH_INCLUDED_TYPE

    Args:
        service_client (client): The secrets manager service client

    Returns:
        string: The randomly generated password.
    """
    passwd = service_client.get_random_password(
        ExcludeCharacters=os.environ.get('EXCLUDE_CHARACTERS', ':/"\'\\$%&*()[]{}<>?!.,;|`'),
        PasswordLength=int(os.environ.get('PASSWORD_LENGTH', 32)),
        ExcludeNumbers=get_environment_bool('EXCLUDE_NUMBERS', False),
        ExcludePunctuation=get_environment_bool('EXCLUDE_PUNCTUATION', False),
        ExcludeUppercase=get_environment_bool('EXCLUDE_UPPERCASE', False),
        ExcludeLowercase=get_environment_bool('EXCLUDE_LOWERCASE', False),
        RequireEachIncludedType=get_environment_bool('REQUIRE_EACH_INCLUDED_TYPE', True)
    )
    return passwd['RandomPassword']


def generate_connection_string(secret_dict, new_password):
    """Generates a connection string for the PostgreSQL database

    This helper function generates a connection string using the provided secret dictionary and new password.

    Args:
        secret_dict (dict): The Secret Dictionary containing connection details
        new_password (str): The new password to be included in the connection string

    Uses secret_dict['connection_string_type'] to determine the format of the connection string. supported formats are:
        - node-pg | psycopg | rustpg: Uses psycopg2 format
        - jdbc: Uses JDBC format
        - odbc: Uses ODBC format
        - dotnet: Uses .NET format
        - gopq: Uses GO pq format

    Returns:
        str: The generated connection string
    """
    # Precondition: Ensure the secret_dict contains the necessary keys
    connection_string_type = secret_dict.get('connection_string_type')
    logger.info("Generating connection string for secret: %s" % connection_string_type)
    encoded_password = urllib.parse.quote_plus(new_password)
    if connection_string_type == 'jdbc':
        conn_string = f"jdbc:postgresql://{secret_dict['host']}:{secret_dict.get('port', 5432)}/{secret_dict.get('dbname')}?user={secret_dict['username']}&password={encoded_password}ssl=true&sslmode={secret_dict.get('sslmode')}&schema={secret_dict.get('schema', 'public')}"
    elif connection_string_type == 'dotnet':
        conn_string = f"Host={secret_dict['host']};Port={secret_dict.get('port', 5432)};Database={secret_dict.get('dbname')};Username={secret_dict['username']};Password={encoded_password};SSL Mode={secret_dict.get('sslmode')};Search Path={secret_dict.get('schema', 'public')};"
    elif connection_string_type == 'odbc':
        conn_string = f"Driver={{PostgreSQL ODBC Driver(UNICODE)}};Server={secret_dict['host']};Port={secret_dict.get('port', 5432)};Database={secret_dict.get('dbname')};UID={secret_dict['username']};PWD={encoded_password};sslmode={secret_dict.get('sslmode')};schema={secret_dict.get('schema', 'public')}"
    elif connection_string_type == 'gopq':
        conn_string = f"postgres://{secret_dict['username']}:{encoded_password}@{secret_dict['host']}:{secret_dict.get('port', 5432)}/{secret_dict.get('dbname')}?sslmode={secret_dict.get('sslmode')}&schema={secret_dict.get('schema', 'public')}"
    elif connection_string_type == 'node-pg' or connection_string_type == 'psycopg' or connection_string_type == 'rustpg':
        conn_string = f"postgressql://{secret_dict['username']}:{encoded_password}@{secret_dict['host']}:{secret_dict.get('port', 5432)}/{secret_dict.get('dbname')}?sslmode={secret_dict.get('sslmode')}&schema={secret_dict.get('schema', 'public')}"
    else:
        conn_string = "(connection string type not supported)"
        logger.warning("Connection string type not supported! Supported types are: node-pg, psycopg, rustpg, jdbc, odbc, dotnet, gopq.")

    return conn_string