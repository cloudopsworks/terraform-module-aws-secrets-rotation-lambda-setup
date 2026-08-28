# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import re
import pymssql
import urllib.parse

logger = logging.getLogger()
try:
    logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())
except ValueError:
    logger.setLevel(logging.INFO)

# Fields of a secret that are safe to name in a log line. Anything outside this
# allow list -- passwords, tokens and the pre-built connection strings that embed
# them -- never reaches the log stream.
LOGGABLE_SECRET_FIELDS = ('engine', 'host', 'port', 'dbname', 'username', 'ssl', 'sslmode', 'schema')

# Placeholder substituted for any credential-looking text.
REDACTED = '***REDACTED***'

# Maximum length of a single value copied into a log record.
MAX_LOGGED_LENGTH = 512

# Credential shapes that database drivers and the AWS SDK embed in their error
# messages: URI user-info sections and key/value pairs.
_URI_CREDENTIAL_RE = re.compile(r'(?i)(//[^/\s:@]+:)([^@\s/]+)(@)')
# The negative lookbehind keeps ARN segments such as ":secret:my-secret-name"
# readable: those identify the secret, they are not the credential.
_KEY_VALUE_CREDENTIAL_RE = re.compile(
    r'(?i)(?<!:)(password|passwd|pwd|secret|token|private_key)("?\s*[=:]\s*)("[^"]*"|\'[^\']*\'|[^\s;,&"\']+)'
)

# Characters that could forge a new log entry (CRLF) or corrupt the log stream.
_CONTROL_CHARACTERS_RE = re.compile(r'[\x00-\x1f\x7f]')


def scrub(value):
    """Renders a value as a string that is safe to write to the log stream

    Credential-looking substrings are masked, control characters (which could be
    used to forge log entries) are collapsed to spaces, and the result is
    truncated so a hostile value cannot flood the log group.

    Args:
        value: Any value. Non-string values are rendered with str()

    Returns:
        string: The sanitized representation of the value

    """
    text = value if isinstance(value, str) else str(value)
    text = _URI_CREDENTIAL_RE.sub(r'\1' + REDACTED + r'\3', text)
    text = _KEY_VALUE_CREDENTIAL_RE.sub(r'\1\2' + REDACTED, text)
    text = _CONTROL_CHARACTERS_RE.sub(' ', text)
    if len(text) > MAX_LOGGED_LENGTH:
        text = text[:MAX_LOGGED_LENGTH] + '...(truncated)'
    return text


def mask_identifier(value):
    """Shortens an opaque identifier so log lines stay correlatable without publishing it

    Args:
        value: The identifier, typically a secret version id or rotation token

    Returns:
        string: The leading characters of the identifier followed by an ellipsis

    """
    text = scrub(value)
    if len(text) <= 8:
        return REDACTED
    return '%s...' % text[:8]


def safe_connection_info(secret_dict):
    """Builds a log-safe description of a connection target

    Only the allow-listed, non-credential fields are copied out of the secret, so
    neither the password nor a pre-built connection string can reach the log
    stream through this value.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        dict: The allow-listed connection fields, sanitized for logging

    """
    return {field: scrub(secret_dict[field]) for field in LOGGABLE_SECRET_FIELDS if field in secret_dict}


class RedactingFilter(logging.Filter):
    """Scrubs every log record as a last line of defence

    Call sites sanitize their own arguments; this filter additionally covers
    records emitted by the AWS SDK and by the database driver, which may carry
    connection URIs containing credentials.

    """

    def filter(self, record):
        record.msg = scrub(record.msg)
        if isinstance(record.args, dict):
            record.args = {key: scrub(value) if isinstance(value, str) else value for key, value in record.args.items()}
        elif record.args:
            record.args = tuple(scrub(arg) if isinstance(arg, str) else arg for arg in record.args)
        return True


_redacting_filter = RedactingFilter()
logger.addFilter(_redacting_filter)
for _handler in logger.handlers:
    _handler.addFilter(_redacting_filter)


def lambda_handler(event, context):
    """Entry point for the rotation Lambda

    Delegates to rotate_secret and re-raises any failure without its original
    message, so that a driver or SDK error carrying a connection URI is never
    printed by the Lambda runtime. The sanitized detail is logged instead.

    Args:
        event (dict): Lambda dictionary of event parameters

        context (LambdaContext): The Lambda runtime information

    Raises:
        RuntimeError: If any rotation step fails

    """
    try:
        return rotate_secret(event, context)
    except Exception as error:
        logger.error("lambda_handler: Rotation failed with %s: %s" % (error.__class__.__name__, scrub(error)))
        raise RuntimeError("Rotation failed with %s, see the function log for details" % error.__class__.__name__) from None


def rotate_secret(event, context):
    """Secrets Manager RDS SQL Server Handler

    This handler uses the single-user rotation scheme to rotate an RDS SQL Server user credential. This rotation
    scheme logs into the database as the user and rotates the user's own password, immediately invalidating the
    user's previous password.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'sqlserver'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name, default to 'master'>,
        'port': <optional: if not specified, default port 1433 will be used>
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
        logger.error("Secret %s is not enabled for rotation" % scrub(arn))
        raise ValueError("Secret %s is not enabled for rotation" % scrub(arn))
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (mask_identifier(token), scrub(arn)))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (mask_identifier(token), scrub(arn)))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (mask_identifier(token), scrub(arn)))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (mask_identifier(token), scrub(arn)))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (mask_identifier(token), scrub(arn)))

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
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (scrub(step), scrub(arn)))
        raise ValueError("Invalid step parameter %s for secret %s" % (scrub(step), scrub(arn)))


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
        logger.info("createSecret: Successfully retrieved secret for %s." % scrub(arn))
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        random_pass = get_random_password(service_client)
        current_dict['password'] = random_pass
        # Check if connection_string is present, if not do nothing
        if 'connection_string' in current_dict:
            current_dict['connection_string'] = generate_connection_string(current_dict, random_pass)
        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (scrub(arn), mask_identifier(token)))


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
        logger.info("setSecret: AWSPENDING secret is already set as password in SQL Server DB for secret arn %s." % scrub(arn))
        return

    # Make sure the user from current and pending match
    if current_dict['username'] != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user %s" % (scrub(pending_dict['username']), scrub(current_dict['username'])))
        raise ValueError("Attempting to modify user %s other than current user %s" % (scrub(pending_dict['username']), scrub(current_dict['username'])))

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (scrub(pending_dict['host']), scrub(current_dict['host'])))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (scrub(pending_dict['host']), scrub(current_dict['host'])))

    # Now try the current password
    conn = get_connection(current_dict)

    # If both current and pending do not work, try previous
    if not conn and previous_dict:
        # Update previous_dict to leverage current SSL settings
        previous_dict.pop('ssl', None)
        if 'ssl' in current_dict:
            previous_dict['ssl'] = current_dict['ssl']

        conn = get_connection(previous_dict)

        # Make sure the user/host from previous and pending match
        if previous_dict['username'] != pending_dict['username']:
            logger.error("setSecret: Attempting to modify user %s other than previous valid user %s" % (scrub(pending_dict['username']), scrub(previous_dict['username'])))
            raise ValueError("Attempting to modify user %s other than previous valid user %s" % (scrub(pending_dict['username']), scrub(previous_dict['username'])))
        if previous_dict['host'] != pending_dict['host']:
            logger.error("setSecret: Attempting to modify user for host %s other than previous host %s" % (scrub(pending_dict['host']), scrub(previous_dict['host'])))
            raise ValueError("Attempting to modify user for host %s other than previous host %s" % (scrub(pending_dict['host']), scrub(previous_dict['host'])))

    # If we still don't have a connection, raise a ValueError
    if not conn:
        logger.error("setSecret: Unable to log into database with previous, current, or pending secret of secret arn %s" % scrub(arn))
        raise ValueError("Unable to log into database with previous, current, or pending secret of secret arn %s" % scrub(arn))

    # Now set the password to the pending password
    try:
        with conn.cursor() as cursor:
            # Get escaped username via QUOTENAME, then verify the server really
            # returned a bracket-quoted identifier before it is used below.
            cursor.execute("SELECT QUOTENAME(%s) AS QUOTENAME", (current_dict['username'],))
            escaped_username = validate_quoted_identifier(cursor.fetchone()['QUOTENAME'])

            # Get the current version and db
            cursor.execute("SELECT @@VERSION AS version")
            version = cursor.fetchall()[0]['version']
            cursor.execute("SELECT DB_NAME() AS name")
            current_db = cursor.fetchall()[0]['name']

            # Determine if we are in a contained DB
            containment = 0
            if not version.startswith("Microsoft SQL Server 2008"):  # SQL Server 2008 does not support contained databases
                cursor.execute("SELECT containment FROM sys.databases WHERE name = %s", current_db)
                containment = cursor.fetchall()[0]['containment']

            # Set the user or login password (depending on database containment).
            # Only the validated identifier is templated into the statement; both
            # passwords are bound parameters and never appear in the query text.
            #
            # The two statement-building lines below are suppressed for the SQL
            # injection rules. T-SQL cannot bind an object name as a parameter, so
            # ALTER LOGIN/USER has no parameterised form. The name reaching the
            # template is quoted server-side by QUOTENAME and then re-checked by
            # validate_quoted_identifier, which rejects anything that is not a single
            # bracket-quoted token; alter_object is chosen from two literals. The
            # rules match on the syntax and cannot see either sanitiser.
            alter_object = "LOGIN" if containment == 0 else "USER"
            # nosemgrep
            alter_stmt = "ALTER {} {} WITH PASSWORD = %s OLD_PASSWORD = %s".format(alter_object, escaped_username)
            # nosemgrep
            cursor.execute(alter_stmt, (pending_dict['password'], current_dict['password']))

            conn.commit()
            logger.info("setSecret: Successfully set password for user %s in SQL Server DB for secret arn %s." % (scrub(pending_dict['username']), scrub(arn)))
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
                cur.execute("SELECT @@VERSION AS version")
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into SQL Server DB with AWSPENDING secret in %s." % scrub(arn))
        return
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % scrub(arn))
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % scrub(arn))


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
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (mask_identifier(version), scrub(arn)))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=token)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (mask_identifier(token), scrub(arn)))


def get_connection(secret_dict):
    """Gets a connection to a SQL Server DB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database. Will attempt a fallback, non-SSL connection when
    initial connection fails using SSL and fall_back is True.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pymssql.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = str(secret_dict['port']) if 'port' in secret_dict else '1433'
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else 'master'

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
    """Attempt to connect and authenticate to a SQL Server DB

    This helper function tries to connect to the database using connectivity info passed in.
    If successful, it returns the connection, else None

    Args:
        - secret_dict (dict): The Secret Dictionary
        - port (int): The databse port to connect to
        - dbname (str): Name of the database
        - use_ssl (bool): Flag indicating whether connection should use SSL/TLS

    Returns:
        Connection: The pymssql.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Dynamically set tds configuration based on ssl flag
    os.environ['FREETDSCONF'] = '/var/task/%s' % ('freetds_ssl.conf' if use_ssl else 'freetds.conf')

    # Try to obtain a connection to the db
    try:
        conn = pymssql.connect(server=secret_dict['host'],
                               user=secret_dict['username'],
                               password=secret_dict['password'],
                               database=dbname,
                               port=port,
                               login_timeout=5,
                               as_dict=True)
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", scrub(secret_dict['username']), scrub(secret_dict['host'])))
        return conn
    except pymssql.OperationalError as e:
        # The driver message is scrubbed before it is logged: FreeTDS can echo the
        # connection parameters back in the error text.
        logger.warning("Unable to connect to database %s, Error is: %s %s" % (safe_connection_info(secret_dict), e.__class__.__name__, scrub(e)))
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
    if 'engine' not in secret_dict or secret_dict['engine'] != 'sqlserver':
        raise KeyError("Database engine must be set to 'sqlserver' in order to use this rotation lambda")
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secret_dict


def validate_quoted_identifier(identifier):
    """Verifies that an identifier was quoted by SQL Server before it is used in a statement

    T-SQL cannot bind an object name as a parameter, so the login name is quoted
    server-side with QUOTENAME and then checked here. Anything that is not a
    single bracket-quoted token is rejected rather than templated into a query.

    Args:
        identifier (string): The value returned by QUOTENAME

    Returns:
        string: The identifier, unchanged, when it is safe to use

    Raises:
        ValueError: If the value is not a bracket-quoted identifier

    """
    # QUOTENAME escapes an embedded ']' by doubling it, so that form is accepted too.
    if not isinstance(identifier, str) or not re.fullmatch(r'\[(?:[^\]\x00-\x1f]|\]\])+\]', identifier):
        raise ValueError("Refusing to build a statement with an unexpected identifier")
    return identifier


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


# Accepted values of the secret's 'connection_string_type' field, mapped to the
# dialect that gets rendered. The driver specific names are kept as aliases so
# that secrets already carrying them keep rotating.
CONNECTION_STRING_TYPES = {
    'jdbc': 'jdbc',
    'dotnet': 'dotnet',
    'odbc': 'odbc',
    'go': 'go',
    'gomssql': 'go',
    'node': 'node',
    'nodejs': 'node',
}

def quote_odbc_value(value):
    """Quotes a value for an ODBC style ``Key=Value;`` connection string

    ODBC requires a value that contains a delimiter or a leading/trailing space to
    be enclosed in braces, with any closing brace inside it doubled. Without this a
    password containing ``;`` would silently truncate the connection string.

    Args:
        value: The value to quote

    Returns:
        string: The value, braced when it needs to be

    """
    text = str(value)
    if text != text.strip() or any(character in text for character in '[]{}(),;?*=!@'):
        return '{%s}' % text.replace('}', '}}')
    return text


def quote_dotnet_value(value):
    """Quotes a value for an ADO.NET style ``Key=Value;`` connection string

    ADO.NET requires a value that contains a delimiter, a quote or a
    leading/trailing space to be enclosed in double quotes, with any inner double
    quote doubled.

    Args:
        value: The value to quote

    Returns:
        string: The value, quoted when it needs to be

    """
    text = str(value)
    if text != text.strip() or any(character in text for character in ';\'"='):
        return '"%s"' % text.replace('"', '""')
    return text


def build_property_string(parameters, quote_value):
    """Renders ``Key=Value;`` pairs, skipping the ones that have no value

    Skipping empties keeps optional settings out of the result instead of emitting
    the string "None" for them.

    Args:
        parameters (list): (key, value) pairs in the order they should appear

        quote_value (callable): The quoting function for the target dialect

    Returns:
        string: The rendered connection string

    """
    return ''.join('%s=%s;' % (key, quote_value(value)) for key, value in parameters if value is not None and str(value) != '')


def build_query_string(parameters):
    """Renders URL query parameters, skipping the ones that have no value

    Args:
        parameters (list): (key, value) pairs in the order they should appear

    Returns:
        string: The rendered query string, without the leading '?'

    """
    return '&'.join('%s=%s' % (key, urllib.parse.quote_plus(str(value))) for key, value in parameters if value is not None and str(value) != '')


def build_userinfo(username, password):
    """Percent-encodes the ``user:password`` section of a connection URI

    Both halves are encoded with no safe characters, so a credential containing
    ``@``, ``:`` or ``/`` cannot break out of the user-info section. quote() is used
    rather than quote_plus() because '+' is not decoded back to a space there.

    Args:
        username (string): The user name

        password (string): The password

    Returns:
        string: The encoded 'user:password' pair

    """
    return '%s:%s' % (urllib.parse.quote(str(username), safe=''), urllib.parse.quote(str(password), safe=''))


def generate_connection_string(secret_dict, new_password):
    """Generates a connection string for the SQL Server database

    This helper function generates a connection string using the provided secret
    dictionary and the new password, in the dialect named by the secret's
    'connection_string_type' field. Encryption is taken from the same 'ssl' key
    that get_ssl_config uses for the rotation connection, so the string cannot
    disagree with how this function actually reaches the database.

    Args:
        secret_dict (dict): The Secret Dictionary containing connection details
        new_password (str): The new password to be included in the connection string

    Supported values of secret_dict['connection_string_type'] are:
        - jdbc: mssql-jdbc URL, 'jdbc:sqlserver://host:port;databaseName=...'
        - dotnet: ADO.NET keyword string, 'Server=host,port;Database=...'
        - odbc: ODBC keyword string, 'Driver={ODBC Driver 18 for SQL Server};...'
        - go | gomssql: go-mssqldb URL, 'sqlserver://user:password@host:port'
        - node | nodejs: node-mssql URL, 'mssql://user:password@host:port/db'

    Returns:
        str: The generated connection string

    Raises:
        ValueError: If connection_string_type is missing or is not supported

    """
    connection_string_type = secret_dict.get('connection_string_type')
    dialect = CONNECTION_STRING_TYPES.get(connection_string_type)
    if dialect is None:
        logger.error("Unsupported connection string type %s, supported types are: %s" % (scrub(connection_string_type), ', '.join(sorted(CONNECTION_STRING_TYPES))))
        raise ValueError("Unsupported connection_string_type, refusing to overwrite the stored connection string")
    logger.info("Generating %s connection string for a %s secret" % (dialect, scrub(connection_string_type)))

    host = secret_dict['host']
    port = secret_dict.get('port', 1433)
    dbname = secret_dict.get('dbname', 'master')
    username = secret_dict['username']
    use_ssl, _ = get_ssl_config(secret_dict)

    if dialect == 'jdbc':
        # mssql-jdbc takes ';' separated properties, not URL query parameters, so
        # the password is placed verbatim and brace quoted rather than
        # percent-encoded -- percent-encoding it would corrupt the credential.
        return "jdbc:sqlserver://%s:%s;" % (host, port) + build_property_string([
            ('databaseName', dbname),
            ('user', username),
            ('password', new_password),
            ('encrypt', 'true' if use_ssl else 'false'),
            ('trustServerCertificate', 'false'),
        ], quote_odbc_value)

    if dialect == 'dotnet':
        return build_property_string([
            ('Server', '%s,%s' % (host, port)),
            ('Database', dbname),
            ('User Id', username),
            ('Password', new_password),
            ('Encrypt', 'True' if use_ssl else 'False'),
            ('TrustServerCertificate', 'False'),
        ], quote_dotnet_value)

    if dialect == 'odbc':
        return "Driver={ODBC Driver 18 for SQL Server};" + build_property_string([
            ('Server', '%s,%s' % (host, port)),
            ('Database', dbname),
            ('Uid', username),
            ('Pwd', new_password),
            ('Encrypt', 'yes' if use_ssl else 'no'),
            ('TrustServerCertificate', 'no'),
        ], quote_odbc_value)

    if dialect == 'go':
        query = build_query_string([
            ('database', dbname),
            ('encrypt', 'true' if use_ssl else 'disable'),
        ])
        return "sqlserver://%s@%s:%s?%s" % (build_userinfo(username, new_password), host, port, query)

    # node-mssql URL form.
    query = build_query_string([('encrypt', 'true' if use_ssl else 'false')])
    return "mssql://%s@%s:%s/%s?%s" % (build_userinfo(username, new_password), host, port, dbname, query)
