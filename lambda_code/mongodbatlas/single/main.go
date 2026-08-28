// main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"net/url"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.mongodb.org/atlas-sdk/v20250312001/admin"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// SecretsManagerEvent
//
// Payload received on lambda from Secrets Manager RotateSecret event
type SecretsManagerEvent struct {
	SecretId           string `json:"SecretId"`
	ClientRequestToken string `json:"ClientRequestToken"`
	Step               string `json:"Step"`
	RotationToken      string `json:"RotationToken"`
}

type RotationConfig struct {
	arn   *string
	token *string
	stage string
}

var (
	cfg aws.Config
)

// Placeholder substituted for any credential-looking text.
const redacted = "***REDACTED***"

// Maximum length of a single value copied into a log record.
const maxLoggedLength = 512

var (
	// Credential shapes that the MongoDB driver, the Atlas SDK and the AWS SDK
	// embed in their error messages: URI user-info sections and key/value pairs.
	// RE2 has no lookbehind, so the character preceding the key is captured and
	// re-emitted; that keeps ARN segments such as ":secret:my-secret-name"
	// readable, since those identify the secret rather than the credential.
	uriCredentialRe      = regexp.MustCompile(`(//[^/\s:@]+:)([^@\s/]+)(@)`)
	keyValueCredentialRe = regexp.MustCompile(`(?i)(^|[^:])(password|passwd|pwd|secret|token|private_key)("?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;,&"']+)`)

	// Characters that could forge a new log entry (CRLF) or corrupt the stream.
	controlCharacterRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// Scrub
//
// Renders a value as a string that is safe to write to the log stream.
//
//	Credential-looking substrings are masked, control characters (which could be
//	used to forge log entries) are collapsed to spaces, and the result is
//	truncated so a hostile value cannot flood the log group.
//
//	Args:
//	    value (any): The value to render, typically an error or a string
//
//	Returns:
//	    string: The sanitized representation of the value
func Scrub(value any) string {
	var text string
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		text = typed
	case error:
		text = typed.Error()
	default:
		text = fmt.Sprintf("%v", typed)
	}
	text = uriCredentialRe.ReplaceAllString(text, "${1}"+redacted+"${3}")
	text = keyValueCredentialRe.ReplaceAllString(text, "${1}${2}${3}"+redacted)
	text = controlCharacterRe.ReplaceAllString(text, " ")
	if len(text) > maxLoggedLength {
		text = text[:maxLoggedLength] + "...(truncated)"
	}
	return text
}

// MaskIdentifier
//
// Shortens an opaque identifier so log lines stay correlatable without publishing it.
//
//	Args:
//	    value (string): The identifier, typically a secret version id or rotation token
//
//	Returns:
//	    string: The leading characters of the identifier followed by an ellipsis
func MaskIdentifier(value string) string {
	text := Scrub(value)
	if len(text) <= 8 {
		return redacted
	}
	return text[:8] + "..."
}

// InitAWS
//
//	This function initializes the AWS SDK with the provided credentials.
//
//	Args:
//	    None
//
//	Returns:
//	    None
func InitAWS() {
	// Load AWS configuration
	initConfig, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		// Runs from init(), outside the scrubbing boundary of HandleRequest.
		log.Fatalf("unable to load SDK config, %v", Scrub(err))
	}
	cfg = initConfig
}

// InitMongoDBAtlas
//
//	This function initializes the MongoDB Atlas API client with the provided credentials.
//
//	Args:
//	    None
//
//	Returns:
//	    admin.APIClient: MongoDB Atlas API client
//	    error: Error if the MongoDB Atlas API client could not be initialized
func InitMongoDBAtlas() (*admin.APIClient, error) {
	smClient := secretsmanager.NewFromConfig(cfg)
	var mongoAdmin *admin.APIClient = nil
	// Retrieve MongoDB Atlas credentials from AWS Secrets Manager
	secretName := os.Getenv("MONGODB_ATLAS_SECRET_NAME")
	if secretName == "" {
		return nil, fmt.Errorf("MONGODB_ATLAS_SECRET_NAME environment variable is not set")
		// Raise an error if the secret name is not set
	}
	// retrieve the secret value should marshal into a map[string]string
	var secretData map[string]string
	secretValue, err := smClient.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret value: %w", err)
	} else {
		// convert the secretValue.SecretString to a map[string]string
		if secretValue.SecretString == nil {
			return nil, fmt.Errorf("secret value is nil")
		}
		if err := json.Unmarshal([]byte(*secretValue.SecretString), &secretData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret value: %w", err)
		}
		publicKey := secretData["public_key"]
		privateKey := secretData["private_key"]
		mongoAdmin, err = admin.NewClient(admin.UseDigestAuth(publicKey, privateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create MongoDB Atlas API client: %w", err)
		}
		log.Printf("MongoDB Atlas API client initialized successfully with public key")
	}
	if mongoAdmin == nil {
		return nil, fmt.Errorf("failed to initialize MongoDB Atlas API client")
	}

	return mongoAdmin, nil
}

func init() {
	InitAWS()
}

// CreateSecret
//
// Generate a new secret
//
//	This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
//	new secret and put it with the passed in token.
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version
func CreateSecret(ctx context.Context, smClient *secretsmanager.Client, arn string, token string) error {
	currentDict, err := GetSecretDict(ctx, smClient, RotationConfig{
		arn:   &arn,
		stage: "AWSCURRENT",
	})
	if err != nil {
		return fmt.Errorf("createSecret: Failed to get current secret for %v: %w, will try to get pending secret", arn, err)
	}
	// Now try to get the secret version, if that fails, put a new secret
	_, err = GetSecretDict(ctx, smClient, RotationConfig{
		arn:   &arn,
		stage: "AWSPENDING",
		token: &token,
	})
	if err != nil {
		randomPass, err := GetRandomPassword(ctx, smClient)
		if err != nil {
			return fmt.Errorf("CreateSecret: Failed to generate random password: %w", err)
		}
		currentDict["password"] = randomPass
		connString, ok := currentDict["connection_string"]
		if ok && strings.TrimSpace(connString) != "" {
			_, err = GenerateConnectionString("connection_string", currentDict, randomPass)
			if err != nil {
				return fmt.Errorf("CreateSecret: Failed to generate random password for connection_string: %w", err)
			}
		}
		connStringSrv, ok := currentDict["connection_string_srv"]
		if ok && strings.TrimSpace(connStringSrv) != "" {
			_, err = GenerateConnectionString("connection_string_srv", currentDict, randomPass)
			if err != nil {
				return fmt.Errorf("CreateSecret: Failed to generate random password for connection_string_srv: %w", err)
			}
		}
		privConnString, ok := currentDict["private_connection_string"]
		if ok && strings.TrimSpace(privConnString) != "" {
			_, err = GenerateConnectionString("private_connection_string", currentDict, randomPass)
			if err != nil {
				return fmt.Errorf("CreateSecret: Failed to generate random password for private_connection_string: %w", err)
			}
		}
		privConnStringSrv, ok := currentDict["private_connection_string_srv"]
		if ok && strings.TrimSpace(privConnStringSrv) != "" {
			_, err = GenerateConnectionString("private_connection_string_srv", currentDict, randomPass)
			if err != nil {
				return fmt.Errorf("CreateSecret: Failed to generate random password for private_connection_string_srv: %w", err)
			}
		}
		jsonMarshal, err := json.Marshal(currentDict)
		if err != nil {
			return fmt.Errorf("CreateSecret: Failed to marshal secret: %w", err)
		}
		jsonString := string(jsonMarshal)

		log.Printf("createSecret: Creating secret for %v", Scrub(arn))
		_, err = smClient.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:           &arn,
			ClientRequestToken: &token,
			SecretString:       &jsonString,
			VersionStages:      []string{"AWSPENDING"},
		})
		if err != nil {
			return fmt.Errorf("createSecret: Failed to put secret for %v: %w", arn, err)
		}
		log.Printf("createSecret: Successfully created secret for %v and version %v", Scrub(arn), MaskIdentifier(token))
	} else {
		log.Printf("createSecret: Successfully retrieved secret for %v", Scrub(arn))
	}
	return nil
}

// SetSecret
//
// Set the pending secret in the database
//
//	This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
//	tries to login with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING password
//	as the user password in the database. Else, it throws a ValueError.
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version
func SetSecret(ctx context.Context, smClient *secretsmanager.Client, mongoAdmin *admin.APIClient, arn string, token string) error {
	// Get the pending secret
	pendingDict, err := GetSecretDict(ctx, smClient, RotationConfig{
		arn:   &arn,
		stage: "AWSPENDING",
		token: &token,
	})
	if err != nil {
		return fmt.Errorf("SetSecret: Failed to get pending secret for %v: %w", arn, err)
	}
	username := pendingDict["username"]
	password := pendingDict["password"]
	authDatabase, ok := pendingDict["auth_database"]
	if !ok {
		authDatabase = "admin"
	}
	projectName, ok := pendingDict["project_name"]
	if !ok {
		return fmt.Errorf("SetSecret: Failed to get project_name for %v, please update with proper mongodbatlas management module", arn)
	}
	projectId, ok := pendingDict["project_id"]
	if !ok {
		return fmt.Errorf("SetSecret: Failed to get project_id for %v, please update with proper mongodbatlas management module", arn)
	}
	project, _, err := mongoAdmin.ProjectsApi.GetProject(ctx, projectId).Execute()
	if err != nil {
		return fmt.Errorf("SetSecret: Failed to get project %v - %v : %w", projectId, projectName, err)
	}
	user, _, err := mongoAdmin.DatabaseUsersApi.GetDatabaseUser(ctx, *project.Id, authDatabase, username).Execute()
	if err != nil {
		return fmt.Errorf("SetSecret: Failed to get user %v - %v : %w", username, projectName, err)
	}
	user.Password = &password
	_, _, err = mongoAdmin.DatabaseUsersApi.UpdateDatabaseUser(ctx, *project.Id, authDatabase, username, user).Execute()
	if err != nil {
		return fmt.Errorf("SetSecret: Failed to update user %v - %v : %w", username, projectName, err)
	}
	log.Printf("SetSecret: Successfully set secret for %v", Scrub(arn))
	return nil
}

// TestSecret
//
// Test the pending secret against the database
//
//	This method tries to log into the database with the secrets staged with AWSPENDING and runs
//	a permissions check to ensure the user has the corrrect permissions.
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version
func TestSecret(ctx context.Context, smClient *secretsmanager.Client, mongoAdmin *admin.APIClient, arn string, token string) error {
	secretDict, err := GetSecretDict(ctx, smClient, RotationConfig{
		arn:   &arn,
		token: &token,
		stage: "AWSPENDING",
	})
	if err != nil {
		return fmt.Errorf("TestSecret: Failed to get pending secret for %v: %w", arn, err)
	}
	conn, err := GetConnection(ctx, secretDict)
	if err != nil {
		return fmt.Errorf("TestSecret: Failed to get connection for %v: %w", arn, err)
	}

	defer func() {
		if disconnectErr := conn.Disconnect(ctx); disconnectErr != nil {
			log.Printf("TestSecret: Failed to disconnect from MongoDB: %v", Scrub(disconnectErr))
		}
	}()

	err = conn.Ping(ctx, nil)
	if err != nil {
		return fmt.Errorf("TestSecret: Failed to ping MongoDB with pending secret for %v: %v", Scrub(arn), Scrub(err))
	} else {
		log.Printf("TestSecret: Successfully pinged MongoDB with pending secret for %v", Scrub(arn))
	}

	return nil
}

// FinishSecret
//
// Finish the rotation by marking the pending secret as current
//
//	This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version
func FinishSecret(ctx context.Context, smClient *secretsmanager.Client, arn string, token string) {
	var currentVersion string = ""
	metadata, err := smClient.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: &arn,
	})
	if err != nil {
		log.Printf("finishSecret: Failed to describe secret for %v: %v", Scrub(arn), Scrub(err))
		return
	}
	for version, labels := range metadata.VersionIdsToStages {
		if slices.Contains(labels, "AWSCURRENT") {
			if strings.EqualFold(version, token) {
				log.Printf("FinishSecret: Version %v already marked as AWSCURRENT for %v", MaskIdentifier(version), Scrub(arn))
				return
			}
			currentVersion = version
			break
		}
	}
	_, err = smClient.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            &arn,
		VersionStage:        aws.String("AWSCURRENT"),
		MoveToVersionId:     &token,
		RemoveFromVersionId: &currentVersion,
	})
	if err != nil {
		log.Printf("finishSecret: Failed to stage secret for %v: %v", Scrub(arn), Scrub(err))
		return
	}
	_, err = smClient.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            &arn,
		VersionStage:        aws.String("AWSPENDING"),
		RemoveFromVersionId: &token,
	})
	if err != nil {
		log.Printf("finishSecret: Failed to remove pending stage for %v: %v", Scrub(arn), Scrub(err))
		return
	}
	log.Printf("FinishSecret: Successfully set AWSCURRENT stage to version %v for secret %v.", MaskIdentifier(token), Scrub(arn))
}

// GetConnection
//
// Get the connection to the database
//
//	This method tries to login to the database with the secret staged with the given stage.
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version
//
//	    stage (string): The stage identifying the secret version
//
//	Returns:
//	    *mongo.Client: The connection to the database
//	    error: Error if the connection could not be established
func GetConnection(ctx context.Context, secretDict map[string]string) (*mongo.Client, error) {
	// Try with private_connection_string_srv first, then private_connection_string, then connection_string_srv, then connection_string
	var uri string
	var conn *mongo.Client
	var err error = nil
	// Try with private_connection_string_srv first
	log.Printf("GetConnection: Trying with private_connection_string_srv")
	uri, ok := secretDict["private_connection_string_srv"]
	if ok {
		conn, err = mongo.Connect(options.Client().ApplyURI(uri))
		if err != nil {
			err = fmt.Errorf("GetConnection: Failed to connect to MongoDB with private_connection_string_srv: %v", Scrub(err))
		} else {
			return conn, nil
		}
	}
	// Now try with private_connection_string
	log.Printf("GetConnection: Trying with private_connection_string")
	uri, ok = secretDict["private_connection_string"]
	if ok {
		conn, err = mongo.Connect(options.Client().ApplyURI(uri))
		if err != nil {
			err = fmt.Errorf("GetConnection: Failed to connect to MongoDB with private_connection_string: %v", Scrub(err))
		} else {
			return conn, nil
		}
	}
	// Now try with connection_string_srv
	log.Printf("GetConnection: Trying with connection_string_srv")
	uri, ok = secretDict["connection_string_srv"]
	if ok {
		conn, err = mongo.Connect(options.Client().ApplyURI(uri))
		if err != nil {
			err = fmt.Errorf("GetConnection: Failed to connect to MongoDB with connection_string_srv: %v", Scrub(err))
		} else {
			return conn, nil
		}
	}
	// Now try with connection_string
	log.Printf("GetConnection: Trying with connection_string")
	uri, ok = secretDict["connection_string"]
	if ok {
		conn, err = mongo.Connect(options.Client().ApplyURI(uri))
		if err != nil {
			err = fmt.Errorf("GetConnection: Failed to connect to MongoDB with connection_string: %v", Scrub(err))
		} else {
			return conn, nil
		}
	}
	return nil, err
}

// GetSecretDict
//
// Gets the secret dictionary corresponding for the secret arn, stage, and token
//
//	This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	    arn (string): The secret ARN or other identifier
//
//	    token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
//
//	    stage (string): The stage identifying the secret version
//
//	Returns:
//	    SecretDictionary: Secret dictionary
func GetSecretDict(ctx context.Context, smClient *secretsmanager.Client, config RotationConfig) (map[string]string, error) {
	// Retrieve the secret value
	var secretValue *secretsmanager.GetSecretValueOutput
	var err error
	if config.token != nil {
		secretValue, err = smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId:     config.arn,
			VersionId:    config.token,
			VersionStage: &config.stage,
		})
	} else {
		secretValue, err = smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId:     config.arn,
			VersionStage: &config.stage,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret value: %w", err)
	}
	if secretValue.SecretString == nil {
		return nil, fmt.Errorf("secret value is nil")
	}
	var secretDict map[string]string
	if err := json.Unmarshal([]byte(*secretValue.SecretString), &secretDict); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret value: %w", err)
	}
	supported_engines := []string{"mongodbatlas"}
	if _, ok := secretDict["engine"]; !ok || !slices.Contains(supported_engines, secretDict["engine"]) {
		return nil, fmt.Errorf("unsupported engine: %v", secretDict["engine"])
	}
	return secretDict, nil

}

// GetRandomPassword
//
// Generates a random new password. Generator loads parameters that affects the content of the resulting password from the environment
//
//	variables. When environment variable is missing sensible defaults are chosen.
//
//	Supported environment variables:
//	    - EXCLUDE_CHARACTERS
//	    - PASSWORD_LENGTH
//	    - EXCLUDE_NUMBERS
//	    - EXCLUDE_PUNCTUATION
//	    - EXCLUDE_UPPERCASE
//	    - EXCLUDE_LOWERCASE
//	    - REQUIRE_EACH_INCLUDED_TYPE
//
//	Args:
//	    service_client (client): The secrets manager service client
//
//	Returns:
//	    string: The randomly generated password.
func GetRandomPassword(ctx context.Context, smClient *secretsmanager.Client) (string, error) {
	excludeCharacters, ok := os.LookupEnv("EXCLUDE_CHARACTERS")
	if !ok {
		excludeCharacters = ":/\"\\'\\\\$%&*()[]{}<>?!.,;|`@"
	}
	passwordLengthStr, ok := os.LookupEnv("PASSWORD_LENGTH")
	if !ok {
		passwordLengthStr = "32"
	}
	passwordLength, err := strconv.ParseInt(passwordLengthStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid PASSWORD_LENGTH value: %v", Scrub(err))
	}
	excludeNumbers := GetEnvironmentBool("EXCLUDE_NUMBERS", false)
	excludePunctuation := GetEnvironmentBool("EXCLUDE_PUNCTUATION", false)
	excludeUppercase := GetEnvironmentBool("EXCLUDE_UPPERCASE", false)
	excludeLowercase := GetEnvironmentBool("EXCLUDE_LOWERCASE", false)
	requireEachIncludedType := GetEnvironmentBool("REQUIRE_EACH_INCLUDED_TYPE", false)

	passwd, err := smClient.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
		ExcludeCharacters:       &excludeCharacters,
		PasswordLength:          &passwordLength,
		ExcludeNumbers:          &excludeNumbers,
		ExcludePunctuation:      &excludePunctuation,
		ExcludeUppercase:        &excludeUppercase,
		ExcludeLowercase:        &excludeLowercase,
		RequireEachIncludedType: &requireEachIncludedType,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return *passwd.RandomPassword, nil
}

// GetEnvironmentBool
//
// Get environment variable as boolean
//
//	Args:
//	    variableName (string): The environment variable name
//
//	    defaultValue (bool): The default value if the environment variable is not set
//
//	Returns:
//	    bool: The value of the environment variable as boolean.
func GetEnvironmentBool(variableName string, defaultValue bool) bool {
	value, ok := os.LookupEnv(variableName)
	if !ok {
		return defaultValue
	}
	validValues := []string{"true", "t", "1", "yes", "y"}
	return slices.Contains(validValues, strings.ToLower(value))
}

// GenerateConnectionString
//
// Generate connection string for the given key
//
//	Args:
//	    key (string): The key to generate connection string for
//
//	    secretDict (map[string]string): The secret dictionary
//
//	    password (string): The password to use for the connection string
//
//	Returns:
//	    map[string]string: The secret dictionary with the connection string generated for the given key
//	    error: The error if any
func GenerateConnectionString(key string, secretDict map[string]string, password string) (map[string]string, error) {
	var supportedStrings = []string{"connection_string", "connection_string_srv", "private_connection_string", "private_connection_string_srv"}
	if !slices.Contains(supportedStrings, key) {
		return nil, fmt.Errorf("invalid key: %v", key)
	}
	// Atlas owns the host list, the replica set options and the SRV scheme, so the
	// stored URI is parsed and only its user-info section is replaced. Splitting the
	// string by hand panicked on a URI with no path and mis-detected the host when a
	// credential contained '@'.
	parsed, err := url.Parse(secretDict[key])
	if err != nil {
		return nil, fmt.Errorf("failed to parse %v as a connection URI: %v", key, Scrub(err))
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("failed to parse %v as a connection URI: no host found", key)
	}
	// url.UserPassword percent-encodes for the user-info section. url.QueryEscape,
	// used previously, encodes a space as '+', which is not decoded back to a space
	// there and so corrupted any credential containing one.
	parsed.User = url.UserPassword(secretDict["username"], password)
	secretDict[key] = parsed.String()
	return secretDict, nil
}

// HandleRequest
//
// *Secrets Manager MongoDB Atlas Handler*
//
//	  This handler uses the single-user rotation scheme to rotate an MongoDB Atlas user credential. This rotation
//	  scheme logs into MongoDB Atlas API and rotates the user's password, immediately invalidating the
//	  user's previous password.
//
//	  The Secret SecretString is expected to be a JSON string with the following format:
//	  {
//			'engine': <required: must be set to 'mongodbatlas'>,
//			'host': <required: instance host name>,
//			'username': <required: username>,
//			'password': <required: password>,
//			'project_name': <required: project name>,
//			'project_id': <optional: project id>,
//			'url': <optional: connection string URL>,
//			'url_srv': <optional: SRV connection string URL>,
//			'private_url': <optional: private connection string URL>,
//			'private_url_srv': <optional: private SRV connection string URL>,
//			'connection_string': <optional: connection string built from url field>,
//			'connection_string_srv': <optional: SRV connection string built from url_srv field>,
//			'private_connection_string': <optional: private connection string built from private_url field>,
//			'private_connection_string_srv': <optional: private SRV connection string built from private_url_srv field>
//	  }
//
//	  Args:
//	      event (dict): Lambda dictionary of event parameters. These keys must include the following:
//	          - SecretId: The secret ARN or identifier
//	          - ClientRequestToken: The ClientRequestToken of the secret version
//	          - Step: The rotation step (one of createSecret, SetSecret, testSecret, or finishSecret)
//
//	      context (LambdaContext): The Lambda runtime information
func HandleRequest(ctx context.Context, event json.RawMessage) error {
	if err := rotateSecret(ctx, event); err != nil {
		log.Printf("HandleRequest: Rotation failed: %v", Scrub(err))
		return fmt.Errorf("rotation failed, see the function log for details")
	}
	return nil
}

// rotateSecret
//
// Runs the rotation step requested by the event.
//
//	Errors returned here are reported by HandleRequest after scrubbing, so they
//	may carry driver detail without reaching the runtime log verbatim.
//
//	Args:
//	    ctx (context.Context): The Lambda invocation context
//
//	    event (json.RawMessage): The raw Secrets Manager rotation event
//
//	Returns:
//	    error: Error if the requested rotation step failed
func rotateSecret(ctx context.Context, event json.RawMessage) error {
	var smEvent SecretsManagerEvent
	if err := json.Unmarshal(event, &smEvent); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}
	mongoAdmin, err := InitMongoDBAtlas()
	if err != nil {
		return fmt.Errorf("failed to initialize MongoDB Atlas API client: %v", Scrub(err))
	}
	smClient := secretsmanager.NewFromConfig(cfg)
	arn := smEvent.SecretId
	token := smEvent.ClientRequestToken
	log.Printf("HandleRequest: Received step %v for secret %v, version %v", Scrub(smEvent.Step), Scrub(arn), MaskIdentifier(token))
	// Describe the secret that was sent to the Lambda function with the event
	secret, err := smClient.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: &smEvent.SecretId,
	})
	if err != nil {
		return fmt.Errorf("failed to describe secret: %w", err)
	}
	// Make Sure the version is staged correctly
	if secret.RotationEnabled != nil && !*secret.RotationEnabled {
		return fmt.Errorf("secret %s is not enabled for rotation", *secret.Name)
	}
	secretVersions := secret.VersionIdsToStages
	secretVersion, ok := secretVersions[token]
	if !ok {
		return fmt.Errorf("secret version %v not found, for secret %v", token, arn)
	}

	if slices.Contains(secretVersion, "AWSCURRENT") {
		log.Printf("secret version %v is in current state, for secret %v", MaskIdentifier(token), Scrub(arn))
		return nil
	} else if !slices.Contains(secretVersion, "AWSPENDING") {
		return fmt.Errorf("secret version %v not in pending state, for secret %v", token, arn)
	}

	// Call the appropriate step function based on the event
	switch smEvent.Step {
	case "createSecret":
		err = CreateSecret(ctx, smClient, arn, token)
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	case "setSecret":
		err = SetSecret(ctx, smClient, mongoAdmin, arn, token)
		if err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}
	case "testSecret":
		err = TestSecret(ctx, smClient, mongoAdmin, arn, token)
		if err != nil {
			return fmt.Errorf("failed to test secret: %w", err)
		}
	case "finishSecret":
		FinishSecret(ctx, smClient, arn, token)
	default:
		return fmt.Errorf("unrecognized step parameter: %v, secret: %v", smEvent.Step, arn)
	}

	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
