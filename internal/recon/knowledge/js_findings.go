package knowledge

// JS finding and leak kinds. These are the values used as keys in
// Entity.Content.JSFindings and as JSLeak.Kind, populated by the
// jsintel package's Learn pass.
const (
	JSFindingPEM      = "pem"
	JSFindingAWSKey   = "aws_key"
	JSFindingJWT      = "jwt"
	JSFindingKeyword  = "keyword"
	JSFindingFirebase = "firebase"
	JSFindingEmail    = "email"

	JSFindingRoleCheck = "role_check"
	JSFindingPrivFlag  = "priv_flag"
	JSFindingPrivGate  = "priv_gate"

	JSFindingFeatureToken  = "feature_token"
	JSFindingFeatureBlock  = "feature_block"
	JSFindingFeatureToggle = "feature_toggle"

	JSFindingEnvRef    = "env_ref"
	JSFindingEnvPublic = "env_public"

	JSFindingHostURL       = "host_url"
	JSFindingHostInternal  = "host_internal"
	JSFindingHostPrivateIP = "host_private_ip"

	JSFindingEndpoint = "endpoint"

	JSFindingASTParsed         = "ast_parsed"
	JSFindingASTParseError     = "ast_parse_error"
	JSFindingASTRecovered      = "ast_recovered"
	JSFindingASTRecoveryRun    = "ast_recovery_run"
	JSFindingASTRecoveryScopes = "ast_recovery_scopes"
	JSFindingASTRecoveryParsed = "ast_recovery_parsed"
	JSFindingASTRecoveryFailed = "ast_recovery_failed"

	JSFindingHTTPFlow = "http_flow"
)
