package knowledge

// Signal = attacker-relevant evidence; no hard types.
type Signal int

const (
	SigHasQueryParams Signal = iota
	SigPublicAccess
	SigHasForm
	SigHasJSONBody
	SigStateChanging
	SigAuthBoundary
	SigRoleBoundary
	SigTokenLike
	SigIDLikeParam
	SigDebugFlag
	SigSensitiveKeyword
	SigFileUpload
	SigAdminSurface
	SigObjectOwnership
	SigPossibleIDOR
	SigCredentiallessTokenIssuance
	SigBrokenTokenValidation
	SigWeakOpaqueTokenValidation
	SigPermissiveCORS
	SigMissingSecurityHeaders
	SigPermissiveFrameAncestors
)

func (s Signal) String() string {
	switch s {
	case SigHasQueryParams:
		return "HasQueryParams"
	case SigHasForm:
		return "HasForm"
	case SigHasJSONBody:
		return "HasJSONBody"
	case SigStateChanging:
		return "StateChanging"
	case SigAuthBoundary:
		return "AuthBoundary"
	case SigRoleBoundary:
		return "RoleBoundary"
	case SigTokenLike:
		return "TokenLike"
	case SigIDLikeParam:
		return "IDLikeParam"
	case SigDebugFlag:
		return "DebugFlag"
	case SigSensitiveKeyword:
		return "SensitiveKeyword"
	case SigFileUpload:
		return "FileUpload"
	case SigAdminSurface:
		return "AdminSurface"
	case SigObjectOwnership:
		return "ObjectOwnership"
	case SigPossibleIDOR:
		return "PossibleIDOR"
	case SigCredentiallessTokenIssuance:
		return "CredentiallessTokenIssuance"
	case SigBrokenTokenValidation:
		return "BrokenTokenValidation"
	case SigWeakOpaqueTokenValidation:
		return "WeakOpaqueTokenValidation"
	case SigPublicAccess:
		return "PublicAccess"
	case SigPermissiveCORS:
		return "PermissiveCORS"
	case SigMissingSecurityHeaders:
		return "MissingSecurityHeaders"
	case SigPermissiveFrameAncestors:
		return "PermissiveFrameAncestors"
	default:
		return "UnknownSignal"
	}
}
