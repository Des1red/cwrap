package knowledge

// Signal = attacker-relevant evidence; no hard types.
type Signal int

const (
	SigHasQueryParams Signal = iota
	SigHasForm
	SigHasJSONBody
	SigStateChanging
	SigAuthBoundary
	SigTokenLike
	SigIDLikeParam
	SigDebugFlag
	SigSensitiveKeyword
	SigFileUpload
	SigAdminSurface
	SigObjectOwnership
	SigPossibleIDOR
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
	default:
		return "UnknownSignal"
	}
}
