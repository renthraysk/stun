package stun

type errorString string

func (e errorString) Error() string { return string(e) }

const (
	ErrMalformedAttribute                  = errorString("malformed attribute")
	ErrNotASTUNMessage                     = errorString("not a stun message")
	ErrFingerprint                         = errorString("fingerprint check failed")
	ErrMessageIntegrity                    = errorString("messageintegrity check failed")
	ErrMessageIntegritySHA256              = errorString("messageintegritysha256 check failed")
	ErrUnknownPasswordAlgorithm            = errorString("unknown password algorithm")
	ErrUnexpectedEOF                       = errorString("unexpected EOF")
	ErrUsernameTooLong                     = errorString("username too long")
	ErrRealmTooLong                        = errorString("realm too long")
	ErrNonceTooLong                        = errorString("nonce too long")
	ErrSoftwareTooLong                     = errorString("software too long")
	ErrMissingUsername                     = errorString("missing username")
	ErrMissingRealm                        = errorString("missing realm")
	ErrInvalidUserHashLength               = errorString("invalid userhash length")
	ErrInvalidErrorCode                    = errorString("invalid error code")
	ErrReasonTooLong                       = errorString("reason too long")
	ErrDomainTooLong                       = errorString("domain too long")
	ErrInvalidIPAddress                    = errorString("invalid IP address length")
	ErrInvalidAttributeSequence            = errorString("invalid attribute sequence")
	ErrInvalidMessageIntegritySHA256Length = errorString("invalid MessageIntegritySHA256 length")
	ErrInvalidPriorityComponentID          = errorString("invalid priority component id")
	ErrInvalidUserHash                     = errorString("invalid user hash")
	ErrMissingMessageIntegrityKey          = errorString("missing message integrity key")
	ErrUnknownAddressAttribute             = errorString("unknown address attribute")
	ErrUnknownIPFamily                     = errorString("unknown IP family")

	ErrKeySet     = errorString("key already set previously")
	ErrKeyNotUsed = errorString("key set but no messageintegrity or messageintegritysha256 attributes used")
)
