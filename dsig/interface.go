package dsig

import (
	"github.com/lestrrat-go/libxml2/types"
	"github.com/reb00ter/xmlsec/clib"
	"github.com/reb00ter/xmlsec/crypto"
)

type TransformID clib.TransformID

var (
	ExclC14N     = TransformID(clib.ExclC14N)
	InclC14N     = TransformID(clib.InclC14N)
	Enveloped    = TransformID(clib.Enveloped)
	Sha1         = TransformID(clib.Sha1)
	RsaSha1      = TransformID(clib.RsaSha1)
	Gost2012_256 = TransformID(clib.Gost2012_256)
	Gost2012_512 = TransformID(clib.Gost2012_512)
)

type Ctx struct {
	ptr uintptr // *C.xmlSecDSigCtx
}

type Signature struct {
	keyinfo    types.Node
	refnode    types.Node
	signmethod TransformID
	signnode   types.Node
}

// SignatureVerify is a convenience wrapper for things that can verify
// XML strings
type SignatureVerify struct {
	key *crypto.Key
}
