package xmlsec_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	"github.com/lestrrat-go/libxml2/parser"
	"github.com/reb00ter/xmlsec"
	"github.com/reb00ter/xmlsec/crypto"
	"github.com/reb00ter/xmlsec/dsig"
)

func ExampleSignature_Sign() {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(`<?xml version="1.0" encoding="UTF-8"?>
<Message><Data>Hello, World!</Data></Message>`)

	n, err := doc.DocumentElement()
	if err != nil {
		log.Printf("DocumentElement failed: %s", err)
		return
	}

	// n is the node where you want your signature to be
	// generated under
	sig, err := dsig.NewSignature(n, dsig.ExclC14N, dsig.RsaSha1, "")
	if err != nil {
		log.Printf("failed to create signature: %s", err)
		return
	}

	sig.AddReference(dsig.Sha1, "", "", "")
	sig.AddTransform(dsig.Enveloped)

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate key: %s", err)
		return
	}

	key, err := crypto.LoadKeyFromRSAPrivateKey(privkey)
	if err := sig.Sign(key); err != nil {
		log.Printf("failed to sign: %s", err)
		return
	}

	log.Printf("%s", doc.Dump(true))
}

func ExampleDSigCtx_Sign() {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	ctx, err := dsig.NewCtx(nil)
	if err != nil {
		log.Printf("Failed to create signature context: %s", err)
		return
	}
	defer ctx.Free()

	// This stuff isn't necessary if you already have a key file
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Failed to generate private key: %s", err)
		return
	}
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	pemfile, err := ioutil.TempFile("", "xmlsec-test-")
	if err != nil {
		log.Printf("Failed to create temporary pemfile")
		return
	}
	defer os.Remove(pemfile.Name())
	defer pemfile.Close()

	if err := pem.Encode(pemfile, pemkey); err != nil {
		log.Printf("Failed to write to pemfile: %s", err)
		return
	}

	if err := pemfile.Sync(); err != nil {
		log.Printf("Failed to sync pemfile: %s", err)
		return
	}

	key, err := crypto.LoadKeyFromFile(pemfile.Name(), crypto.KeyDataFormatPem)
	if err != nil {
		log.Printf("Faild to load key: %s", err)
		return
	}
	ctx.SetKey(key)

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(`<?xml version="1.0" encoding="UTF-8"?>
<!-- XML Security Library example: Simple signature template file for sign1 example.  -->
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <KeyName/>
    </KeyInfo>
  </Signature>
</Envelope>`)

	if err != nil {
		log.Printf("Failed to parse source XML: %s", err)
		return
	}
	defer doc.Free()

	if err := ctx.Sign(doc); err != nil {
		log.Printf("Failed to sign document: %s", err)
		return
	}

	log.Printf("%s", doc.Dump(true))
}
