package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"text/template"

	"github.com/beevik/etree"
	"github.com/crewjam/go-xmlsec"
)

// AttributeConsumingService defines, well, an AttributeConsumingService.
type AttributeConsumingService struct {
	ServiceName string
	Attributes  []string
}

// Organization defines SP Organization data
type Organization struct {
	Names        []string
	DisplayNames []string
	URLs         []string
}

type ContactPerson struct {
	Attributes      CPAttributes
	Extensions      CPExtensions
	Company         string
	EmailAddress    string
	TelephoneNumber string
}

type CPAttributes struct {
	ContactType string
}

type CPExtensions struct {
	IPACode                string
	VATNumber              string
	FiscalCode             string
	Public                 bool
	CessionarioCommittente CessionarioCommittente
}

type CessionarioCommittente struct {
	DatiAnagrafici DatiAnagrafici
	Sede           Sede
}

type DatiAnagrafici struct {
	IDFiscaleIVA IDFiscaleIVA
	Anagrafica   Anagrafica
}

type IDFiscaleIVA struct {
	IDPaese  string
	IDCodice string
}

type Anagrafica struct {
	Denominazione string
	Titolo        string
	CodiceEORI    string
}

type Sede struct {
	Indirizzo    string
	NumeroCivico string
	CAP          string
	Comune       string
	Provincia    string
	Nazione      string
}

// SAMLBinding can be either HTTPRedirect or HTTPPost.
type SAMLBinding string

// Constants for SAMLBinding
const (
	HTTPRedirect SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPost     SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SP represents our Service Provider
type SP struct {
	EntityID                   string
	KeyFile                    string
	CertFile                   string
	AssertionConsumerServices  []string
	SingleLogoutServices       map[string]SAMLBinding
	AttributeConsumingServices []AttributeConsumingService
	IDP                        map[string]*IDP
	_cert                      *x509.Certificate
	_key                       *rsa.PrivateKey
	Organization               Organization
	ContactPersons             []ContactPerson
}

// Session represents an active SPID session.
type Session struct {
	IDPEntityID  string
	NameID       string
	SessionIndex string
	AssertionXML []byte
	Level        int
	Attributes   map[string]string
}

// CertPEM returns the of this Service Provider. certificate in PEM format.
func (sp *SP) CertPEM() []byte {
	byteValue, err := ioutil.ReadFile(sp.CertFile)
	if err != nil {
		panic(err)
	}
	return byteValue
}

// Cert returns the certificate of this Service Provider.
func (sp *SP) Cert() *x509.Certificate {
	if sp._cert == nil {
		// read file as a byte array
		byteValue := sp.CertPEM()

		block, _ := pem.Decode(byteValue)
		if block == nil || block.Type != "CERTIFICATE" {
			panic("failed to parse certificate PEM")
		}

		var err error
		sp._cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._cert
}

// Key returns the private key of this Service Provider
func (sp *SP) Key() *rsa.PrivateKey {
	if sp._key == nil {
		// read file as a byte array
		byteValue, _ := ioutil.ReadFile(sp.KeyFile)

		block, _ := pem.Decode(byteValue)
		if block == nil {
			panic("failed to parse private key from PEM file " + sp.KeyFile)
		}

		var err error

		switch block.Type {
		case "RSA PRIVATE KEY":
			sp._key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

		case "PRIVATE KEY":
			var keyOfSomeType interface{}
			keyOfSomeType, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			var ok bool
			sp._key, ok = keyOfSomeType.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("file " + sp.KeyFile + " does not contain an RSA private key")
			}
		default:
			err = errors.New("unknown key type " + block.Type)
		}

		if err != nil {
			panic(err)
		}
	}
	return sp._key
}

// KeyPEM returns the private key of this Service Provider in PEM format
func (sp *SP) KeyPEM() []byte {
	key := sp.Key()
	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}

// GetIDP returns an IDP object representing the Identity Provider matching the given entityID.
func (sp *SP) GetIDP(entityID string) (*IDP, error) {
	if value, ok := sp.IDP[entityID]; ok {
		return value, nil
	}
	return nil, errors.New("IdP not found")
}

// Metadata generates XML metadata of this Service Provider.
func (sp *SP) Metadata() string {
	const tmpl = `<?xml version="1.0"?> 
	<md:EntityDescriptor 
  		xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  		xmlns:spid="https://spid.gov.it/saml-extensions"
		ID="{{.ID}}"
		entityID="{{.EntityID}}"> 

    {{.Signature}}

    <md:SPSSODescriptor  
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"  
        AuthnRequestsSigned="true"  
        WantAssertionsSigned="true"> 
        
        <md:KeyDescriptor use="signing"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor>
        
        {{ range $url, $binding := .SingleLogoutServices }}
        <md:SingleLogoutService 
            Binding="{{ $binding }}"
            Location="{{ $url }}" /> 
        {{ end }}
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> 

        {{ range $index, $url := .AssertionConsumerServices }}
        <md:AssertionConsumerService  
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"  
            Location="{{ $url }}"  
            index="{{ $index }}"  
            isDefault="{{ if gt $index 0 }}false{{ else }}true{{ end }}" /> 
        {{ end }}
        
        {{ range $index, $attcs := .AttributeConsumingServices }}
        <md:AttributeConsumingService index="{{ $index }}"> 
            <md:ServiceName xml:lang="it">{{ $attcs.ServiceName }}</md:ServiceName>
            {{ range $attr := $attcs.Attributes }}
            <md:RequestedAttribute Name="{{ $attr }}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            {{ end }}
        </md:AttributeConsumingService>
        {{ end }}

    </md:SPSSODescriptor> 

    <md:Organization>
        {{ range $name := .Organization.Names }}
        <md:OrganizationName xml:lang="it">{{ $name }}</md:OrganizationName>
        {{ end }}
        {{ range $displayName := .Organization.DisplayNames }}
        <md:OrganizationDisplayName xml:lang="it">{{ $displayName }}</md:OrganizationDisplayName>
        {{ end }}
        {{ range $url := .Organization.URLs }}
        <md:OrganizationURL xml:lang="it">{{ $url }}</md:OrganizationURL>
        {{ end }}
    </md:Organization>

    {{ range $cp := .ContactPersons }}
    <md:ContactPerson contactType="{{$cp.Attributes.ContactType}}"> 
		<md:Extensions {{ if (eq $cp.Attributes.ContactType "billing")}}xmlns:fpa="https://spid.gov.it/invoicing-extensions"{{end}}>
			{{ if $cp.Extensions.Public }}
				<spid:IPACode>{{$cp.Extensions.IPACode}}</spid:IPACode>
				<spid:Public/>
			{{ else }}
			{{  if (ne $cp.Attributes.ContactType "billing")}}
				{{ if $cp.Extensions.VATNumber }}
					<spid:VATNumber>{{ $cp.Extensions.VATNumber }}</spid:VATNumber>
				{{ end }}
				{{ if $cp.Extensions.FiscalCode}}
					<spid:FiscalCode>{{ $cp.Extensions.FiscalCode }}</spid:FiscalCode>
				{{ end }}
				<spid:Private/>
			{{ end }}
			{{ end }}
			{{ if (eq $cp.Attributes.ContactType "billing")}}
				{{$cessionarioCommittente := $cp.Extensions.CessionarioCommittente}}
				<fpa:CessionarioCommittente>
					<fpa:DatiAnagrafici>
						<fpa:IdFiscaleIVA>
							<fpa:IdPaese>{{$cessionarioCommittente.DatiAnagrafici.IDFiscaleIVA.IDPaese}}</fpa:IdPaese>
							<fpa:IdCodice>{{$cessionarioCommittente.DatiAnagrafici.IDFiscaleIVA.IDCodice}}</fpa:IdCodice>
						</fpa:IdFiscaleIVA>
						<fpa:Anagrafica>
						   <fpa:Denominazione>{{$cessionarioCommittente.DatiAnagrafici.Anagrafica.Denominazione}}</fpa:Denominazione> 
						   {{ if $cessionarioCommittente.DatiAnagrafici.Anagrafica.Titolo}}
						   <fpa:Titolo>{{$cessionarioCommittente.DatiAnagrafici.Anagrafica.Titolo}}</fpa:Titolo> 
						   {{ end }}
						   {{ if $cessionarioCommittente.DatiAnagrafici.Anagrafica.CodiceEORI}}
						   <fpa:CodiceEORI>{{$cessionarioCommittente.DatiAnagrafici.Anagrafica.CodiceEORI}}</fpa:CodiceEORI> 
						   {{ end }}
						   </fpa:Anagrafica>
					</fpa:DatiAnagrafici>
					{{$sede := $cp.Extensions.CessionarioCommittente.Sede}}
					<fpa:Sede>
						 <fpa:Indirizzo>{{$sede.Indirizzo}}</fpa:Indirizzo>
						 {{ if $sede.NumeroCivico }}
						 	<fpa:NumeroCivico>{{$sede.NumeroCivico}}</fpa:NumeroCivico>
						 {{ end }}
						 <fpa:CAP>{{$sede.CAP}}</fpa:CAP>
						 <fpa:Comune>{{$sede.Comune}}</fpa:Comune>
						 {{ if $sede.Provincia }}
						 	<fpa:Provincia>{{$sede.Provincia}}</fpa:Provincia>
						 {{ end }}
						 <fpa:Nazione>{{$sede.Nazione}}</fpa:Nazione>
					</fpa:Sede>
				</fpa:CessionarioCommittente>
			{{ end }}
		</md:Extensions>
		{{ if $cp.Company }}
		<md:Company>{{ $cp.Company }}</md:Company>
		{{ end }}
		<md:EmailAddress>{{ $cp.EmailAddress }}</md:EmailAddress>
		{{ if $cp.TelephoneNumber }}
		<md:TelephoneNumber>{{ $cp.TelephoneNumber }}</md:TelephoneNumber>
		{{ end }}
	</md:ContactPerson>
    {{ end }}

</md:EntityDescriptor>
`
	id := "fb36a5dc-9328-4966-8fe2-961011896a48"
	aux := struct {
		*SP
		Cert      string
		ID        string
		Signature string
	}{
		sp,
		base64.StdEncoding.EncodeToString(sp.Cert().Raw),
		id,
		string(sp.signature(id)),
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, aux)
	return string(sp.signMetadata(metadata))
}

func (sp *SP) signMetadata(metadata bytes.Buffer) []byte {
	doc := etree.NewDocument()
	doc.ReadFromBytes(metadata.Bytes())
	root := doc.Root()
	signed, err := xmlsec.Sign(sp.KeyPEM(), metadata.Bytes(), xmlsec.SignatureOptions{
		XMLID: []xmlsec.XMLIDOption{
			{
				ElementName:      root.Tag,
				ElementNamespace: "",
				AttributeName:    "ID",
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return signed
}

func (sp *SP) signature(id string) []byte {
	const tmpl = `
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
       <ds:SignedInfo>
         <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
         <ds:Reference URI="#{{ .ID }}">
           <ds:Transforms>
             <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
             <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
           </ds:Transforms>
           <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
           <ds:DigestValue></ds:DigestValue>
         </ds:Reference>
       </ds:SignedInfo>
       <ds:SignatureValue></ds:SignatureValue>
       <ds:KeyInfo>
         <ds:X509Data>
           <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate>
         </ds:X509Data>
       </ds:KeyInfo>
     </ds:Signature>
`
	aux := struct {
		ID   string
		Cert string
	}{
		id,
		base64.StdEncoding.EncodeToString(sp.Cert().Raw),
	}
	t := template.Must(template.New("sp-signature").Parse(tmpl))
	var signature bytes.Buffer
	t.Execute(&signature, aux)

	return signature.Bytes()
}
