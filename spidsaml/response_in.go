package spidsaml

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	xmlsec "github.com/crewjam/go-xmlsec"
)

const (
	samlVersion       = "2.0"
	samlIssuerFormat  = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	samlNameIDFormat  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	samlSubjectMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// Response represents an incoming SPID Response/Assertion message. We get such messages after an AuthnRequest (Single Sign-On).
type Response struct {
	inMessage
}

// ParseResponse parses a Response/Assertion.
// Validation is performed (see the documentation for the Response::validate()
// method), so this method may return an error.
// A second argument can be supplied, containing the C<ID> of the request message;
// in this case validation will also check the InResponseTo attribute.
func (sp *SP) ParseResponse(r *http.Request, inResponseTo string) (*Response, error) {
	response := &Response{}
	response.SP = sp
	err := response.parse(r, "SAMLResponse")
	if err != nil {
		return nil, err
	}

	err = response.validate(inResponseTo)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// validate performs validation on this message, that is a response from an IDP to a login request
func (response *Response) validate(inResponseTo string) error {
	err := response.inMessage.matchIncomingIDP()
	if err != nil {
		return err
	}

	if inResponseTo != response.InResponseTo() {
		return fmt.Errorf("Invalid InResponseTo: '%s' (expected: '%s')",
			response.InResponseTo(), inResponseTo)
	}

	version := response.Version()
	if version != samlVersion {
		return fmt.Errorf("Invalid Version: '%s'", version)
	}

	issueInstant := response.IssueInstant()
	if _, err := time.Parse(time.RFC3339, issueInstant); err != nil {
		return fmt.Errorf("Invalid issue instant: '%s'", issueInstant)
	}

	// As of current SPID spec, Destination might be populated with the entityID
	// instead of the ACS URL
	destination := response.Destination()
	knownDestination := destination == response.SP.EntityID
	for _, acs := range response.SP.AssertionConsumerServices {
		if acs == destination {
			knownDestination = true
			break
		}
	}
	if !knownDestination {
		return fmt.Errorf("Invalid Destination: '%s'", destination)
	}

	if response.Success() {
		if err := response.validateAssertion(); err != nil {
			return err
		}

		if err := response.validateNameID(); err != nil {
			return err
		}

		if err := response.validateAssertionIssuer(); err != nil {
			return err
		}

		if issueInstant != response.AuthnInstant() {
			return fmt.Errorf("Response/IssueInstant (%s) does not match AuthnInstant (%s)",
				issueInstant, response.AuthnInstant())
		}

		if response.IssuerFormat() != "" && response.IssuerFormat() != samlIssuerFormat {
			return fmt.Errorf("Response/Issuer/Format (%s) is not equal to %s",
				response.IssuerFormat(), samlIssuerFormat)
		}

		if response.AssertionAudience() != response.SP.EntityID {
			return fmt.Errorf("Invalid Audience: '%s' (expected: '%s')",
				response.AssertionAudience(), response.SP.EntityID)
		}

		if response.AssertionInResponseTo() != inResponseTo {
			return fmt.Errorf("Invalid InResponseTo: '%s' (expected: '%s')",
				response.AssertionInResponseTo(), inResponseTo)
		}

		if response.AssertionMethod() != samlSubjectMethod {
			return fmt.Errorf("Invalid Method: '%s' (expected: '%s')",
				response.AssertionMethod(), samlSubjectMethod)
		}

		for _, cert := range response.IDP.CertPEM() {
			err = xmlsec.Verify(cert, response.XML, xmlsec.SignatureOptions{
				XMLID: []xmlsec.XMLIDOption{
					{
						ElementName:      "Assertion",
						ElementNamespace: "",
						AttributeName:    "ID",
					},
					{
						ElementName:      "Response",
						ElementNamespace: "",
						AttributeName:    "ID",
					},
				},
			})
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("Signature verification failed: %s", err.Error())
		}

		// SPID regulations require that Assertion is signed, while Response can be not signed
		if response.doc.FindElement("/Response/Assertion/Signature") == nil {
			return fmt.Errorf("Assertion is not signed")
		}

		now := response.clock.Now().UTC()

		// exact match is ok
		notBefore, err := response.NotBefore()
		if err != nil {
			return err
		}
		if now.Before(notBefore) {
			return fmt.Errorf("Invalid NotBefore: '%s' (now: '%s')",
				notBefore.Format(time.RFC3339), now.Format(time.RFC3339))
		}

		// exact match is *not* ok
		notOnOrAfter, err := response.NotOnOrAfter()
		if err != nil {
			return err
		}
		if now.After(notOnOrAfter) || now.Equal(notOnOrAfter) {
			fmt.Println(string(response.XML))
			return fmt.Errorf("Invalid NotOnOrAfter: '%s' (now: '%s')",
				notOnOrAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		}

		// exact match is *not* ok
		scdNotOnOrAfter, err := response.SubjectConfirmationDataNotOnOrAfter()
		if err != nil {
			return err
		}
		if now.After(scdNotOnOrAfter) || now.Equal(scdNotOnOrAfter) {
			return fmt.Errorf("Invalid SubjectConfirmationData/NotOnOrAfter: '%s' (now: '%s')",
				scdNotOnOrAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		}

		assertionRecipient := response.AssertionRecipient()
		knownRecipient := false
		for _, acs := range response.SP.AssertionConsumerServices {
			if acs == assertionRecipient {
				knownRecipient = true
				break
			}
		}
		if !knownRecipient {
			return fmt.Errorf("Invalid SubjectConfirmationData/@Recipient': '%s'", assertionRecipient)
		}

		if response.Destination() != response.AssertionRecipient() {
			return fmt.Errorf("Mismatch between Destination and SubjectConfirmationData/@Recipient")
		}
	} else {
		// Authentication failed, so we expect no <Assertion> element.
	}

	return nil
}

// Success returns true if authentication succeeded (and thus we got an assertion
// from the Identity Provider). In case of failure, you can call the StatusCode()
// method for more details.
func (response *Response) Success() bool {
	return response.StatusCode() == "urn:oasis:names:tc:SAML:2.0:status:Success"
}

// Session returns a Session object populated with useful information from this
// Response/Assertion. You might want to store this object along with the user
// session of your application, so that you can use it for generating the
// LoginRequest
func (response *Response) Session() *Session {
	return &Session{
		IDPEntityID:  response.IDP.EntityID,
		NameID:       response.NameID(),
		SessionIndex: response.SessionIndex(),
		AssertionXML: response.XML,
		Level:        response.Level(),
		Attributes:   response.Attributes(),
	}
}

// StatusCode returns the value of the <StatusCode> element.
func (response *Response) StatusCode() string {
	return response.doc.FindElement("/Response/Status/StatusCode").SelectAttrValue("Value", "")
}

// StatusCode2 returns the value of the <StatusCode><StatusCode> sub-element.
func (response *Response) StatusCode2() string {
	return response.doc.FindElement("/Response/Status/StatusCode/StatusCode").SelectAttrValue("Value", "")
}

// StatusMessage returns the value of the <StatusMessage> element.
func (response *Response) StatusMessage() string {
	return response.doc.FindElement("/Response/Status/StatusMessage").Text()
}

// NameID returns the value of the <NameID> element.
func (response *Response) NameID() string {
	return response.doc.FindElement("/Response/Assertion/Subject/NameID").Text()
}

// SessionIndex returns the value of the SessionIndex attribute.
func (response *Response) SessionIndex() string {
	return response.doc.FindElement("/Response/Assertion/AuthnStatement").SelectAttrValue("SessionIndex", "")
}

// AuthnInstant returns the value of the AuthnInstant attribute.
func (response *Response) AuthnInstant() string {
	// remove milliseconds
	m1 := regexp.MustCompile(`(\.\d+?)Z$`)
	ii := response.doc.FindElement("/Response/Assertion/AuthnStatement").SelectAttrValue("AuthnInstant", "")
	return m1.ReplaceAllString(ii, "Z")
}

// HasAssertion checks if <Assertion> element exists.
func (response *Response) HasAssertion() bool {
	return response.doc.FindElement("/Response/Assertion") != nil
}

// AssertionID returns the value of the <Assertion><ID> element.
func (response *Response) AssertionID() string {
	return response.doc.FindElement("/Response/Assertion").SelectAttrValue("ID", "")
}

// AssertionVersion returns the value of the <Assertion><Version> element.
func (response *Response) AssertionVersion() string {
	return response.doc.FindElement("/Response/Assertion").SelectAttrValue("Version", "")
}

// AssertionIssueInstant returns the value of the <Assertion><IssueInstant> element.
func (response *Response) AssertionIssueInstant() string {
	// remove milliseconds
	m1 := regexp.MustCompile(`(\.\d+?)Z$`)
	ii := response.doc.FindElement("/Response/Assertion").SelectAttrValue("IssueInstant", "")
	return m1.ReplaceAllString(ii, "Z")
}

// AssertionIssuer returns the value of the <Assertion><Issuer> element.
func (response *Response) AssertionIssuer() string {
	return response.doc.FindElement("/Response/Assertion/Issuer").Text()
}

// AssertionIssuerFormat returns the value of the <Assertion><Issuer> format attribute.
func (response *Response) AssertionIssuerFormat() string {
	return response.doc.FindElement("/Response/Assertion/Issuer").SelectAttrValue("Format", "")
}

// NameIDFormat returns the value of the <Assertion><Subject><NameID><Format> element.
func (response *Response) NameIDFormat() string {
	return response.doc.FindElement("/Response/Assertion/Subject/NameID").SelectAttrValue("Format", "")
}

// NameIDNameQualifier returns the value of the <Assertion><Subject><NameID><NameQualifier> element.
func (response *Response) NameIDNameQualifier() string {
	return response.doc.FindElement("/Response/Assertion/Subject/NameID").SelectAttrValue("NameQualifier", "")
}

// AssertionRecipient returns the value of the <Assertion> Recipient attribute.
func (response *Response) AssertionRecipient() string {
	return response.doc.FindElement("/Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData").SelectAttrValue("Recipient", "")
}

// AssertionAudience returns the value of the <Assertion><Audience> element.
func (response *Response) AssertionAudience() string {
	return response.doc.FindElement("/Response/Assertion/Conditions/AudienceRestriction/Audience").Text()
}

// AssertionInResponseTo returns the value of the <Assertion> InResponseTo attribute.
func (response *Response) AssertionInResponseTo() string {
	return response.doc.FindElement("/Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData").SelectAttrValue("InResponseTo", "")
}

// AssertionMethod returns the value of the <Assertion><Subject><SubjectConfirmation> Method attribute.
func (response *Response) AssertionMethod() string {
	return response.doc.FindElement("/Response/Assertion/Subject/SubjectConfirmation").SelectAttrValue("Method", "")
}

// NotBefore returns the value of the <Assertion> NotBefore attribute.
func (response *Response) NotBefore() (time.Time, error) {
	ts := response.doc.FindElement("/Response/Assertion/Conditions").SelectAttrValue("NotBefore", "")
	return time.Parse(time.RFC3339, ts)
}

// NotOnOrAfter returns the value of the <Assertion> NotOnOrAfter attribute.
func (response *Response) NotOnOrAfter() (time.Time, error) {
	ts := response.doc.FindElement("/Response/Assertion/Conditions").SelectAttrValue("NotOnOrAfter", "")
	return time.Parse(time.RFC3339, ts)
}

// SubjectConfirmationDataNotOnOrAfter returns the value of the <Assertion><SubjectConfirmationData> NotOnOrAfter attribute.
func (response *Response) SubjectConfirmationDataNotOnOrAfter() (time.Time, error) {
	ts := response.doc.FindElement("/Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData").SelectAttrValue("NotOnOrAfter", "")
	return time.Parse(time.RFC3339, ts)
}

// Level returns the SPID level specified in the assertion.
func (response *Response) Level() int {
	ref := response.doc.FindElement("/Response/Assertion/AuthnStatement/AuthnContext/AuthnContextClassRef").Text()
	r, _ := regexp.Compile("https://www.spid.gov.it/SpidL([1-3])")
	res := r.FindStringSubmatch(ref)
	if len(res) == 0 {
		panic(fmt.Errorf("invalid spid AuthnContextClassRef value (%s)", ref))
	}
	i, _ := strconv.Atoi(res[1])
	return i
}

// Attributes returns the attributes carried by the assertion.
func (response *Response) Attributes() map[string]string {
	attributes := make(map[string]string)
	for _, e := range response.doc.FindElements("/Response/Assertion/AttributeStatement/Attribute") {
		attributes[e.SelectAttr("Name").Value] = e.FindElement("AttributeValue").Text()
	}
	return attributes
}

func (response *Response) validateAssertion() error {
	if !response.HasAssertion() {
		return fmt.Errorf("Assertion element not exists")
	}

	if response.AssertionID() == "" {
		return fmt.Errorf("Invalid Assertion ID attribute")
	}

	if version := response.AssertionVersion(); version != samlVersion {
		return fmt.Errorf("Invalid Assertion Version: '%s'", version)

	}

	issueInstant := response.AssertionIssueInstant()
	if _, err := time.Parse(time.RFC3339, issueInstant); err != nil {
		return fmt.Errorf("Invalid assertion issue instant: '%s'", issueInstant)
	}
	if resIssueInstant := response.IssueInstant(); issueInstant != resIssueInstant {
		return fmt.Errorf("Response/Assertion/IssueInstant (%s) does not match Response/IssueInstant (%s)",
			issueInstant, resIssueInstant)
	}

	return nil
}

func (response *Response) validateNameID() error {
	if response.NameID() == "" {
		return fmt.Errorf("Invalid Response/Assertion/Subject/NameID value")
	}

	if format := response.NameIDFormat(); format != samlNameIDFormat {
		return fmt.Errorf("Response/Assertion/Subject/NameID/Format (%s) does not match (%s)",
			format, samlNameIDFormat)
	}

	if response.NameIDNameQualifier() == "" {
		return fmt.Errorf("Invalid Response/Assertion/Subject/NameID/NameQualifier value")
	}

	return nil
}

func (response *Response) validateAssertionIssuer() error {
	if response.Issuer() != response.AssertionIssuer() {
		return fmt.Errorf("Response/Issuer (%s) does not match Assertion/Issuer (%s)",
			response.Issuer(), response.AssertionIssuer())
	}

	if response.AssertionIssuerFormat() != samlIssuerFormat {
		return fmt.Errorf("Response/Assertion/Issuer/Format (%s) is not equal to %s",
			response.AssertionIssuerFormat(), samlIssuerFormat)
	}

	return nil
}
