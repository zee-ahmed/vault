package aws

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hashicorp/go-cleanhttp"
)

const AWSFederationURL = "https://signin.aws.amazon.com/federation"
const AWSConsoleURL = "https://console.aws.amazon.com/"
const AWSConsoleRegionURL = "https://%s.console.aws.amazon.com/"

type awsSession struct {
	SessionID    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

type awsSigninToken struct {
	SigninToken string `json:"SigninToken"`
}

func (b *backend) federationSigninCreate(accessKeyId, secretAccessKey, sessionToken, region string) (string, error) {
	// encode session into JSON string
	session := &awsSession{
		SessionID:    accessKeyId,
		SessionKey:   secretAccessKey,
		SessionToken: sessionToken,
	}
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("Error marshalling sesion JSON: %s", err)
	}

	federationParams := url.Values{}
	federationParams.Set("Action", "getSigninToken")
	federationParams.Set("Session", string(sessionBytes))

	http := cleanhttp.DefaultClient()
	federationResponse, err := http.Get(AWSFederationURL + "?" + federationParams.Encode())
	if err != nil {
		return "", fmt.Errorf("Error getting federation signin token: %s", err)
	}
	defer federationResponse.Body.Close()

	signinToken := awsSigninToken{}
	err = json.NewDecoder(federationResponse.Body).Decode(&signinToken)
	if err != nil {
		return "", fmt.Errorf("Error parsing federation signin token: %s", err)
	}

	consoleURL := AWSConsoleURL
	if region != "" {
		consoleURL = fmt.Sprintf(AWSConsoleRegionURL, region)
	}

	signinParams := url.Values{}
	signinParams.Set("Action", "login")
	signinParams.Set("Issuer", "vault")
	signinParams.Set("Destination", consoleURL)
	signinParams.Set("SigninToken", signinToken.SigninToken)

	return AWSFederationURL + "?" + signinParams.Encode(), nil
}
