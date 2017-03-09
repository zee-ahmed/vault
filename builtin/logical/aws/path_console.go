package aws

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConsole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "console/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `Lifetime of the token in seconds.
AWS documentation excerpt: The duration, in seconds, that the credentials
should remain valid. Acceptable durations for IAM user sessions range from 900
seconds (15 minutes) to 129600 seconds (36 hours), with 43200 seconds (12
hours) as the default. Sessions for AWS account owners are restricted to a
maximum of 3600 seconds (one hour). If the duration is longer than one hour,
the session for AWS account owners defaults to one hour.`,
				Default: 3600,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConsoleRead,
			logical.UpdateOperation: b.pathConsoleRead,
		},

		HelpSynopsis:    pathConsoleHelpSyn,
		HelpDescription: pathConsoleHelpDesc,
	}
}

func (b *backend) pathConsoleRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp, err := b.pathSTSRead(req, d)
	if err != nil {
		return nil, fmt.Errorf("error retrieving sts: %s", err)
	}

	awsConfig, err := getRootConfig(req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error getting AWS config: %s", err)), nil
	}

	signinURL, err := b.federationSigninCreate(
		resp.Data["access_key"].(string),
		resp.Data["secret_key"].(string),
		resp.Data["security_token"].(string),
		*awsConfig.Region,
	)
	if err != nil {
		return nil, fmt.Errorf("error retrieving federation signin: %s", err)
	}

	resp.Data["signin_url"] = signinURL

	return resp, nil

}

const pathConsoleHelpSyn = `
Generate a signin url for the AWS web console.
`

const pathConsoleHelpDesc = `
This path will generate a new, never before used key pair + security token for
accessing AWS. The IAM policy used to back this key pair will be
the "name" parameter. For example, if this backend is mounted at "aws",
then "aws/sts/deploy" would generate access keys for the "deploy" role.

Note, these credentials are instantiated using the AWS STS backend.

The access keys will have a lease associated with them. The access keys
can be revoked by using the lease ID.
`
