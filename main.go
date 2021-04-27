package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type parameters struct {
	region      string
	endpointURL string
	users       []string
	skipOpt     skipResources
}

func parseOnlyOption(s string) (skipResources, error) {
	opt := skipResources{}
	for _, f := range strings.Split(s, ",") {
		switch f {
		case "lp":
			opt.loginProfile = true
		case "ak":
			opt.AccessKeys = true
		case "sc":
			opt.SigningCertificates = true
		case "sk":
			opt.SSHPublicKeys = true
		case "ssc":
			opt.ServiceSpecificCredentials = true
		case "md":
			opt.MFADevices = true
		case "ip":
			opt.InlinePolicies = true
		case "mp":
			opt.ManagedPolicies = true
		case "g":
			opt.Groups = true
		case "u":
			opt.User = true
		default:
			return skipResources{}, fmt.Errorf("unknown option is received: %s", f)
		}
	}

	// If the skip option is used, it does not delete IAM User.
	if len(s) != 0 {
		opt.User = true
	}

	return opt, nil
}

func parseArgs(args []string) (parameters, error) {
	var skipOpt string
	params := parameters{}

	skipOptMsg := `Use it if you want to skip to delete specified resources.
The tool does not delete IAM User if you specify any one of the resources.

Example:
# Delete resources depending on 'sample-user' without Login Profile
$ aws-del-user --skip u,lp sample-user

You can specify the following resources.
- ak: Access Key
- g: IAM Group
- ip: Inline Policy
- lp: Login Profile
- md: MFA Device
- mp: Managed Policy
- sc: Signing Certificate
- sk: SSH Public Key
- ssc: Service Specific Credential
- u: IAM User`

	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	flags.StringVar(&skipOpt, "skip", "", skipOptMsg)
	flags.StringVar(&params.region, "region", "", "The name of the region. Override the region configured in config file.")
	flags.StringVar(&params.endpointURL, "endpoint-url", "", "The url of endpoint. Override default endpoint with the given URL.")
	flags.Usage = func() {
		fmt.Fprintf(os.Stdout, "aws-del-user is a tool for deleting IAM User.\n\n")
		fmt.Fprintf(os.Stdout, "Usage: \n")
		fmt.Fprintf(os.Stdout, "  aws-del-user [OPTION] <USER_NAME>...\n\n")
		fmt.Fprintf(os.Stdout, "Options: \n")
		flags.PrintDefaults()
	}
	flags.Parse(args[1:])

	params.users = flags.Args()
	if len(params.users) == 0 {
		return parameters{}, errors.New("no users")
	}

	var err error
	params.skipOpt, err = parseOnlyOption(skipOpt)
	if err != nil {
		return parameters{}, err
	}

	return params, nil
}

func loadConfig(params parameters) (aws.Config, error) {
	paramsFns := []func(*config.LoadOptions) error{}

	if params.endpointURL != "" {
		endpointResolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			return aws.Endpoint{URL: params.endpointURL, SigningRegion: params.region}, nil
		})
		paramsFns = append(paramsFns, config.WithEndpointResolver(endpointResolver))
	}

	if params.region != "" {
		paramsFns = append(paramsFns, config.WithRegion(params.region))
	}

	return config.LoadDefaultConfig(context.Background(), paramsFns...)
}

func getDependencyResources(cli client, users []string, skip skipResources) (resourcesByType, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return cli.getDependencyResources(ctx, users, skip)
}

func removeDependencyResources(cli client, resources resourcesByType) (resourcesByType, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return cli.removeDependencyResources(ctx, resources)
}

func getUsers(cli client, users []string) (resourcesByType, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return cli.getUsers(ctx, users)
}

func deleteUsers(cli client, users []string) ([]string, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return cli.deleteUsers(ctx, users)
}

func displayResources(resources resourcesByType) {
	types := []resType{}
	for typ := range resources {
		types = append(types, typ)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

	for _, typ := range types {
		m := make(map[string][]string)
		for _, rs := range resources[typ] {
			m[rs.user] = rs.resources
		}

		fmt.Printf("%s:\n", typ)
		for u, rs := range m {
			for _, r := range rs {
				fmt.Printf("- %s (%s)\n", r, u)
			}
		}
		fmt.Println()
	}
}

func ask(msg string) bool {
	var ans string
	fmt.Print(msg)
	fmt.Scan(&ans)
	return ans == "y"
}

func exec() error {
	params, err := parseArgs(os.Args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig(params)
	if err != nil {
		return err
	}

	cli := client{iam.NewFromConfig(cfg)}
	users, err := getUsers(cli, params.users)
	if err != nil {
		return err
	}
	displayResources(users)

	resources, err := getDependencyResources(cli, params.users, params.skipOpt)
	if err != nil {
		return err
	}

	fmt.Println("Dependency resources to be deleted or detached (Managed Policy, IAM Groups)")
	displayResources(resources)

	if !ask("Delete and Detach the resources and delete user? [y/n]: ") {
		return nil
	}

	unremovedResources, err := removeDependencyResources(cli, resources)
	if err != nil {
		fmt.Println("Could not delete and detach the resources. Please check the errors and retry it.")
		displayResources(unremovedResources)
		return err
	}

	unremovedUsers, err := deleteUsers(cli, params.users)
	if err != nil {
		fmt.Println("Could not delete the users. Please check the errors and retry it.")
		for _, user := range unremovedUsers {
			fmt.Printf("- %s\n", user)
		}
		return err
	}

	fmt.Println("Deleted and detached the all resources!")
	return nil
}

func main() {
	if err := exec(); err != nil {
		fmt.Println(err)
	}
}
