package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type resourceGetter interface {
	getAccessKeys(ctx context.Context, user string) ([]string, error)
	getAttachedPolicies(ctx context.Context, user string) ([]string, error)
	getGroupsForUser(ctx context.Context, user string) ([]string, error)
	getInlinePolicies(ctx context.Context, user string) ([]string, error)
	getLoginProfile(ctx context.Context, user string) ([]string, error)
	getMFADevices(ctx context.Context, user string) ([]string, error)
	getServiceSpecificCredentials(ctx context.Context, user string) ([]string, error)
	getSigningCertificates(ctx context.Context, user string) ([]string, error)
	getSSHPublicKeys(ctx context.Context, user string) ([]string, error)
}

type resourceRemover interface {
	deactivateMFADevices(ctx context.Context, _ string, deviceIds []string) error
	deleteAccessKeys(ctx context.Context, user string, keyIds []string) error
	deleteInlinePolicies(ctx context.Context, user string, policies []string) error
	deleteLoginProfile(ctx context.Context, user string, _ []string) error
	deleteServiceSpecificCredentials(ctx context.Context, user string, certIds []string) error
	deleteSigningCertificates(ctx context.Context, user string, certIds []string) error
	deleteSSHPublicKeys(ctx context.Context, user string, keyIds []string) error
	detachPolicies(ctx context.Context, user string, policies []string) error
	removeUserFromGroup(ctx context.Context, user string, groups []string) error
}

type getResourcesFunc func(ctx context.Context, user string) ([]string, error)
type removeResourcesFunc func(ctx context.Context, user string, resources []string) error

type client struct {
	client *iam.Client
}

func (c *client) getLoginProfile(ctx context.Context, user string) ([]string, error) {
	in := &iam.GetLoginProfileInput{
		UserName: aws.String(user),
	}
	out, err := c.client.GetLoginProfile(ctx, in)
	if err != nil {
		var e *types.NoSuchEntityException
		if errors.As(err, &e) {
			return []string{}, nil
		}
		return nil, err
	}
	return []string{*out.LoginProfile.UserName}, nil
}

func (c *client) deleteLoginProfile(ctx context.Context, user string, _ []string) error {
	in := &iam.DeleteLoginProfileInput{
		UserName: aws.String(user),
	}
	_, err := c.client.DeleteLoginProfile(ctx, in)
	return err
}

func (c *client) getAccessKeys(ctx context.Context, user string) ([]string, error) {
	keyIds := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListAccessKeysInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListAccessKeys(ctx, in)
		if err != nil {
			return nil, err
		}

		ids := make([]string, len(out.AccessKeyMetadata))
		for i, data := range out.AccessKeyMetadata {
			ids[i] = *data.AccessKeyId
		}
		keyIds = append(keyIds, ids...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return keyIds, nil
}

func (c *client) deleteAccessKeys(ctx context.Context, user string, keyIds []string) error {
	for _, id := range keyIds {
		in := &iam.DeleteAccessKeyInput{
			AccessKeyId: aws.String(id),
			UserName:    aws.String(user),
		}
		_, err := c.client.DeleteAccessKey(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getSigningCertificates(ctx context.Context, user string) ([]string, error) {
	certIds := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListSigningCertificatesInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListSigningCertificates(ctx, in)
		if err != nil {
			return nil, err
		}

		ids := make([]string, len(out.Certificates))
		for i, cert := range out.Certificates {
			ids[i] = *cert.CertificateId
		}
		certIds = append(certIds, ids...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return certIds, nil
}

func (c *client) deleteSigningCertificates(ctx context.Context, user string, certIds []string) error {
	for _, id := range certIds {
		in := &iam.DeleteSigningCertificateInput{
			CertificateId: aws.String(id),
			UserName:      aws.String(user),
		}
		_, err := c.client.DeleteSigningCertificate(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getSSHPublicKeys(ctx context.Context, user string) ([]string, error) {
	keyIds := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListSSHPublicKeysInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListSSHPublicKeys(ctx, in)
		if err != nil {
			return nil, err
		}

		ids := make([]string, len(out.SSHPublicKeys))
		for i, key := range out.SSHPublicKeys {
			ids[i] = *key.SSHPublicKeyId
		}
		keyIds = append(keyIds, ids...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return keyIds, nil
}

func (c *client) deleteSSHPublicKeys(ctx context.Context, user string, keyIds []string) error {
	for _, id := range keyIds {
		in := &iam.DeleteSSHPublicKeyInput{
			SSHPublicKeyId: aws.String(id),
			UserName:       aws.String(user),
		}
		_, err := c.client.DeleteSSHPublicKey(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getServiceSpecificCredentials(ctx context.Context, user string) ([]string, error) {
	in := &iam.ListServiceSpecificCredentialsInput{
		UserName: aws.String(user),
	}
	out, err := c.client.ListServiceSpecificCredentials(ctx, in)
	if err != nil {
		return nil, err
	}

	certIds := make([]string, len(out.ServiceSpecificCredentials))
	for i, key := range out.ServiceSpecificCredentials {
		certIds[i] = *key.ServiceSpecificCredentialId
	}

	return certIds, nil
}

func (c *client) deleteServiceSpecificCredentials(ctx context.Context, user string, certIds []string) error {
	for _, id := range certIds {
		in := &iam.DeleteServiceSpecificCredentialInput{
			ServiceSpecificCredentialId: aws.String(id),
			UserName:                    aws.String(user),
		}
		_, err := c.client.DeleteServiceSpecificCredential(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getMFADevices(ctx context.Context, user string) ([]string, error) {
	deviceIds := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListMFADevicesInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListMFADevices(ctx, in)
		if err != nil {
			return nil, err
		}

		ids := make([]string, len(out.MFADevices))
		for i, device := range out.MFADevices {
			ids[i] = *device.SerialNumber
		}
		deviceIds = append(deviceIds, ids...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return deviceIds, nil
}

func (c *client) isVirtualMFADevice(serialNumber string) bool {
	return strings.HasPrefix(serialNumber, "arn:aws:iam::")
}

func (c *client) deactivateMFADevices(ctx context.Context, _ string, deviceIds []string) error {
	for _, id := range deviceIds {
		in := &iam.DeactivateMFADeviceInput{
			SerialNumber: aws.String(id),
		}
		_, err := c.client.DeactivateMFADevice(ctx, in)
		if err != nil {
			return err
		}
		if c.isVirtualMFADevice(id) {
			in := &iam.DeleteVirtualMFADeviceInput{
				SerialNumber: aws.String(id),
			}
			_, err := c.client.DeleteVirtualMFADevice(ctx, in)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *client) getInlinePolicies(ctx context.Context, user string) ([]string, error) {
	policies := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListUserPoliciesInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListUserPolicies(ctx, in)
		if err != nil {
			return nil, err
		}

		names := make([]string, len(out.PolicyNames))
		for i, policy := range out.PolicyNames {
			names[i] = policy
		}
		policies = append(policies, names...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return policies, nil
}

func (c *client) deleteInlinePolicies(ctx context.Context, user string, policies []string) error {
	for _, policy := range policies {
		in := &iam.DeleteUserPolicyInput{
			PolicyName: aws.String(policy),
			UserName:   aws.String(user),
		}
		_, err := c.client.DeleteUserPolicy(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getAttachedPolicies(ctx context.Context, user string) ([]string, error) {
	policies := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListAttachedUserPoliciesInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListAttachedUserPolicies(ctx, in)
		if err != nil {
			return nil, err
		}

		arns := make([]string, len(out.AttachedPolicies))
		for i, policy := range out.AttachedPolicies {
			arns[i] = *policy.PolicyArn
		}
		policies = append(policies, arns...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return policies, nil
}

func (c *client) detachPolicies(ctx context.Context, user string, policies []string) error {
	for _, policy := range policies {
		in := &iam.DetachUserPolicyInput{
			PolicyArn: aws.String(policy),
			UserName:  aws.String(user),
		}
		_, err := c.client.DetachUserPolicy(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getGroupsForUser(ctx context.Context, user string) ([]string, error) {
	groups := make([]string, 0)
	var marker *string
	for {
		in := &iam.ListGroupsForUserInput{
			Marker:   marker,
			UserName: aws.String(user),
		}
		out, err := c.client.ListGroupsForUser(ctx, in)
		if err != nil {
			return nil, err
		}

		names := make([]string, len(out.Groups))
		for i, policy := range out.Groups {
			names[i] = *policy.GroupName
		}
		groups = append(groups, names...)

		marker = out.Marker
		if marker == nil {
			break
		}
	}
	return groups, nil
}

func (c *client) removeUserFromGroup(ctx context.Context, user string, groups []string) error {
	for _, group := range groups {
		in := &iam.RemoveUserFromGroupInput{
			GroupName: aws.String(group),
			UserName:  aws.String(user),
		}
		_, err := c.client.RemoveUserFromGroup(ctx, in)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *client) getUser(ctx context.Context, user string) (string, error) {
	in := &iam.GetUserInput{
		UserName: aws.String(user),
	}
	out, err := c.client.GetUser(ctx, in)
	if err != nil {
		return "", err
	}
	return *out.User.Arn, nil
}

func (c *client) deleteUser(ctx context.Context, user string) error {
	in := &iam.DeleteUserInput{
		UserName: aws.String(user),
	}
	_, err := c.client.DeleteUser(ctx, in)
	return err
}

type resType string

const (
	iamAccessKey                 resType = "Access Key"
	iamGroup                     resType = "IAM Group"
	iamInlinePolicy              resType = "Inline Policy"
	iamLoginProfile              resType = "Login Profile"
	iamManagedPolicy             resType = "Managed Policies"
	iamMFADevice                 resType = "MFA Device"
	iamServiceSpecificCredential resType = "Service Specific Credentials"
	iamSigningCertificate        resType = "Signing Certificate"
	iamSSHPublicKey              resType = "SSH Public Key"
	iamUser                      resType = "IAM User"
)

type resource struct {
	kind      resType
	user      string
	resources []string
}

type resourcesByType map[resType][]resource

type skipResources struct {
	loginProfile               bool
	AccessKeys                 bool
	SigningCertificates        bool
	SSHPublicKeys              bool
	ServiceSpecificCredentials bool
	MFADevices                 bool
	InlinePolicies             bool
	ManagedPolicies            bool
	Groups                     bool
	User                       bool
}

func (c *client) getUsers(ctx context.Context, users []string) (resourcesByType, error) {
	type result struct {
		responce resource
		err      error
	}
	ch := make(chan result)

	var wg sync.WaitGroup
	for _, user := range users {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()
			arn, err := c.getUser(ctx, user)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					ch <- result{
						err: err,
					}
				}
			}
			ch <- result{
				responce: resource{
					kind:      iamUser,
					user:      user,
					resources: []string{arn},
				},
			}
		}(user)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	resources := make(resourcesByType)
	errs := []error{}
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		if v, ok := resources[iamUser]; ok {
			resources[iamUser] = append(v, r.responce)
		} else {
			resources[iamUser] = []resource{r.responce}
		}
	}

	if len(errs) != 0 {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		return nil, fmt.Errorf("errors occurred:\n  %s", strings.Join(errStrs, "\n  "))
	}
	return resources, nil
}

func (c *client) getResources(ctx context.Context, fs map[resType]getResourcesFunc, users []string) (resourcesByType, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		responce resource
		err      error
	}
	ch := make(chan result)

	var wg sync.WaitGroup
	for _, user := range users {
		for t, f := range fs {
			wg.Add(1)
			go func(typ resType, fn getResourcesFunc, user string) {
				defer wg.Done()
				r, err := fn(ctx, user)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						ch <- result{
							err: err,
						}
					}
					return
				}
				ch <- result{
					responce: resource{
						kind:      typ,
						user:      user,
						resources: r,
					},
				}
			}(t, f, user)
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	resources := make(resourcesByType)
	for r := range ch {
		if r.err != nil {
			return nil, r.err
		}
		if len(r.responce.resources) == 0 {
			continue
		}
		if v, ok := resources[r.responce.kind]; ok {
			resources[r.responce.kind] = append(v, r.responce)
		} else {
			resources[r.responce.kind] = []resource{r.responce}
		}
	}

	return resources, nil
}

func (c *client) getResourcesFuncs(skip skipResources) map[resType]getResourcesFunc {
	fs := map[resType]getResourcesFunc{
		iamLoginProfile:              c.getLoginProfile,
		iamGroup:                     c.getGroupsForUser,
		iamAccessKey:                 c.getAccessKeys,
		iamInlinePolicy:              c.getInlinePolicies,
		iamMFADevice:                 c.getMFADevices,
		iamManagedPolicy:             c.getAttachedPolicies,
		iamSSHPublicKey:              c.getSSHPublicKeys,
		iamServiceSpecificCredential: c.getServiceSpecificCredentials,
		iamSigningCertificate:        c.getSigningCertificates,
	}

	if skip.loginProfile {
		delete(fs, iamLoginProfile)
	}
	if skip.AccessKeys {
		delete(fs, iamAccessKey)
	}
	if skip.SigningCertificates {
		delete(fs, iamSigningCertificate)
	}
	if skip.SSHPublicKeys {
		delete(fs, iamSSHPublicKey)
	}
	if skip.Groups {
		delete(fs, iamGroup)
	}
	if skip.InlinePolicies {
		delete(fs, iamInlinePolicy)
	}
	if skip.ManagedPolicies {
		delete(fs, iamManagedPolicy)
	}
	if skip.MFADevices {
		delete(fs, iamManagedPolicy)
	}
	if skip.ServiceSpecificCredentials {
		delete(fs, iamServiceSpecificCredential)
	}

	return fs
}

func (c *client) getDependencyResources(ctx context.Context, users []string, skip skipResources) (resourcesByType, error) {
	fs := c.getResourcesFuncs(skip)
	return c.getResources(ctx, fs, users)
}

func (c *client) removeResourcesFuncs() map[resType]removeResourcesFunc {
	fs := map[resType]removeResourcesFunc{
		iamLoginProfile:              c.deleteLoginProfile,
		iamGroup:                     c.removeUserFromGroup,
		iamAccessKey:                 c.deleteAccessKeys,
		iamInlinePolicy:              c.deleteInlinePolicies,
		iamMFADevice:                 c.deactivateMFADevices,
		iamManagedPolicy:             c.detachPolicies,
		iamSSHPublicKey:              c.deleteSSHPublicKeys,
		iamServiceSpecificCredential: c.deleteServiceSpecificCredentials,
		iamSigningCertificate:        c.deleteSigningCertificates,
	}
	return fs
}

func (c *client) removeResources(ctx context.Context, fs map[resType]removeResourcesFunc, resources resourcesByType) (resourcesByType, []error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		responce resource
		err      error
	}
	ch := make(chan result)

	var wg sync.WaitGroup
	for t, f := range fs {
		for _, rs := range resources[t] {
			wg.Add(1)
			go func(typ resType, fn removeResourcesFunc, rs resource) {
				defer wg.Done()
				err := fn(ctx, rs.user, rs.resources)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						ch <- result{
							err: err,
						}
					}
					ch <- result{
						responce: rs,
					}
				}
			}(t, f, rs)
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	unremovedResources := make(resourcesByType)
	errs := []error{}
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		if v, ok := unremovedResources[r.responce.kind]; ok {
			unremovedResources[r.responce.kind] = append(v, r.responce)
		} else {
			unremovedResources[r.responce.kind] = []resource{r.responce}
		}
	}

	if len(errs) != 0 {
		return unremovedResources, errs
	}
	return nil, nil
}

func (c *client) removeDependencyResources(ctx context.Context, resources resourcesByType) (resourcesByType, error) {
	fs := c.removeResourcesFuncs()
	unremovedResources, errs := c.removeResources(ctx, fs, resources)
	if errs != nil {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		return unremovedResources, fmt.Errorf("errors occurred:\n  %s", strings.Join(errStrs, "\n  "))
	}
	return nil, nil
}

func (c *client) deleteUsers(ctx context.Context, users []string) ([]string, error) {
	type result struct {
		responce string
		err      error
	}
	ch := make(chan result)

	var wg sync.WaitGroup
	for _, user := range users {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()
			err := c.deleteUser(ctx, user)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					ch <- result{
						err: err,
					}
				}
				ch <- result{
					responce: user,
				}
			}
		}(user)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	unremovedResources := []string{}
	errs := []error{}
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
		}
		unremovedResources = append(unremovedResources, r.responce)
	}

	if len(errs) != 0 {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		return unremovedResources, fmt.Errorf("errors occurred:\n  %s", strings.Join(errStrs, "\n  "))
	}
	return nil, nil
}
