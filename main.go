package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"go.uber.org/zap"
)

const (
	// Possible service names:
	// curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' | sort -u
	AWS_SERVICE = "CLOUDFRONT"

	// updateSecurityGroup operations
	AUTHORIZE = "Authorize"
	REVOKE    = "Revoke"

	// rule type
	INGRESS = "Ingress"
	EGRESS  = "Egress"
)

// Always set by AWS in Lambda execution environment
var AWS_REGION = os.Getenv("AWS_REGION")

// Main entrypoint for our lambda
func main() {
	lambda.Start(Handler)
}

// Handler handles the actual requests coming in
func Handler(ctx context.Context, request Event) (string, error) {
	// extract execution context
	lc, _ := lambdacontext.FromContext(ctx)

	// prepare logger; add aws_request_id to all log entries
	logger, _ := zap.NewProduction(
		zap.Fields(
			zap.String("aws_request_id", lc.AwsRequestID),
		),
	)
	defer logger.Sync()

	// incoming event from SNS topic
	logger.Info("incoming event",
		zap.Any("request", request),
		zap.String("invoked_arn", lc.InvokedFunctionArn),
	)

	// parse the SNS message from the request
	msg := Message{}
	if err := json.Unmarshal([]byte(request.Records[0].Sns.Message), &msg); err != nil {
		logger.Error("could not unmarshal JSON message from request", zap.Error(err))
		return "ERROR", err
	}

	// get url and md5 checksum from the message and use them to
	// fetch and validate the ip ranges file
	ips, err := getIPList(msg.URL, msg.MD5)
	if err != nil {
		return "ERROR", err
	}
	logger.Info("succesfully retrieved IP Ranges file",
		zap.Int("entries", len(ips.Prefixes)),
	)

	// filter cloudfront ips from total ip ranges list
	cfRegional := ips.getIPs(AWS_SERVICE, ScopeRegional)
	logger.Info("selected Cloudfront regional ips",
		zap.Int("count", len(cfRegional)),
	)
	cfGlobal := ips.getIPs(AWS_SERVICE, ScopeGlobal)
	logger.Info("selected Cloudfront global ips",
		zap.Int("count", len(cfGlobal)),
	)

	// get AWS client session
	sess, err := session.NewSession(&aws.Config{Region: aws.String(AWS_REGION)})
	if err != nil {
		logger.Error("Failed to create AWS session", zap.Error(err))
		return "ERROR", err
	}

	// get EC2 API client using AWS session
	svc := ec2.New(sess)

	// find security groups containing global cloudfront IPs
	globalSGs, err := getSecurityGroups(svc, ScopeGlobal)
	if err != nil {
		return "ERROR", fmt.Errorf("error fetching ec2 security groups by tag: %v", err)
	}

	// update all global groups
	for _, gsg := range globalSGs {
		processGroup(logger, svc, gsg, cfGlobal)
	}

	// find security groups containing regional cloudfront IPs
	regionalSGs, err := getSecurityGroups(svc, ScopeRegional)
	if err != nil {
		return "ERROR", fmt.Errorf("error fetching ec2 security groups by tag: %v", err)
	}

	// update all regional groups
	for _, rsg := range regionalSGs {
		processGroup(logger, svc, rsg, cfRegional)
	}

	return "SUCCESS", nil
}

// processGroup updates a single securitygroup
func processGroup(_logger *zap.Logger, svc *ec2.EC2, grp *ec2.SecurityGroup, ips []*ec2.IpRange) {
	logger := _logger.WithOptions(zap.Fields(
		zap.String("group_name", *grp.GroupName),
		zap.String("group_id", *grp.GroupId),
	))

	// Check if there are any rules present (securitygroup might be empty)
	if len(grp.IpPermissions) == 0 {
		grp.IpPermissions = []*ec2.IpPermission{
			{
				FromPort:   aws.Int64(443),
				ToPort:     aws.Int64(443),
				IpProtocol: aws.String("tcp"),
				IpRanges:   []*ec2.IpRange{},
			},
		}
	}

	// ingress rules to add
	add := diff(grp.IpPermissions[0].IpRanges, ips)
	logger.Info("missing ip prefixes to add",
		zap.Int("items_to_add", len(add)),
	)
	updateSecurityGroup(logger, svc, grp, add, INGRESS, AUTHORIZE)

	// ingress rules to remove
	remove := diff(ips, grp.IpPermissions[0].IpRanges)
	logger.Info("outdated ip prefixes to remove",
		zap.Int("items_to_remove", len(remove)),
	)
	updateSecurityGroup(logger, svc, grp, remove, INGRESS, REVOKE)

	if len(grp.IpPermissionsEgress) == 0 {
		// No default allow-all egress found, we need to add it
		updateSecurityGroup(logger, svc, grp, nil, EGRESS, AUTHORIZE)
	}
}

// diff compares two IpRange slices and returns slice of differences
// the returned slice contains all items that are in b, but not in a (missing)
func diff(a, b []*ec2.IpRange) []*ec2.IpRange {
	// create map with length of the 'a' slice
	ma := make(map[string]void, len(a))
	diffs := []*ec2.IpRange{}
	// Convert first slice to map with empty struct (0 bytes)
	for _, ka := range a {
		key := aws.StringValue(ka.CidrIp)
		ma[key] = void{}
	}
	// find missing values in a
	for _, kb := range b {
		key := aws.StringValue(kb.CidrIp)
		if _, ok := ma[key]; !ok {
			diffs = append(diffs, &ec2.IpRange{CidrIp: aws.String(key)})
		}
	}
	return diffs
}
