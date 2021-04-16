package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"go.uber.org/zap"
)

// 0 byte type..
type void struct{}

type Event struct {
	Records []struct {
		EventVersion         string `json:"EventVersion"`
		EventSubscriptionArn string `json:"EventSubscriptionArn"`
		EventSource          string `json:"EventSource"`
		Sns                  struct {
			SignatureVersion string    `json:"SignatureVersion"`
			Timestamp        time.Time `json:"Timestamp"`
			Signature        string    `json:"Signature"`
			SigningCertURL   string    `json:"SigningCertUrl"`
			MessageID        string    `json:"MessageId"`
			Message          string    `json:"Message"`
			Type             string    `json:"Type"`
			UnsubscribeURL   string    `json:"UnsubscribeUrl"`
			TopicArn         string    `json:"TopicArn"`
			Subject          string    `json:"Subject"`
		} `json:"Sns"`
	} `json:"Records"`
}

type Message struct {
	CreateTime string `json:"create-time"`
	Synctoken  string `json:"synctoken"`
	MD5        string `json:"md5"`
	URL        string `json:"url"`
}

type IPList struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
}

type ServiceScope string

const (
	ScopeGlobal   = ServiceScope("GLOBAL")
	ScopeRegional = ServiceScope("REGION")
	ScopeAll      = ServiceScope("ALL")
)

func (s ServiceScope) IsGlobal() bool {
	return s == ScopeGlobal
}

func (s ServiceScope) IsRegional() bool {
	return s == ScopeRegional
}

func (s ServiceScope) IsAll() bool {
	return s == ScopeAll
}

func (s ServiceScope) GetTags() map[string]string {
	switch s {
	case ScopeGlobal:
		return map[string]string{
			"Name":       GLOBAL_TAG,
			"AutoUpdate": "true",
		}
	case ScopeRegional:
		return map[string]string{
			"Name":       REGIONAL_TAG,
			"AutoUpdate": "true",
		}
	}
	return map[string]string{}
}

const (
	// Possible service names:
	// curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' | sort -u
	AWS_SERVICE = "CLOUDFRONT"

	// Security Group tags
	GLOBAL_TAG   = "cloudfront_g"
	REGIONAL_TAG = "cloudfront_r"

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
	logger.Info("succesfully retrieved IP Ranges file", zap.Int("entries", len(ips.Prefixes)))

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
	if l := len(globalSGs); l != 1 {
		return "ERROR", fmt.Errorf("expected single global security group, but found: %d", l)
	}
	gsg := globalSGs[0]
	logger.Info("found security group with global CF rules",
		zap.String("name", *gsg.GroupName),
		zap.String("id", *gsg.GroupId),
	)

	// find security groups containing regional cloudfront IPs
	regionalSGs, err := getSecurityGroups(svc, ScopeRegional)
	if err != nil {
		return "ERROR", fmt.Errorf("error fetching ec2 security groups by tag: %v", err)
	}
	if l := len(regionalSGs); l != 1 {
		return "ERROR", fmt.Errorf("expected single regional security group, but found: %d", l)
	}
	rsg := regionalSGs[0]
	logger.Info("found security group with regional CF rules",
		zap.String("name", *rsg.GroupName),
		zap.String("id", *rsg.GroupId),
	)

	// Check if there are any rules present (securitygroup might be empty)
	if len(gsg.IpPermissions) == 0 {
		gsg.IpPermissions = []*ec2.IpPermission{
			{
				FromPort:   aws.Int64(443),
				ToPort:     aws.Int64(443),
				IpProtocol: aws.String("tcp"),
				IpRanges:   []*ec2.IpRange{},
			},
		}
	}

	if len(rsg.IpPermissions) == 0 {
		rsg.IpPermissions = []*ec2.IpPermission{
			{
				FromPort:   aws.Int64(443),
				ToPort:     aws.Int64(443),
				IpProtocol: aws.String("tcp"),
				IpRanges:   []*ec2.IpRange{},
			},
		}
	}

	// regional ingress rules to add
	rta := diff(rsg.IpPermissions[0].IpRanges, cfRegional)
	logger.Info("regional missing ip prefixes to add",
		zap.Int("items_to_add", len(rta)),
	)
	updateSecurityGroup(logger, svc, rsg, rta, INGRESS, AUTHORIZE)

	// regional ingrress rules to remove
	rtr := diff(cfRegional, rsg.IpPermissions[0].IpRanges)
	logger.Info("regional outdated ip prefixes to remove",
		zap.Int("items_to_remove", len(rtr)),
	)
	updateSecurityGroup(logger, svc, rsg, rtr, INGRESS, REVOKE)

	// global ingress rules to add
	gta := diff(gsg.IpPermissions[0].IpRanges, cfGlobal)
	logger.Info("regional missing ip prefixes to add",
		zap.Int("items_to_add", len(gta)),
	)
	updateSecurityGroup(logger, svc, gsg, gta, INGRESS, AUTHORIZE)

	// global ingress rules to remove
	gtr := diff(cfGlobal, gsg.IpPermissions[0].IpRanges)
	logger.Info("regional outdated ip prefixes to remove",
		zap.Int("items_to_remove", len(gtr)),
	)
	updateSecurityGroup(logger, svc, gsg, gtr, INGRESS, REVOKE)

	if len(gsg.IpPermissionsEgress) == 0 {
		// No default allow-all egress found, we need to add it
		updateSecurityGroup(logger, svc, gsg, nil, EGRESS, AUTHORIZE)
	}

	if len(rsg.IpPermissionsEgress) == 0 {
		// No default allow-all egress found, we need to add it
		updateSecurityGroup(logger, svc, rsg, nil, EGRESS, AUTHORIZE)
	}

	return "SUCCESS", nil
}

// getIPList retrieves the IP ranges file published by AWS,
// and verifies it against the (in message) published md5 hash
func getIPList(url, hash string) (IPList, error) {
	ipList := IPList{}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return ipList, err
	}
	defer resp.Body.Close()

	rawJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ipList, fmt.Errorf("failed to read http response: %v", err)
	}

	h := md5.New()
	h.Write(rawJSON)
	sum := hex.EncodeToString(h.Sum(nil))
	if hash != sum {
		return ipList, fmt.Errorf("checksum (MD5) mismatch. Got: %s Expected: %s", sum, hash)
	}

	err = json.Unmarshal(rawJSON, &ipList)
	if err != nil {
		return ipList, fmt.Errorf("failed to parse ip ranges data: %v", err)
	}

	return ipList, nil
}

// getIPs takes the IPList and returns a new slice with filtered ip prefixes.
func (ips *IPList) getIPs(service string, scope ServiceScope) []*ec2.IpRange {
	// holds all ips
	var result []*ec2.IpRange

	for _, p := range ips.Prefixes {
		if (scope.IsAll() && p.Service == service) ||
			(scope.IsRegional() && p.Region != "GLOBAL" && p.Service == service) ||
			(scope.IsGlobal() && p.Region == "GLOBAL" && p.Service == service) {
			// convert IPPrefix entry to a ec2 IpRange that our security group understands
			// also, it will make comparing IpRanges much easier later on..
			result = append(result, &ec2.IpRange{CidrIp: aws.String(p.IPPrefix)})
		}
	}

	return result
}

// getSecurityGroups retrieves securitygroups by their tags
// tags are defined through the requested scope
func getSecurityGroups(sess *ec2.EC2, scope ServiceScope) ([]*ec2.SecurityGroup, error) {
	// f is our filter definition
	f := []*ec2.Filter{}

	// append filter tag key/value pair for each entry in tags map
	for k, v := range scope.GetTags() {
		f = append(f,
			&ec2.Filter{
				Name:   aws.String("tag-key"),
				Values: aws.StringSlice([]string{k}),
			},
			&ec2.Filter{
				Name:   aws.String("tag-value"),
				Values: aws.StringSlice([]string{v}),
			},
		)
	}

	// get securitygroups using filter
	res, err := sess.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{Filters: f})
	if err != nil {
		return nil, err
	}

	return res.SecurityGroups, nil
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

// updateSecurityGroup stores the updated securitygroup back to AWS
func updateSecurityGroup(_logger *zap.Logger, sess *ec2.EC2, group *ec2.SecurityGroup, ips []*ec2.IpRange, ruleType, op string) {
	logger := _logger.WithOptions(zap.Fields(
		zap.String("group", *group.GroupName),
		zap.String("group_id", *group.GroupId),
		zap.String("operation", op),
	))

	if ruleType == INGRESS && len(ips) == 0 {
		logger.Info("update security group: nothing to do")
		return
	}

	var resString string
	var resErr error
	switch ruleType {
	case INGRESS:
		switch op {
		case AUTHORIZE:
			result, err := sess.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				GroupId: group.GroupId,
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String("tcp"),
						IpRanges:   ips,
					},
				},
			})

			resString = result.GoString()
			resErr = err

		case REVOKE:
			result, err := sess.RevokeSecurityGroupIngress(&ec2.RevokeSecurityGroupIngressInput{
				GroupId: group.GroupId,
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(443),
						ToPort:     aws.Int64(443),
						IpProtocol: aws.String("tcp"),
						IpRanges:   ips,
					},
				},
			})

			resString = result.GoString()
			resErr = err
		}

	case EGRESS:
		switch op {
		case AUTHORIZE:
			result, err := sess.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
				GroupId: group.GroupId,
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(0),
						ToPort:     aws.Int64(0),
						IpProtocol: aws.String("-1"),
						IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
				},
			})

			resString = result.GoString()
			resErr = err

		case REVOKE:
			result, err := sess.RevokeSecurityGroupEgress(&ec2.RevokeSecurityGroupEgressInput{
				GroupId: group.GroupId,
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(0),
						ToPort:     aws.Int64(0),
						IpProtocol: aws.String("-1"),
						IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
					},
				},
			})

			resString = result.GoString()
			resErr = err
		}
	}

	if resErr != nil {
		if aerr, ok := resErr.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				logger.Error("error setting new permissions on security group",
					zap.String("code", aerr.Code()),
					zap.String("message", aerr.Message()),
					zap.Error(aerr),
				)
				return
			}
		} else {
			logger.Error("error setting new permissions on security group",
				zap.Error(resErr),
			)
			return
		}
	}

	logger.Info("succesfully updated security group",
		zap.String("aws_ec2_response", resString),
	)
}
