package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"go.uber.org/zap"
)

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

// updateSecurityGroup stores the updated securitygroup back to AWS
func updateSecurityGroup(_logger *zap.Logger, sess *ec2.EC2, group *ec2.SecurityGroup, ips []*ec2.IpRange, ruleType, op string) {
	logger := _logger.WithOptions(zap.Fields(
		zap.String("group", *group.GroupName),
		zap.String("group_id", *group.GroupId),
		zap.String("operation", op),
		zap.String("type", ruleType),
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
