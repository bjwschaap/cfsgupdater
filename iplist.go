package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

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
