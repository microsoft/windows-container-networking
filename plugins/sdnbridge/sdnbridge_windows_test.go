package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"strings"
	"encoding/json"
//	. "github.com/Microsoft/windows-container-networking/plugins/sdnbridge"
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"github.com/Microsoft/hcsshim/hcn"
)

const BridgeJson = `{
  "cniVersion": "0.2.0",
  "name": "cbr0",
  "type": "sdnbridge",
  "capabilities": {
    "portMappings": true,
    "dnsCapabilities": true
  },
  "dns": {
    "Nameservers": [
      "11.0.0.10"
    ],
    "Search": [
      "svc.cluster.local"
    ]
  },
  "AdditionalArgs": [
    {
      "Name": "EndpointPolicy",
      "Value": {
        "Type": "OutBoundNAT",
        "Settings": {
          "Exceptions": [
            "192.168.0.0/16",
            "11.0.0.0/8",
            "10.124.24.0/23"
          ]
        }
      }
    },
    {
      "Name": "EndpointPolicy",
      "Value": {
        "Type": "SdnRoute",
        "Settings": {
          "DestinationPrefix": "10.124.24.196/32",
          "NeedEncap": true
        }
      }
    }
  ]
}`

const PoliciesString = `[{"Type":"OutBoundNAT","Settings":{"Exceptions":["192.168.0.0/16","11.0.0.0/8","10.124.24.0/23"]}},{"Type":"SdnRoute","Settings":{"DestinationPrefix":"10.124.24.196/32","NeedEncap":true}}]`

var _ = Describe("Sdnbridge", func() {
	var (
		network *hcn.HostComputeNetwork
		namespace *hcn.HostComputeNamespace
		endpoint *hcn.HostComputeEndpoint
		err error
	)
	
	BeforeSuite(func() {
		network, err = util.CreateBridgeTestNetwork()
		Expect (err).ToNot(HaveOccurred())
		namespace, err = util.CreateNamespace()
		Expect (err).ToNot(HaveOccurred())
	})
	AfterSuite(func() {
		network.Delete()
		namespace.Delete()
	})

	Describe("Add/Del CNI commands", func() {
		var (
			dummyID string
		)
		It("should be able to add and endpoint to a namespace", func() {
			dummyID = "12345"
			cmdArgs := util.CreateArgs(dummyID, namespace.Id, BridgeJson)
			util.AddCase(cmdArgs)
			namespace, err = hcn.GetNamespaceByID(namespace.Id)
		})
		It("should have correct endpoint values", func() {
			epName := dummyID + "_" + network.Name
			endpoint, err = hcn.GetEndpointByName(epName)
			Expect (err).ToNot(HaveOccurred())
			Expect (endpoint.HostComputeNamespace).To(Equal(namespace.Id))
			Expect (endpoint.HostComputeNetwork).To(Equal(network.Id))
			Expect (endpoint.Dns.Search).To(Equal([]string{".svc.cluster.local", "svc.cluster.local"}))
			Expect (endpoint.Dns.ServerList).To(Equal([]string{"11.0.0.10"}))
			dummyEp := hcn.HostComputeEndpoint{}
			json.Unmarshal([]byte(PoliciesString), &dummyEp.Policies)
			numMatchedPolicies := 0
			for _, expectedPolicy := range dummyEp.Policies {
				for _, targetPolicy := range endpoint.Policies {
					if (strings.ToUpper(string(expectedPolicy.Type)) == strings.ToUpper(string(targetPolicy.Type))) {
						Expect (targetPolicy.Settings).To(Equal(expectedPolicy.Settings))
						numMatchedPolicies += 1
						break
					}
				}
			}
			Expect (numMatchedPolicies).To(Equal(len(dummyEp.Policies)))
		})
		It("should have endpoint added to the namespace", func() {
			namespace, err = hcn.GetNamespaceByID(namespace.Id)
			Expect (err).ToNot(HaveOccurred())
			Expect (strings.Contains(string(namespace.Resources[0].Data), strings.ToUpper(endpoint.Id))).Should(BeTrue())
		})
	})
})
	
