// Copyright Microsoft Corp.
// All rights reserved.

//go:build windows
// +build windows

package cni

import (
	"testing"
)

// TestParseMasterField tests that the master field is properly parsed from CNI config
func TestParseMasterField(t *testing.T) {
	// Test with master field present
	configWithMaster := `{
		"cniVersion": "0.3.0",
		"name": "testNetwork",
		"type": "nat",
		"master": "Ethernet",
		"ipam": {
			"subnet": "192.168.100.0/24"
		}
	}`

	config, err := ParseNetworkConfig([]byte(configWithMaster))
	if err != nil {
		t.Fatalf("Failed to parse config with master field: %v", err)
	}

	if config.Master != "Ethernet" {
		t.Errorf("Expected master to be 'Ethernet', got '%s'", config.Master)
	}

	// Test with master field missing (should be empty string)
	configWithoutMaster := `{
		"cniVersion": "0.3.0",
		"name": "testNetwork",
		"type": "nat",
		"ipam": {
			"subnet": "192.168.100.0/24"
		}
	}`

	config2, err := ParseNetworkConfig([]byte(configWithoutMaster))
	if err != nil {
		t.Fatalf("Failed to parse config without master field: %v", err)
	}

	if config2.Master != "" {
		t.Errorf("Expected master to be empty when not specified, got '%s'", config2.Master)
	}
}

// TestMasterFieldInNetworkInfo tests that the master field is properly propagated to NetworkInfo
func TestMasterFieldInNetworkInfo(t *testing.T) {
	config := &NetworkConfig{
		CniVersion: "0.3.0",
		Name:       "testNetwork",
		Type:       "nat",
		Master:     "Ethernet",
		Ipam: IpamConfig{
			Subnet: "192.168.100.0/24",
		},
	}

	networkInfo, err := config.GetNetworkInfo("")
	if err != nil {
		t.Fatalf("Failed to get network info: %v", err)
	}

	if networkInfo.InterfaceName != "Ethernet" {
		t.Errorf("Expected InterfaceName to be 'Ethernet', got '%s'", networkInfo.InterfaceName)
	}

	// Test with empty master
	config.Master = ""
	networkInfo2, err := config.GetNetworkInfo("")
	if err != nil {
		t.Fatalf("Failed to get network info with empty master: %v", err)
	}

	if networkInfo2.InterfaceName != "" {
		t.Errorf("Expected InterfaceName to be empty when master is empty, got '%s'", networkInfo2.InterfaceName)
	}
}