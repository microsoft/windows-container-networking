// Copyright Microsoft Corp.
// All rights reserved.

package cni

import (
	"github.com/Microsoft/windows-container-networking/common"

	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniVers "github.com/containernetworking/cni/pkg/version"
)

// Plugin is the parent class for CNI plugins.
type Plugin struct {
	*common.Plugin
}

// NewPlugin creates a new CNI plugin.
func NewPlugin(name, version string) (*Plugin, error) {
	// Setup base plugin.
	plugin, err := common.NewPlugin(name, version)
	if err != nil {
		return nil, err
	}

	return &Plugin{
		Plugin: plugin,
	}, nil
}

// Initialize initializes the plugin.
func (plugin *Plugin) Initialize(config *common.PluginConfig) error {
	// Initialize the base plugin.
	return plugin.Plugin.Initialize(config)
}

// Uninitialize uninitializes the plugin.
func (plugin *Plugin) Uninitialize() {
	plugin.Plugin.Uninitialize()
}

// Execute executes the CNI command.
func (plugin *Plugin) Execute(api PluginApi) error {
	// Set supported CNI versions.
	pluginInfo := cniVers.VersionsStartingFrom(OldestVersionSupported)

	// Parse args and call the appropriate cmd handler.
	cniErr := cniSkel.PluginMainWithError(api.Add, nil, api.Delete, pluginInfo, "CNI plugin WinCni")
	if cniErr != nil {
		cniErr.Print()
		return cniErr
	}

	return nil
}
