// Copyright Microsoft Corp.
// All rights reserved.

package cni

import (
	"github.com/sirupsen/logrus"
	"github.com/Microsoft/hcsshim/hcn"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

func ResolveError(err error) *cniTypes.Error {
	if err == nil {
		return nil
	}
	logrus.Debugf("[cni-net] Error detected, resolving error, %v", err)
	if hcn.IsNotFoundError(err) {
		switch err.(type) {
		case hcn.NetworkNotFoundError:
			return newNetworkNotFoundError(err)
		}
	}
	
	if hcn.IsPortAlreadyExistsError(err) {
		return newPortAlreadyExistsError(err)
	}
	
	return newGenericError(err)
	
}

func newGenericError(err error) *cniTypes.Error {
	return &cniTypes.Error{
		Code:    66,
		Msg:     "failure in cni",
		Details: err.Error(),
	}
}

func newPortAlreadyExistsError(err error) *cniTypes.Error {
	return &cniTypes.Error{
		Code:    71,
		Msg:     "Port specified is already in use. This indicates that an endpoint already exists with the port mapping requested. Delete the endpoint or change the port",
		Details: err.Error(),
	}
}

func newNetworkNotFoundError(err error) *cniTypes.Error {
	return &cniTypes.Error{
		Code:    81,
		Msg:     "Network not found. The network specified in the CNI config was not found and the endpoint can not be created. Please create the network to proceed.",
		Details: err.Error(),
	}
}
