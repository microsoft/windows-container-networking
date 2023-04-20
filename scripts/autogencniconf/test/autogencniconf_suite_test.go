//go:build windows
// +build windows

package autogenCniConfTest

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestAutogenCniConf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "autogencniconf")
}
