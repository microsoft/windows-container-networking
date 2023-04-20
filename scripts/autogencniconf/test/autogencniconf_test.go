//go:build windows
// +build windows

package autogenCniConfTest

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Global variables
var scriptPath string
var scriptName string = "generateCNIConfig.ps1"
var cniConfPath string = ".\\configs\\cni.conf"

// Utility Functions
func getEncodedCniArgs(inputJson string) string {
	json, err := os.ReadFile("configs\\" + inputJson)
	Expect(err).NotTo(HaveOccurred())
	encodedJsonString := base64.StdEncoding.EncodeToString(json)
	return encodedJsonString
}

func compareFileContents(expectedCniConf string) bool {
	expectedCniConfPath := "configs\\" + expectedCniConf
	Expect(expectedCniConfPath).To(BeAnExistingFile())
	generatedJson, err := os.ReadFile(cniConfPath)
	Expect(err).NotTo(HaveOccurred())
	expectedJson, err := os.ReadFile(expectedCniConfPath)
	Expect(err).NotTo(HaveOccurred())
	return string(expectedJson) == string(generatedJson)
}

///////////////////////////////////////////////////

var _ = BeforeSuite(func() {
	mydir, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred())
	mydir = strings.ReplaceAll(mydir, "\\", "/") // windows to unix
	scriptPath = path.Join(path.Dir(mydir), scriptName)
	scriptPath = strings.ReplaceAll(scriptPath, "/", "\\") // unix to windows
	Expect(scriptPath).To(BeAnExistingFile())
})

var _ = Describe("Autogen CNI conf Tests", func() {

	// Test Case 1
	It("Verifies that error is thrown if input json is invalid", func() {
		cniArgs := getEncodedCniArgs("tc1_input.json")
		Expect(cniArgs).NotTo(BeEmpty())

		cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
		out, err := cmd.CombinedOutput()
		Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
		Expect(cniConfPath).NotTo(BeAnExistingFile())
	})

	// Test Case 2
	It("Verifies user ACL policies are created", func() {
		cniArgs := getEncodedCniArgs("tc2_input.json")
		Expect(cniArgs).NotTo(BeEmpty())

		cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
		Expect(cniConfPath).To(BeAnExistingFile())
		Expect(compareFileContents("tc2_output.json")).To(BeTrue())
		err = os.Remove(cniConfPath)
		time.Sleep(2 * time.Second) // wait for 2 seconds to cleanup
		Expect(err).NotTo(HaveOccurred())
		Expect(cniConfPath).NotTo(BeAnExistingFile())
	})

	// Test Case 3
	When("SkipDefaultPolicies flag is set", func() {
		It("Verifies SkipDefaultPolicies flag is honored with user ACL policies", func() {
			cniArgs := getEncodedCniArgs("tc3a_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).To(BeAnExistingFile())
			Expect(compareFileContents("tc3a_output.json")).To(BeTrue())
			err = os.Remove(cniConfPath)
			time.Sleep(2 * time.Second) // wait for 2 seconds to cleanup
			Expect(err).NotTo(HaveOccurred())
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies SkipDefaultPolicies flag is honored without user ACL policies", func() {
			cniArgs := getEncodedCniArgs("tc3b_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).To(BeAnExistingFile())
			Expect(compareFileContents("tc3b_output.json")).To(BeTrue())
			err = os.Remove(cniConfPath)
			time.Sleep(2 * time.Second) // wait for 2 seconds to cleanup
			Expect(err).NotTo(HaveOccurred())
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})
	})

	// Test Case 4
	It("Verifies the mandatory parameters are passed to the script", func() {
		cmd := exec.Command("powershell", scriptPath) // calling script without mandatory param CniArgs
		out, err := cmd.CombinedOutput()
		Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
		Expect(cniConfPath).NotTo(BeAnExistingFile())
	})

	// Test Case 5
	It("Verifies user ACL policies are sorted based on priority", func() {
		cniArgs := getEncodedCniArgs("tc5_input.json")
		Expect(cniArgs).NotTo(BeEmpty())

		cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
		Expect(cniConfPath).To(BeAnExistingFile())
		Expect(compareFileContents("tc5_output.json")).To(BeTrue())
		err = os.Remove(cniConfPath)
		time.Sleep(2 * time.Second) // wait for 2 seconds to cleanup
		Expect(err).NotTo(HaveOccurred())
		Expect(cniConfPath).NotTo(BeAnExistingFile())
	})

	// Test Case 6
	When("CniArgs is passed to the script", func() {

		It("Verifies error is thrown if mandatory parameter 'Name' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6a_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'Type' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6b_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'Subnet' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6c_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'Gateway' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6d_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'InfraPrefix' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6e_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'DnsServers' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6f_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies error is thrown if mandatory parameter 'ManagementIp' is not present", func() {
			cniArgs := getEncodedCniArgs("tc6g_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})
	})

	// Test Case 7
	When("User ACL policies are configured", func() {

		It("Verifies lower limit of the user priority band is honored", func() {
			cniArgs := getEncodedCniArgs("tc7a_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})

		It("Verifies higher limit of the user priority band is honored", func() {
			cniArgs := getEncodedCniArgs("tc7b_input.json")
			Expect(cniArgs).NotTo(BeEmpty())

			cmd := exec.Command("powershell", scriptPath, "-CniArgs", cniArgs, "-CniConfPath", cniConfPath)
			out, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "cmd [%s] failed with error [%v]. output is [%s]", cmd, err, out)
			Expect(cniConfPath).NotTo(BeAnExistingFile())
		})
	})
})
