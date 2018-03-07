package credentials_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/thomasmmitchell/go-bosh-config-server/credentials"
)

//The most basic of basic tests to make sure that all the creds
// still are attached to _something_
var _ = Describe("Lookup", func() {
	DescribeTable("This key should be in the Credentials Index",
		func(key string) {
			fmt.Fprintf(GinkgoWriter, "Index looks like %+v\n", Index)
			_, found := Index[key]
			Expect(found).To(BeTrue())
		},
		Entry("value", "value"),
		Entry("json", "json"),
		Entry("password", "password"),
		Entry("user", "user"),
		Entry("certificate", "certificate"),
		Entry("rsa", "rsa"),
		Entry("ssh", "ssh"),
	)
})
