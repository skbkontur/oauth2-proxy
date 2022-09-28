package header

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/skbkontur/oauth2-proxy/pkg/logger"
)

var (
	filesDir string
)

func TestHeaderSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Header")
}

var _ = BeforeSuite(func() {
	os.Setenv("SECRET_ENV", "super-secret-env")

	dir, err := ioutil.TempDir("", "oauth2-proxy-header-suite")
	Expect(err).ToNot(HaveOccurred())
	Expect(ioutil.WriteFile(path.Join(dir, "secret-file"), []byte("super-secret-file"), 0644)).To(Succeed())
	filesDir = dir
})

var _ = AfterSuite(func() {
	os.Unsetenv("SECRET_ENV")
	Expect(os.RemoveAll(filesDir)).To(Succeed())
})
