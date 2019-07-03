package dockerUtils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDataRoot(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "TestParseDataRoot")
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "daemon.json")

	var data = []byte(`{"data-root":"/some/dir", "debug":false, "userns-remap":"sysvisor"}`)
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		t.Errorf("writeFile failed: %s", err)
	}

	dataRoot := parseDataRoot(filename)

	if dataRoot != "/some/dir" {
		t.Errorf("parseDataRoot(): want \"/some/dir\", got %s", dataRoot)
	}
}

func TestIsDockerContainer(t *testing.T) {
	dockerDataRoot = "/some/dir"

	rootfs := "/some/dir/container-id"
	if !IsDockerContainer(rootfs) {
		t.Errorf("IsDockerContainer(): want true, got false")
	}

	rootfs = "/some/other/dir/container-id"
	if IsDockerContainer(rootfs) {
		t.Errorf("IsDockerContainer(): want false, got true")
	}
}
