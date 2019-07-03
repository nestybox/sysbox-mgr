// Docker-related utilities

package dockerUtils

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
)

var daemonCfgFile string = "/etc/docker/daemon.json"
var dockerDataRoot string

func init() {
	dockerDataRoot = parseDataRoot(daemonCfgFile)
}

func parseDataRoot(daemonCfg string) string {
	dr := "/var/lib/docker"

	file, err := os.Open(daemonCfg)
	if err != nil {
		return dr
	}
	defer file.Close()

	type dockerdCfg struct {
		DataRoot string `json:"data-root"`
	}

	var cfg dockerdCfg

	byteValue, _ := ioutil.ReadAll(file)
	json.Unmarshal(byteValue, &cfg)

	if cfg.DataRoot != "" {
		dr = cfg.DataRoot
	}

	return dr
}

func GetDataRoot() string {
	return dockerDataRoot
}

func IsDockerContainer(rootfs string) bool {
	return strings.Contains(rootfs, dockerDataRoot)
}
