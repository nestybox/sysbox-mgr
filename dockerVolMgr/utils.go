package dockerVolMgr

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/nestybox/sysbox/dockerUtils"
)

func queryDockerForImageID(id string) (string, error) {

	docker, err := dockerUtils.DockerConnect()
	if err != nil {
		return "", err
	}

	container, err := docker.GetContainer(id)
	if err != nil {
		return "", err
	}

	return container.ImageID, nil
}

// getContainerImage returns the container image ID of the given container.
func getContainerImage(id string) (string, error) {

	imgID, err := queryDockerForImageID(id)
	if err != nil {
		return "", err
	}

	// XXX: in the future we should query containerd too.

	return imgID, nil
}

// Detects if a sys container image has inner Docker images inside of it.
func syscontHasInnerImg(rootfs string) (bool, error) {

	// Note: this function currently detect sys container inner images only when the inner
	// Docker uses the overlay2 storage driver. If it doesn't, this function assumes the
	// inner docker has no embedded images within it.

	path := filepath.Join(rootfs, dockerRoot, dockerImgDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}

	// If there are any inner images, the "overlay2/l" subdir will have links to them.

	path = filepath.Join(path, "l")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}

	images, err := ioutil.ReadDir(path)
	if err != nil {
		return false, err
	}

	if len(images) > 0 {
		return true, nil
	}

	return false, nil
}

// rsyncVol performs an rsync from src to dest
// 'shiftUids': if set, rsync modifies the ownership of files copied to dest to match the givne uid(gid).
// 'exclude': regex string indicating files to exclude from the transfer
// 'deleteAtRx': delete extraneous files from destination (i.e., those that don't exist on source)
func rsyncVol(src, dest string, uid, gid uint32, shiftUids bool, exclude string, deleteAtRx bool) error {

	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	srcDir := src + "/"

	// Note: rsync uses file modification time and size to determine if a sync is
	// needed. This should be fine for sync'ing the given directories, assuming the
	// probability of files being different yet having the same size & timestamp is low. If
	// this assumption changes we could pass the `--checksum` option to rsync, but this
	// will slow the copy operation significantly.

	if shiftUids {
		chownOpt := "--chown=" + strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)

		if len(exclude) > 0 {
			if deleteAtRx {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", "--exclude", exclude, chownOpt, srcDir, dest)
			} else {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--exclude", exclude, chownOpt, srcDir, dest)
			}
		} else {
			if deleteAtRx {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", chownOpt, srcDir, dest)
			} else {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", chownOpt, srcDir, dest)
			}
		}

	} else {

		if len(exclude) > 0 {
			if deleteAtRx {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", "--exclude", exclude, srcDir, dest)
			} else {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--exclude", exclude, srcDir, dest)
			}
		} else {
			if deleteAtRx {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", srcDir, dest)
			} else {
				cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", srcDir, dest)
			}
		}
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to sync %s to %s: %v %v\n", srcDir, dest, string(stdout.Bytes()), string(stderr.Bytes()))
	}

	return nil
}

func dirIsEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}

	return false, err
}
