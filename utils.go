//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-mgr/dsVolMgr"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/lib/dockerUtils"
	"github.com/nestybox/sysbox-mgr/subidAlloc"
	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func allocSubidRange(subID []user.SubID, size, min, max uint64) ([]user.SubID, error) {
	var holeStart, holeEnd uint64

	if size == 0 {
		return subID, fmt.Errorf("invalid allocation size: %d", size)
	}

	holeStart = min

	for _, id := range subID {
		holeEnd = uint64(id.SubID)
		if holeEnd-holeStart >= size {
			subID = append(subID, user.SubID{"sysbox", int64(holeStart), int64(size)})
			return subID, nil
		}
		holeStart = uint64(id.SubID + id.Count)
	}

	holeEnd = max
	if holeEnd-holeStart < size {
		return subID, fmt.Errorf("failed to allocate %d subids in range %d, %d", size, min, max)
	}

	subID = append(subID, user.SubID{"sysbox", int64(holeStart), int64(size)})
	return subID, nil
}

func writeSubidFile(path string, subID []user.SubID) error {

	// TODO: lock the /etc/subuid(gid) file (?)

	var buf bytes.Buffer
	for _, id := range subID {
		l := fmt.Sprintf("%s:%d:%d\n", id.Name, id.SubID, id.Count)
		buf.WriteString(l)
	}

	return ioutil.WriteFile(path, []byte(buf.String()), 644)
}

func configSubidRange(path string, size, min, max uint64) error {

	subID, err := user.ParseSubIDFile(path)
	if err != nil {
		return fmt.Errorf("error parsing file %s: %s", path, err)
	}

	// TODO: this only handles zero or one entries for user "sysbox" in the subuid file;
	// it's possible (but rare) that there are multiple such entries though.

	index := -1
	for i, id := range subID {
		if id.Name == "sysbox" {
			if uint64(id.Count) == size {
				return nil
			}
			index = i
		}
	}

	if index >= 0 {
		copy(subID[index:], subID[index+1:])
		subID = subID[:len(subID)-1]
	}

	subID, err = allocSubidRange(subID, size, min, max)
	if err != nil {
		return fmt.Errorf("failed to configure subid range for sysbox: %s", err)
	}

	if err = writeSubidFile(path, subID); err != nil {
		return fmt.Errorf("failed to configure subid range for sysbox: %s", err)
	}

	return nil
}

// getSubidLimits returns the subuid min, subuid max, subgid min, and subgid max limits
// for the host (in that order)
func getSubidLimits(file string) ([]uint64, error) {

	// defaults (see login.defs(5); we set the max limits to 2^32 because uid(gid)
	// are 32-bit, even though login.defs(5) indicates it's above this value)
	limits := []uint64{100000, 4294967295, 100000, 4294967295}

	// check if these defaults are overriden by login.defs; if login.defs does not exist, move on.
	f, err := os.Open(file)
	if err != nil {
		return limits, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "SUB_UID_MIN") {
			valStr := strings.Split(line, " ")[1]
			limits[0], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_UID_MAX") {
			valStr := strings.Split(line, " ")[1]
			limits[1], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_GID_MIN") {
			valStr := strings.Split(line, " ")[1]
			limits[2], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_GID_MAX") {
			valStr := strings.Split(line, " ")[1]
			limits[3], err = strconv.ParseUint(valStr, 10, 64)
		}
		if err != nil {
			return limits, fmt.Errorf("failed to parse line %s: %s", line, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return limits, fmt.Errorf("failed to scan file %s: %v", file, err)
	}

	return limits, nil
}

func setupSubidAlloc(ctx *cli.Context) (intf.SubidAlloc, error) {
	var reusePol subidAlloc.ReusePolicy

	allocMode := ctx.GlobalString("userns-remap")

	if allocMode == "identity" {
		logrus.Infof("Sysbox configured in identity userns-remap mode")
	} else {
		logrus.Infof("Sysbox configured in exclusive userns-remap mode")
	}

	// get subid min/max limits from login.defs (if any)
	limits, err := getSubidLimits("/etc/login.defs")
	if err != nil {
		return nil, err
	}

	subUidMin := limits[0]
	subUidMax := limits[1]
	subGidMin := limits[2]
	subGidMax := limits[3]

	// configure the subuid(gid) range for "sysbox"
	if err := configSubidRange("/etc/subuid", subidRangeSize, subUidMin, subUidMax); err != nil {
		return nil, err
	}
	if err := configSubidRange("/etc/subgid", subidRangeSize, subGidMin, subGidMax); err != nil {
		return nil, err
	}

	logrus.Infof("Subid allocation range: start = %v, size = %v", subUidMin, subidRangeSize)

	if ctx.GlobalString("subid-policy") == "no-reuse" {
		reusePol = subidAlloc.NoReuse
		logrus.Infof("Subid allocation exhaust policy set to \"no-reuse\"")
	} else {
		reusePol = subidAlloc.Reuse
		logrus.Infof("Subid allocation exhaust policy set to \"reuse\"")
	}

	subuidSrc, err := os.Open("/etc/subuid")
	if err != nil {
		return nil, err
	}
	defer subuidSrc.Close()

	subgidSrc, err := os.Open("/etc/subgid")
	if err != nil {
		return nil, err
	}
	defer subgidSrc.Close()

	subidAlloc, err := subidAlloc.New("sysbox", allocMode, reusePol, subuidSrc, subgidSrc)
	if err != nil {
		return nil, err
	}

	return subidAlloc, nil
}

func setupDsVolMgr(ctx *cli.Context) (intf.VolMgr, error) {
	hostDir := filepath.Join(sysboxLibDir, "docker")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}
	ds, err := dsVolMgr.New(hostDir)
	if err != nil {
		return nil, err
	}
	return ds, nil
}

func setupWorkDirs() error {
	if err := cleanupWorkDirs(); err != nil {
		return err
	}
	if err := os.MkdirAll(sysboxRunDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(sysboxLibDir, 0700); err != nil {
		return err
	}
	return nil
}

func cleanupWorkDirs() error {

	if _, err := os.Stat(sysboxRunDir); err == nil {
		if err := removeDirContents(sysboxRunDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(sysboxLibDir); err == nil {
		if err := removeDirContents(sysboxLibDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return nil
}

func removeDirContents(path string) error {
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return fmt.Errorf("ReadDir(%v) failed: %v", path, err)
	}
	for _, d := range dir {
		if err := os.RemoveAll(filepath.Join(path, d.Name())); err != nil {
			return fmt.Errorf("RemoveAll(%v) failed: %v", filepath.Join(path, d.Name()), err)
		}
	}
	return nil
}

func sanitizeRootfs(rootfs string) string {
	// Sanitize the given container's rootfs. Specifically, in docker containers on
	// overlayfs the rootfs is usually "/var/lib/docker/overlay2/<container-id>/merged",
	// but docker removes the "merged" directory during container stop and re-creates it
	// during container start. Thus, we can't rely on the presence of "merged" to determine
	// if a container was stopped or removed. Instead, we use the rootfs path up to
	// <container-id>.
	if dockerUtils.IsDockerContainer(rootfs) {
		if strings.Contains(rootfs, "overlay2") && filepath.Base(rootfs) == "merged" {
			rootfs = filepath.Dir(rootfs)
		}
	}

	return rootfs
}
