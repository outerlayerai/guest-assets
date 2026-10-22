// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Magu Studios, Inc.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const version = "outerlayer-guest 2"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		if os.Getpid() == 1 {
			os.Exit(runInit())
		}
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		os.Exit(runInit())
	case "mount":
		os.Exit(runMount(args[1:]))
	case "relay":
		os.Exit(runRelay(args[1:]))
	case "net":
		os.Exit(runNet(args[1:]))
	case "exec-agent":
		os.Exit(runExecAgent(args[1:]))
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: outerlayer-guest init|mount|relay|net|exec-agent|version")
}

// mountOptionFlags are the generic options mapped to mount flags; anything
// else is passed to the filesystem as data.
var mountOptionFlags = map[string]uintptr{
	"ro":      unix.MS_RDONLY,
	"nosuid":  unix.MS_NOSUID,
	"nodev":   unix.MS_NODEV,
	"noexec":  unix.MS_NOEXEC,
	"noatime": unix.MS_NOATIME,
	"remount": unix.MS_REMOUNT,
}

func splitMountOptions(opts string) (uintptr, string) {
	var flags uintptr
	var data []string
	for _, o := range strings.Split(opts, ",") {
		switch {
		case o == "":
		case o == "rw":
		default:
			if f, ok := mountOptionFlags[o]; ok {
				flags |= f
			} else {
				data = append(data, o)
			}
		}
	}
	return flags, strings.Join(data, ",")
}

func runMount(args []string) int {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	source := fs.String("source", "", "device or source path")
	target := fs.String("target", "", "mount point")
	fstype := fs.String("type", "", "filesystem type")
	options := fs.String("options", "", "comma-separated mount options")
	bind := fs.Bool("bind", false, "bind mount source onto target")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" || (*source == "" && !*bind) {
		fmt.Fprintln(os.Stderr, "mount: --source and --target are required")
		return 2
	}
	flags, data := splitMountOptions(*options)
	if *bind {
		if err := unix.Mount(*source, *target, "", unix.MS_BIND|(flags&^unix.MS_RDONLY), ""); err != nil {
			fmt.Fprintf(os.Stderr, "mount: bind %s onto %s: %v\n", *source, *target, err)
			return 1
		}
		// The kernel ignores MS_RDONLY on the initial bind; it needs a remount.
		if flags&unix.MS_RDONLY != 0 {
			if err := unix.Mount("", *target, "", unix.MS_BIND|unix.MS_REMOUNT|flags, ""); err != nil {
				fmt.Fprintf(os.Stderr, "mount: remount %s read-only: %v\n", *target, err)
				return 1
			}
		}
		return 0
	}
	if err := unix.Mount(*source, *target, *fstype, flags, data); err != nil {
		fmt.Fprintf(os.Stderr, "mount: %s on %s (%s): %v\n", *source, *target, *fstype, err)
		return 1
	}
	return 0
}
