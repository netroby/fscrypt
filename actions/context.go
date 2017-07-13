/*
 * context.go - top-level interface to fscrypt packages
 *
 * Copyright 2017 Google Inc.
 * Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

// Package actions is the high-level interface to the fscrypt packages. The
// functions here roughly correspond with commands for the tool in cmd/fscrypt.
// All of the actions include a significant amount of logging, so that good
// output can be provided for cmd/fscrypt's verbose mode.
// The top-level actions currently include:
//	- Creating a new config file
//	- Creating a context on which to perform actions
//	- Creating, unlocking, and modifying Protectors
//	- Creating, unlocking, and modifying Policies
package actions

import (
	"log"

	"github.com/pkg/errors"

	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
)

// Errors relating to Config files or Config structures.
var (
	ErrNoConfigFile     = errors.New("global config file does not exist")
	ErrBadConfigFile    = errors.New("global config file has invalid data")
	ErrConfigFileExists = errors.New("global config file already exists")
	ErrBadConfig        = errors.New("invalid Config structure provided")
	ErrLocked           = errors.New("key needs to be unlocked first")
)

// Context contains the necessary global state to perform most of fscrypt's
// actions. It contains a config struct, which is loaded from the global config
// file, but can be edited manually. A context is specific to a filesystem, and
// all actions to add, edit, remove, and apply Protectors and Policies are done
// relative to that filesystem.
type Context struct {
	Config *metadata.Config
	Mount  *filesystem.Mount
}

// NewContextFromPath makes a context for the filesystem containing the
// specified path and whose Config is loaded from the global config file. On
// success, the Context contains a valid Config and Mount.
func NewContextFromPath(path string) (ctx *Context, err error) {
	ctx = new(Context)
	if ctx.Mount, err = filesystem.FindMount(path); err != nil {
		return
	}
	if ctx.Config, err = getConfig(); err != nil {
		return
	}

	log.Printf("%s is on %s filesystem %q (%s)", path,
		ctx.Mount.Filesystem, ctx.Mount.Path, ctx.Mount.Device)
	return
}

// NewContextFromMountpoint makes a context for the filesystem at the specified
// mountpoint and whose Config is loaded from the global config file. On
// success, the Context contains a valid Config and Mount.
func NewContextFromMountpoint(mountpoint string) (ctx *Context, err error) {
	ctx = new(Context)
	if ctx.Mount, err = filesystem.GetMount(mountpoint); err != nil {
		return
	}
	if ctx.Config, err = getConfig(); err != nil {
		return
	}

	log.Printf("found %s filesystem %q (%s)", ctx.Mount.Filesystem,
		ctx.Mount.Path, ctx.Mount.Device)
	return
}

// checkContext verifies that the context contains an valid config and a mount
// which is being used with fscrypt.
func (ctx *Context) checkContext() error {
	if err := ctx.Config.CheckValidity(); err != nil {
		return errors.Wrap(ErrBadConfig, err.Error())
	}
	return ctx.Mount.CheckSetup()
}

// getService returns the keyring service for this context. We use the presence
// of the LegacyConfig flag to determine if we should use the legacy services
// (which are necessary for kernels before v4.8).
func (ctx *Context) getService() string {
	// For legacy configurations, we may need non-standard services
	if ctx.Config.HasCompatibilityOption(LegacyConfig) {
		switch ctx.Mount.Filesystem {
		case "ext4", "f2fs":
			return ctx.Mount.Filesystem + ":"
		}
	}
	return crypto.DefaultService
}

// getProtectorOption returns the ProtectorOption for the protector on the
// context's mountpoint with the specified descriptor.
func (ctx *Context) getProtectorOption(protectorDescriptor string) *ProtectorOption {
	mnt, data, err := ctx.Mount.GetProtector(protectorDescriptor)
	if err != nil {
		return &ProtectorOption{ProtectorInfo{}, nil, err}
	}

	info := ProtectorInfo{data}
	// No linked path if on the same mountpoint
	if mnt == ctx.Mount {
		return &ProtectorOption{info, nil, nil}
	}
	return &ProtectorOption{info, mnt, nil}
}

// ProtectorOptions creates a slice of all the options for all of the Protectors
// on the Context's mountpoint.
func (ctx *Context) ProtectorOptions() ([]*ProtectorOption, error) {
	if err := ctx.checkContext(); err != nil {
		return nil, err
	}
	descriptors, err := ctx.Mount.ListProtectors()
	if err != nil {
		return nil, err
	}

	options := make([]*ProtectorOption, len(descriptors))
	for i, descriptor := range descriptors {
		options[i] = ctx.getProtectorOption(descriptor)
	}
	return options, nil
}
