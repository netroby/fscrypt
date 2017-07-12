/*
 * pam_fscrypt.go - Checks the validity of a login token key against PAM.
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

package main

/*
#cgo LDFLAGS: -lpam -fPIC
#cgo CFLAGS: -O2 -Wall

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
*/
import "C"
import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"unsafe"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"github.com/google/fscrypt/filesystem"
	"github.com/google/fscrypt/metadata"
	"github.com/google/fscrypt/pam"
	"github.com/google/fscrypt/util"
)

const (
	authtokLabel         = "fscrypt_authtok"
	descriptorLabel      = "fscrypt_descriptor"
	provisionedKeysLabel = "fscrypt_provisioned_keys"
	moduleName           = "pam_fscrypt"
)

func parseArgs(argc C.int, argv **C.char) map[string]bool {
	args := make(map[string]bool)
	for _, cString := range util.PointerSlice(unsafe.Pointer(argv))[:argc] {
		args[C.GoString((*C.char)(cString))] = true
	}
	return args
}

// setupLogging directs turns off standard logging (or redirects it to debug
// syslog if  the "debug" argument is passed) and returns a writer to the error
// syslog.
func setupLogging(args map[string]bool) io.Writer {
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)
	if args["debug"] {
		debugWriter, err := syslog.New(syslog.LOG_DEBUG, moduleName)
		if err == nil {
			log.SetOutput(debugWriter)
		}
	}

	errorWriter, err := syslog.New(syslog.LOG_ERR, moduleName)
	if err != nil {
		return ioutil.Discard
	}
	return errorWriter
}

// flagSet returns true if flag is set in flags.
func flagSet(flags C.int, flag pam.Flag) bool {
	return pam.Flag(flags)&flag != 0
}

// makeKeyFunc returns a KeyFunc which converts the a data pointer to a
// cryptographic key. This KeyFunc will fail on retry.
func makeKeyFunc(data unsafe.Pointer) actions.KeyFunc {
	return func(info actions.ProtectorInfo, retry bool) (*crypto.Key, error) {
		if retry {
			return nil, pam.ErrPAMPassphrase
		}
		l := int(C.strlen((*C.char)(data)))
		r := bytes.NewReader(util.ByteSlice(data)[:l])
		return crypto.NewFixedLengthKeyFromReader(r, l)
	}
}

// loginProtector returns the login protector corresponding to the PAM_USER if
// one exists. This protector descriptor will be cashed in the pam data, under
// descriptorLabel.
func loginProtector(handle *pam.Handle) (*actions.Protector, error) {
	ctx, err := actions.NewContextFromMountpoint("/")
	if err != nil {
		return nil, err
	}
	if descriptor, err := handle.GetString(descriptorLabel); err == nil {
		log.Printf("using cached descriptor %q", descriptor)
		return actions.GetProtector(ctx, descriptor)
	}

	// Find the right protector and write the descriptor to cache.
	pamUID, err := handle.GetUID()
	if err != nil {
		return nil, err
	}
	options, err := ctx.ProtectorOptions()
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		if option.Source() != metadata.SourceType_pam_passphrase || option.UID() != pamUID {
			continue
		}

		log.Printf("caching descriptor %q", option.Descriptor())
		if err = handle.SetString(descriptorLabel, option.Descriptor()); err != nil {
			log.Printf("could not set descriptor data: %s", err)
			// We can still get the protector, so no error.
		}

		return actions.GetProtectorFromOption(ctx, option)
	}
	return nil, fmt.Errorf("no PAM protector on %q", ctx.Mount.Path)
}

var i int

//export pam_sm_authenticate
func pam_sm_authenticate(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))
	fmt.Fprintf(errWriter, "i is %d", i)
	i++

	if _, err := loginProtector(handle); err != nil {
		log.Printf("no need to copy AUTHTOK: %s", err)
		return C.PAM_SUCCESS
	}

	log.Print("copying AUTHTOK in pam_sm_authenticate()")
	authtok, err := handle.GetItem(pam.Authtok)
	if err != nil {
		fmt.Fprintf(errWriter, "could not get AUTHTOK: %s", err)
		return C.PAM_SERVICE_ERR
	}
	if err = handle.SetSecret(authtokLabel, authtok); err != nil {
		fmt.Fprintf(errWriter, "could not set AUTHTOK data: %s", err)
		return C.PAM_SERVICE_ERR
	}
	return C.PAM_SUCCESS
}

//export pam_sm_setcred
func pam_sm_setcred(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

//export pam_sm_open_session
func pam_sm_open_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))
	fmt.Fprintf(errWriter, "i is %d", i)
	i++

	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no directories to unlock: %s", err)
		return C.PAM_SUCCESS
	}

	log.Print("unlocking directories in pam_sm_open_session()")
	// Right now our keyFunc just reads the authtok, and fails if it is
	// incorrect. In the future we could prompt the user for the passphrase.
	authtok, err := handle.GetSecret(authtokLabel)
	if err != nil {
		fmt.Fprintf(errWriter, "no AUTHTOK to unlock directories: %s", err)
		return C.PAM_SERVICE_ERR
	}
	defer handle.ClearSecret(authtokLabel)
	keyFn := makeKeyFunc(authtok)

	var provisionedKeys []string
	// Check each filesystem to see if the protector is in use, then
	// provision all policies protected with the protector.
	mounts, err := filesystem.AllFilesystems()
	if err != nil {
		fmt.Fprint(errWriter, err)
		return C.PAM_SERVICE_ERR
	}
	for _, mount := range mounts {
		// Skip mountpoints that do not have a reference to the
		// specified protector, or where we cannot read the policies.
		if _, _, err := mount.GetProtector(protector.Descriptor()); err != nil {
			continue
		}
		policyDescriptors, err := mount.ListPolicies()
		if err != nil {
			fmt.Fprintf(errWriter, "can't list policies for %q: %s", mount.Path, err)
			continue
		}

		ctx := &actions.Context{Config: protector.Context.Config, Mount: mount}
		// Go though each policy and provision if necessary.
		for _, policyDescriptor := range policyDescriptors {
			policy, err := actions.GetPolicy(ctx, policyDescriptor)
			if err != nil {
				fmt.Fprintf(errWriter, "can't load policy %s: %s",
					policyDescriptor, err)
				continue
			}
			if policy.IsProvisioned() {
				log.Printf("policy %s already provisioned", policyDescriptor)
				continue
			}
			// This does nothing if protector is already unlocked.
			if err := protector.Unlock(keyFn); err != nil {
				fmt.Fprintf(errWriter, "can't unlock protector %s: %s",
					protector.Descriptor(), err)
				return C.PAM_SERVICE_ERR
			}
			if err := policy.UnlockWithProtector(protector); err != nil {
				log.Printf("protector %s: %s", protector.Descriptor(), err)
				continue
			}
			defer policy.Lock()
			if err := policy.Provision(); err != nil {
				fmt.Fprintf(errWriter, "can't provision policy %s: %s",
					policyDescriptor, err)
				continue
			}
			log.Printf("protector %s provisioned", protector.Descriptor())
			provisionedKeys = append(provisionedKeys, policy.Description())
		}
	}

	if len(provisionedKeys) > 0 {
		err = handle.SetSlice(provisionedKeysLabel, provisionedKeys)
		if err != nil {
			fmt.Fprintf(errWriter, "could not set key list data: %s", err)
			return C.PAM_SERVICE_ERR
		}
	}

	return C.PAM_SUCCESS
}

//export pam_sm_close_session
func pam_sm_close_session(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	args := parseArgs(argc, argv)
	errWriter := setupLogging(args)
	fmt.Fprintf(errWriter, "i is %d", i)
	i++

	provisionedKeys, err := handle.GetSlice(provisionedKeysLabel)
	if err != nil {
		log.Printf("no directories to lock: %s", err)
		return C.PAM_SUCCESS
	}

	log.Print("locking directories in pam_sm_close_session()")
	for _, provisionedKey := range provisionedKeys {
		if err := crypto.RemovePolicyKey(provisionedKey); err != nil {
			fmt.Fprintf(errWriter, "can't remove %s: %s", provisionedKey, err)
		}
	}

	if args["drop_caches"] {
		log.Print("dropping page caches")
		f, err := os.OpenFile("/proc/sys/vm/drop_caches", os.O_WRONLY|os.O_SYNC, 0)
		if err != nil {
			fmt.Fprint(errWriter, err)
			return C.PAM_SERVICE_ERR
		}
		defer f.Close()
		if _, err := f.WriteString("3"); err != nil {
			fmt.Fprint(errWriter, err)
			return C.PAM_SERVICE_ERR
		}
	}

	return C.PAM_SUCCESS
}

//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh unsafe.Pointer, flags, argc C.int, argv **C.char) C.int {
	handle := pam.NewHandle(pamh)
	errWriter := setupLogging(parseArgs(argc, argv))
	fmt.Fprintf(errWriter, "i is %d", i)
	i++

	if flagSet(flags, pam.PrelimCheck) {
		log.Print("no preliminary checks need to run")
		return C.PAM_SUCCESS
	}

	protector, err := loginProtector(handle)
	if err != nil {
		log.Printf("no protector to rewrap: %s", err)
		return C.PAM_SUCCESS
	}

	// Get our old and new authentication tokens
	authtok, err := handle.GetItem(pam.Authtok)
	if err != nil {
		fmt.Fprintf(errWriter, "could not get AUTHTOK: %s", err)
		return C.PAM_SERVICE_ERR
	}
	oldAuthtok, err := handle.GetItem(pam.Oldauthtok)
	if err != nil {
		fmt.Fprintf(errWriter, "could not get OLDAUTHTOK: %s", err)
		return C.PAM_SERVICE_ERR
	}

	log.Print("rewrapping protector in pam_sm_chauthtok()")
	if err := protector.Unlock(makeKeyFunc(oldAuthtok)); err != nil {
		fmt.Fprint(errWriter, err)
		return C.PAM_SERVICE_ERR
	}
	if err := protector.Rewrap(makeKeyFunc(authtok)); err != nil {
		fmt.Fprint(errWriter, err)
		return C.PAM_SERVICE_ERR
	}

	return C.PAM_SUCCESS
}

// A main() is needed to make a shared library compile
func main() {}
