/*
 * pam.go - Utility functions for interfacing with the PAM libraries.
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

package pam

/*
#cgo LDFLAGS: -lpam
#include "pam.h"

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>

// CleaupFuncs are used to cleanup specific PAM data.
typedef void (*CleanupFunc)(pam_handle_t *pamh, void *data, int error_status);

// Calls free() on data.
void freeData(pam_handle_t *pamh, void *data, int error_status) {
  free(data);
}

// void freeData(pam_handle_t *pamh, void *data, int error_status);
// Frees each item in a null terminated array of pointers and the array itself.
void freeArray(pam_handle_t *pamh, void *data, int error_status) {
  void** array = data;
  while (*array) { free(*(array++)); }
  free(data);
}

void wipeString(pam_handle_t *pamh, void *data, int error_status) {
  // Cast to volitile pointer
  volatile char* p = data;
  while (*p) { *(p++) = 0; }
  free(data);
}

*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/google/fscrypt/util"
)

// Handle wraps the C pam_handle_t type. This is used from within modules.
type Handle struct {
	handle *C.pam_handle_t
	status C.int
}

// NewHandle creates a Handle from a raw pointer.
func NewHandle(pamh unsafe.Pointer) *Handle {
	return &Handle{
		handle: (*C.pam_handle_t)(pamh),
		status: C.PAM_SUCCESS,
	}
}

func (h *Handle) setData(name string, data unsafe.Pointer, cleanup unsafe.Pointer) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	h.status = C.pam_set_data(h.handle, cName, data, (C.CleanupFunc)(cleanup))
	return h.err()
}

func (h *Handle) getData(name string) (unsafe.Pointer, error) {
	var data unsafe.Pointer
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	h.status = C.pam_get_data(h.handle, cName, &data)
	return data, h.err()
}

func (h *Handle) SetSecret(name string, secret unsafe.Pointer) error {
	return h.setData(name, unsafe.Pointer(C.strdup((*C.char)(secret))), C.wipeString)
}

func (h *Handle) GetSecret(name string) (unsafe.Pointer, error) {
	return h.getData(name)
}

func (h *Handle) ClearSecret(name string) error {
	return h.setData(name, unsafe.Pointer(C.CString("")), C.freeData)
}

func (h *Handle) SetString(name string, s string) error {
	return h.setData(name, unsafe.Pointer(C.CString(s)), C.freeData)
}

func (h *Handle) GetString(name string) (string, error) {
	data, err := h.getData(name)
	if err != nil {
		return "", err
	}
	return C.GoString((*C.char)(data)), nil
}

func (h *Handle) SetSlice(name string, slice []string) error {
	sliceLength := uintptr(len(slice))
	memorySize := (sliceLength + 1) * unsafe.Sizeof(uintptr(0))
	data := C.malloc(C.size_t(memorySize))

	cSlice := util.PointerSlice(data)
	for i, str := range slice {
		cSlice[i] = unsafe.Pointer(C.CString(str))
	}
	cSlice[sliceLength] = nil

	return h.setData(name, data, C.freeArray)
}

func (h *Handle) GetSlice(name string) ([]string, error) {
	data, err := h.getData(name)
	if err != nil {
		return nil, err
	}

	var slice []string
	for _, cString := range util.PointerSlice(data) {
		if cString == nil {
			return slice, nil
		}
		slice = append(slice, C.GoString((*C.char)(cString)))
	}
	panic("We will never get here")
}

// GetItem retrieves a PAM information item. This a pointer directory to the
// data, so it shouldn't be modified.
func (h *Handle) GetItem(i Item) (unsafe.Pointer, error) {
	var data unsafe.Pointer
	h.status = C.pam_get_item(h.handle, C.int(i), &data)
	return data, h.err()
}

// GetUID retrieves the UID of the corresponding PAM_USER.
func (h *Handle) GetUID() (int64, error) {
	var pamUsername *C.char
	h.status = C.pam_get_user(h.handle, &pamUsername, nil)
	if err := h.err(); err != nil {
		return 0, err
	}

	pwd := C.getpwnam(pamUsername)
	if pwd == nil {
		return 0, fmt.Errorf("unknown user %q", C.GoString(pamUsername))
	}
	return int64(pwd.pw_uid), nil
}

func (h *Handle) err() error {
	if h.status == C.PAM_SUCCESS {
		return nil
	}
	s := C.GoString(C.pam_strerror(h.handle, C.int(h.status)))
	return errors.New(s)
}

// Transaction represents a wrapped pam_handle_t type created with pam_start
// form an application.
type Transaction Handle

// Start initializes a pam Transaction. End() should be called after the
// Transaction is no longer needed.
func Start(service, username string) (*Transaction, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	t := &Transaction{
		handle: nil,
		status: C.PAM_SUCCESS,
	}
	t.status = C.pam_start(cService, cUsername, &C.conv, &t.handle)
	return t, (*Handle)(t).err()
}

// End finalizes a pam Transaction with pam_end().
func (t *Transaction) End() {
	C.pam_end(t.handle, t.status)
}

// Authenticate returns a boolean indicating if the user authenticated correctly
// or not. If the authentication check did not complete, an error is returned.
func (t *Transaction) Authenticate(quiet bool) (bool, error) {
	var flags C.int = C.PAM_DISALLOW_NULL_AUTHTOK
	if quiet {
		flags |= C.PAM_SILENT
	}
	t.status = C.pam_authenticate(t.handle, flags)
	if t.status == C.PAM_AUTH_ERR {
		return false, nil
	}
	return true, (*Handle)(t).err()
}
