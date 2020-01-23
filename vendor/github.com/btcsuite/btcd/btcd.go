// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	_ "net/http/pprof"

	"github.com/btcsuite/btcd/btcd_lib"
	"github.com/pkg/profile"
)

func main() {
	defer profile.Start().Stop()
	btcd_lib.RunMain()
}
