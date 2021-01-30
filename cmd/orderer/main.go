/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main is the entrypoint for the orderer binary
// and calls only into the server.Main() function.  No other
// function should be included in this package.
package main

import (
	"github.com/hyperledger/fabric/orderer/common/server"
)
import _ "net/http/pprof"
func main() {
	//go func() {
	//	// 启动一个 http server，注意 pprof 相关的 handler 已经自动注册过了
	//	if err := http.ListenAndServe(":6060", nil); err != nil {
	//
	//	}
	//}()
	//runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
	//runtime.SetBlockProfileRate(1) // 开启对阻塞操作的跟踪
	server.Main()
}
