/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package statecouchdb

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/statedb"
	"github.com/hyperledger/fabric/core/ledger/ledgerconfig"
	"github.com/hyperledger/fabric/core/ledger/util/couchdb"
	"github.com/stretchr/testify/assert"
)

var testConfig *couchdb.Config

// TestVDBEnv provides a couch db backed versioned db for testing
type TestVDBEnv struct {
	t          testing.TB
	DBProvider statedb.VersionedDBProvider
}

// NewTestVDBEnv instantiates and new couch db backed TestVDB
func NewTestVDBEnv(t testing.TB) *TestVDBEnv {
	t.Logf("Creating new TestVDBEnv")
	dbPath := ledgerconfig.GetCouchdbRedologsPath()
	assert.NoError(t, os.RemoveAll(dbPath))
	dbProvider, err := NewVersionedDBProvider(testConfig, &disabled.Provider{})
	if err != nil {
		t.Fatalf("Error creating CouchDB Provider: %s", err)
	}
	testVDBEnv := &TestVDBEnv{t, dbProvider}
	// No cleanup for new test environment.  Need to cleanup per test for each DB used in the test.
	return testVDBEnv
}

func (env *TestVDBEnv) CloseAndReopen() {
	env.DBProvider.Close()
	dbProvider, _ := NewVersionedDBProvider(testConfig, &disabled.Provider{})
	env.DBProvider = dbProvider
}

// Cleanup drops the test couch databases and closes the db provider
func (env *TestVDBEnv) Cleanup() {
	env.t.Logf("Cleaningup TestVDBEnv")
	CleanupDB(env.t, env.DBProvider)
	dbPath := ledgerconfig.GetCouchdbRedologsPath()
	env.DBProvider.Close()
	os.RemoveAll(dbPath)
}

func CleanupDB(t testing.TB, dbProvider statedb.VersionedDBProvider) {
	couchdbProvider, _ := dbProvider.(*VersionedDBProvider)
	for _, v := range couchdbProvider.databases {
		if _, err := v.metadataDB.DropDatabase(); err != nil {
			assert.Failf(t, "DropDatabase %s fails. err: %v", v.metadataDB.DBName, err)
		}

		for _, db := range v.namespaceDBs {
			if _, err := db.DropDatabase(); err != nil {
				assert.Failf(t, "DropDatabase %s fails. err: %v", db.DBName, err)
			}
		}
	}
}
