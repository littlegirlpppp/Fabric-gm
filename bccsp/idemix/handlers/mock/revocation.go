// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	// "crypto/ecdsa"
	"github.com/jxu86/gmsm/sm2"
	"sync"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/idemix/handlers"
)

type Revocation struct {
	NewKeyStub        func() (*sm2.PrivateKey, error)
	newKeyMutex       sync.RWMutex
	newKeyArgsForCall []struct {
	}
	newKeyReturns struct {
		result1 *sm2.PrivateKey
		result2 error
	}
	newKeyReturnsOnCall map[int]struct {
		result1 *sm2.PrivateKey
		result2 error
	}
	SignStub        func(*sm2.PrivateKey, [][]byte, int, bccsp.RevocationAlgorithm) ([]byte, error)
	signMutex       sync.RWMutex
	signArgsForCall []struct {
		arg1 *sm2.PrivateKey
		arg2 [][]byte
		arg3 int
		arg4 bccsp.RevocationAlgorithm
	}
	signReturns struct {
		result1 []byte
		result2 error
	}
	signReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	VerifyStub        func(*sm2.PublicKey, []byte, int, bccsp.RevocationAlgorithm) error
	verifyMutex       sync.RWMutex
	verifyArgsForCall []struct {
		arg1 *sm2.PublicKey
		arg2 []byte
		arg3 int
		arg4 bccsp.RevocationAlgorithm
	}
	verifyReturns struct {
		result1 error
	}
	verifyReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Revocation) NewKey() (*sm2.PrivateKey, error) {
	fake.newKeyMutex.Lock()
	ret, specificReturn := fake.newKeyReturnsOnCall[len(fake.newKeyArgsForCall)]
	fake.newKeyArgsForCall = append(fake.newKeyArgsForCall, struct {
	}{})
	fake.recordInvocation("NewKey", []interface{}{})
	fake.newKeyMutex.Unlock()
	if fake.NewKeyStub != nil {
		return fake.NewKeyStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.newKeyReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Revocation) NewKeyCallCount() int {
	fake.newKeyMutex.RLock()
	defer fake.newKeyMutex.RUnlock()
	return len(fake.newKeyArgsForCall)
}

func (fake *Revocation) NewKeyCalls(stub func() (*sm2.PrivateKey, error)) {
	fake.newKeyMutex.Lock()
	defer fake.newKeyMutex.Unlock()
	fake.NewKeyStub = stub
}

func (fake *Revocation) NewKeyReturns(result1 *sm2.PrivateKey, result2 error) {
	fake.newKeyMutex.Lock()
	defer fake.newKeyMutex.Unlock()
	fake.NewKeyStub = nil
	fake.newKeyReturns = struct {
		result1 *sm2.PrivateKey
		result2 error
	}{result1, result2}
}

func (fake *Revocation) NewKeyReturnsOnCall(i int, result1 *sm2.PrivateKey, result2 error) {
	fake.newKeyMutex.Lock()
	defer fake.newKeyMutex.Unlock()
	fake.NewKeyStub = nil
	if fake.newKeyReturnsOnCall == nil {
		fake.newKeyReturnsOnCall = make(map[int]struct {
			result1 *sm2.PrivateKey
			result2 error
		})
	}
	fake.newKeyReturnsOnCall[i] = struct {
		result1 *sm2.PrivateKey
		result2 error
	}{result1, result2}
}

func (fake *Revocation) Sign(arg1 *sm2.PrivateKey, arg2 [][]byte, arg3 int, arg4 bccsp.RevocationAlgorithm) ([]byte, error) {
	var arg2Copy [][]byte
	if arg2 != nil {
		arg2Copy = make([][]byte, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.signMutex.Lock()
	ret, specificReturn := fake.signReturnsOnCall[len(fake.signArgsForCall)]
	fake.signArgsForCall = append(fake.signArgsForCall, struct {
		arg1 *sm2.PrivateKey
		arg2 [][]byte
		arg3 int
		arg4 bccsp.RevocationAlgorithm
	}{arg1, arg2Copy, arg3, arg4})
	fake.recordInvocation("Sign", []interface{}{arg1, arg2Copy, arg3, arg4})
	fake.signMutex.Unlock()
	if fake.SignStub != nil {
		return fake.SignStub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.signReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Revocation) SignCallCount() int {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	return len(fake.signArgsForCall)
}

func (fake *Revocation) SignCalls(stub func(*sm2.PrivateKey, [][]byte, int, bccsp.RevocationAlgorithm) ([]byte, error)) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = stub
}

func (fake *Revocation) SignArgsForCall(i int) (*sm2.PrivateKey, [][]byte, int, bccsp.RevocationAlgorithm) {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	argsForCall := fake.signArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *Revocation) SignReturns(result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	fake.signReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Revocation) SignReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	if fake.signReturnsOnCall == nil {
		fake.signReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.signReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Revocation) Verify(arg1 *sm2.PublicKey, arg2 []byte, arg3 int, arg4 bccsp.RevocationAlgorithm) error {
	var arg2Copy []byte
	if arg2 != nil {
		arg2Copy = make([]byte, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.verifyMutex.Lock()
	ret, specificReturn := fake.verifyReturnsOnCall[len(fake.verifyArgsForCall)]
	fake.verifyArgsForCall = append(fake.verifyArgsForCall, struct {
		arg1 *sm2.PublicKey
		arg2 []byte
		arg3 int
		arg4 bccsp.RevocationAlgorithm
	}{arg1, arg2Copy, arg3, arg4})
	fake.recordInvocation("Verify", []interface{}{arg1, arg2Copy, arg3, arg4})
	fake.verifyMutex.Unlock()
	if fake.VerifyStub != nil {
		return fake.VerifyStub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.verifyReturns
	return fakeReturns.result1
}

func (fake *Revocation) VerifyCallCount() int {
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	return len(fake.verifyArgsForCall)
}

func (fake *Revocation) VerifyCalls(stub func(*sm2.PublicKey, []byte, int, bccsp.RevocationAlgorithm) error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = stub
}

func (fake *Revocation) VerifyArgsForCall(i int) (*sm2.PublicKey, []byte, int, bccsp.RevocationAlgorithm) {
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	argsForCall := fake.verifyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *Revocation) VerifyReturns(result1 error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = nil
	fake.verifyReturns = struct {
		result1 error
	}{result1}
}

func (fake *Revocation) VerifyReturnsOnCall(i int, result1 error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = nil
	if fake.verifyReturnsOnCall == nil {
		fake.verifyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.verifyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Revocation) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.newKeyMutex.RLock()
	defer fake.newKeyMutex.RUnlock()
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Revocation) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ handlers.Revocation = new(Revocation)
