package main

var (
	// RROR:80:not authenticated
	notAuth = []byte{2, 1, 0, 0, 0, 0, 0, 27, 69, 82, 82, 79, 82, 58, 56, 48, 58, 110, 111, 116, 32, 97, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 101, 100, 10}

	// Invalid credential
	// https://github.com/aerospike/aerospike-client-go/blob/master/types/result_code.go#L188
	invalidCredential = []byte{2, 2, 0, 0, 0, 0, 0, 16, 0, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// Invalid user
	// https://github.com/aerospike/aerospike-client-go/blob/master/types/result_code.go#L173
	invalidUser = []byte{2, 2, 0, 0, 0, 0, 0, 16, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)
