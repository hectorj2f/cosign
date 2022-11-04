// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"time"
)

// TSABundle holds metadata about recording a Signature's ephemeral key to
// a TSA timestamp authority.
type TSABundle struct {
	EntryTimestamp time.Time
	Payload        []byte
	// TODO: We might want to store the signature as part of the bundle instead of the certBytes
	CertBytes []byte
}

func EntryToTSABundle(responseBytes []byte, ts time.Time, certBytes []byte) *TSABundle {
	return &TSABundle{
		EntryTimestamp: ts,
		Payload:        responseBytes,
		CertBytes:      certBytes,
	}
}
