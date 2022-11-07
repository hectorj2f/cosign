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
	"github.com/sigstore/rekor/pkg/generated/models"
)

// Bundle .
type Bundle struct {
	VerificationData
	VerificationMaterial
}

type VerificationData struct {
	Payload RekorPayload
	TimestampVerificationData
}

// VerificationMaterial captures details on the materials used to verify
// signatures.
type VerificationMaterial struct {
	CertBytes []byte
}

type TimestampVerificationData struct {
	SignedEntryTimestamp []byte

	// EntryTimestampAuthority contains the recorded timestamp authority data
	EntryTimestampAuthority []byte
}

func EntryToBundle(tLogEntry *models.LogEntryAnon, tvd *TimestampVerificationData) *Bundle {
	b := &Bundle{}
	if (tLogEntry == nil || tLogEntry.Verification == nil) && tvd == nil {
		return nil
	}
	// Add Transparency log entry
	if tLogEntry != nil && tLogEntry.Verification != nil {
		b.Payload = RekorPayload{
			Body:           tLogEntry.Body,
			IntegratedTime: *tLogEntry.IntegratedTime,
			LogIndex:       *tLogEntry.LogIndex,
			LogID:          *tLogEntry.LogID,
		}
		b.SignedEntryTimestamp = tLogEntry.Verification.SignedEntryTimestamp
	}
	// Check if TimestampVerificationData is nil, otherwise set the EntryTimestampAuthority
	if tvd != nil && len(tvd.EntryTimestampAuthority) > 0 {
		b.EntryTimestampAuthority = tvd.EntryTimestampAuthority
	}
	return b
}
