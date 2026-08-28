package httper

import (
	"context"
	"testing"
)

type zeroTierGetSignature func(string) ([]byte, error)
type zeroTierPostSignature func(string, string) ([]byte, error)
type zeroTierGetContextSignature func(context.Context, string) ([]byte, error)
type zeroTierPostContextSignature func(context.Context, string, string) ([]byte, error)

func TestZeroTierHelperSignaturesRemainCompatible(t *testing.T) {
	get := zeroTierGetSignature(ZTGet)
	post := zeroTierPostSignature(ZTPost)
	getContext := zeroTierGetContextSignature(ZTGetContext)
	postContext := zeroTierPostContextSignature(ZTPostContext)
	if get == nil || post == nil || getContext == nil || postContext == nil {
		t.Fatal("ZeroTier helper API is unavailable")
	}
}
