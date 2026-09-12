package httper

import (
	"context"

	"github.com/IceWhaleTech/CasaOS/internal/zerotierapi"
)

func ZTGet(endpoint string) ([]byte, error) {
	return zerotierapi.Get(endpoint)
}

func ZTGetContext(ctx context.Context, endpoint string) ([]byte, error) {
	return zerotierapi.GetContext(ctx, endpoint)
}

func ZTPost(endpoint string, body string) ([]byte, error) {
	return zerotierapi.Post(endpoint, body)
}

func ZTPostContext(ctx context.Context, endpoint, body string) ([]byte, error) {
	return zerotierapi.PostContext(ctx, endpoint, body)
}
