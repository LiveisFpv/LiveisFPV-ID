package auth

import (
	"context"

	ssov1 "github.com/LiveisFPV/sso_v1/gen/go/sso"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

// Interface from grpcApp
type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
}
