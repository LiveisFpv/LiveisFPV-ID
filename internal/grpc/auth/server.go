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

func (s *serverAPI) Login(
	ctx context.Context,
	in *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	return nil, nil
}
func (s *serverAPI) Register(
	ctx context.Context,
	in *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	return nil, nil
}
