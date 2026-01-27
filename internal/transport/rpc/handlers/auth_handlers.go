package handlers

import (
	liveidv1 "authorization_service/api/live_id/v1"
	"authorization_service/internal/app"
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthHandler struct {
	liveidv1.UnimplementedAuthServiceServer
	app *app.App
}

func NewAuthHandler(a *app.App) *AuthHandler {
	return &AuthHandler{app: a}
}

func (h *AuthHandler) Authenticate(ctx context.Context, req *liveidv1.AuthenticateRequest) (*liveidv1.UserResponse, error) {
	accessToken, err := accessTokenFromContext(ctx, req.GetAccessToken())
	if err != nil {
		return nil, err
	}
	user, err := h.app.AuthService.Authenticate(ctx, accessToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}
	return userResponse(user), nil
}

func (h *AuthHandler) Validate(ctx context.Context, req *liveidv1.ValidateRequest) (*emptypb.Empty, error) {
	accessToken, err := accessTokenFromContext(ctx, req.GetAccessToken())
	if err != nil {
		return nil, err
	}
	if _, err := h.app.AuthService.Validate(ctx, accessToken); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "validate failed: %v", err)
	}
	return &emptypb.Empty{}, nil
}
