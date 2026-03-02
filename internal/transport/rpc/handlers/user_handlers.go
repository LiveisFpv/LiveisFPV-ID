package handlers

import (
	liveidv1 "authorization_service/api/live_id/v1"
	"authorization_service/internal/app"
	"authorization_service/internal/domain"
	"authorization_service/internal/service"
	"authorization_service/internal/transport/dto"
	"authorization_service/internal/validation"
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserHandler struct {
	liveidv1.UnimplementedUserServiceServer
	app *app.App
}

func NewUserHandler(a *app.App) *UserHandler {
	return &UserHandler{app: a}
}

func (h *UserHandler) CreateUser(ctx context.Context, req *liveidv1.UserRegisterRequest) (*liveidv1.UserResponse, error) {
	if req.GetFirstName() == "" || req.GetLastName() == "" || req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "first_name, last_name, email, and password are required")
	}
	register := &dto.RegisterRequest{
		FirstName: req.GetFirstName(),
		LastName:  req.GetLastName(),
		Email:     req.GetEmail(),
		Password:  req.GetPassword(),
	}
	err := validation.Valid.Struct(register)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid validation: %s", err)
	}
	user := &domain.User{
		FirstName: req.GetFirstName(),
		LastName:  req.GetLastName(),
		Email:     req.GetEmail(),
		Password:  ptr(req.GetPassword()),
	}
	created, err := h.app.AuthService.CreateUser(ctx, user)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "create user failed: %v", err)
	}
	return userResponse(created), nil
}

func (h *UserHandler) UpdateUser(ctx context.Context, req *liveidv1.UserUpdateRequest) (*liveidv1.UserResponse, error) {
	accessToken, err := accessTokenFromContext(ctx, req.GetAccessToken())
	if err != nil {
		return nil, err
	}
	updatereq := &dto.UserUpdateRequest{
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Email:      req.Email,
		Password:   req.Password,
		LocaleType: req.LocaleType,
	}
	err = validation.Valid.Struct(updatereq)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid validation: %s", err)
	}
	current, err := h.app.AuthService.Authenticate(ctx, accessToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}
	updated := &domain.User{
		FirstName:  current.FirstName,
		LastName:   current.LastName,
		Email:      current.Email,
		Password:   nil,
		Roles:      current.Roles,
		Photo:      current.Photo,
		LocaleType: current.LocaleType,
	}
	if req.FirstName != nil {
		updated.FirstName = req.GetFirstName()
	}
	if req.LastName != nil {
		updated.LastName = req.GetLastName()
	}
	if req.Email != nil {
		updated.Email = req.GetEmail()
	}
	if req.Password != nil {
		updated.Password = ptr(req.GetPassword())
	}
	if req.LocaleType != nil {
		updated.LocaleType = ptr(req.GetLocaleType())
	}

	user, err := h.app.AuthService.UpdateUser(ctx, accessToken, updated)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update user failed: %v", err)
	}
	return userResponse(user), nil
}
