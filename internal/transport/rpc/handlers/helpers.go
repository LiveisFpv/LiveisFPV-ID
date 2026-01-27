package handlers

import (
	liveidv1 "authorization_service/api/live_id/v1"
	"authorization_service/internal/domain"
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func accessTokenFromContext(ctx context.Context, token string) (string, error) {
	if token != "" {
		parsed, err := parseBearer(token)
		if err != nil {
			return "", status.Error(codes.Unauthenticated, err.Error())
		}
		return parsed, nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing authorization token")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization token")
	}
	parsed, err := parseBearer(values[0])
	if err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	return parsed, nil
}

func parseBearer(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("missing authorization token")
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) == 1 {
		return parts[0], nil
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization token format")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("invalid authorization token format")
	}
	return token, nil
}

func userResponse(user *domain.User) *liveidv1.UserResponse {
	if user == nil {
		return nil
	}
	return &liveidv1.UserResponse{
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		EmailConfirmed: user.EmailConfirmed,
		LocaleType:     user.LocaleType,
		Roles:          user.Roles,
		Photo:          user.Photo,
	}
}

func ptr(value string) *string {
	return &value
}
