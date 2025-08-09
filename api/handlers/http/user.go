package http

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

func SignUp(svcGetter ServiceGetter[*service.UserService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.UserSignUpRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}
		response, err := srv.SignUp(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrUserCreationValidation) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		return c.JSON(response)
	}
}

func SignIn(svcGetter ServiceGetter[*service.UserService], cfg config.ServerConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.UserSignInRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}
		response, err := srv.SignIn(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidUserPassword) {
				return fiber.ErrUnauthorized
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		c.Cookie(&fiber.Cookie{
			Name:     "refresh_token",
			Value:    response.RefreshToken,
			Path:     "/",
			Expires:  time.Now().Add(time.Duration(cfg.AuthRefreshMinute) * time.Minute),
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
		})

		// Return only access token in the response body
		return c.JSON(fiber.Map{
			"accessToken": response.AccessToken,
		})
	}
}

func SignOut(svcGetter ServiceGetter[*service.UserService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		refreshToken := c.Cookies("refresh_token")
		if refreshToken == "" {
			return c.JSON(fiber.Map{
				"message": "Already logged out",
			})
		}
		err := srv.SignOut(c.UserContext(), &pb.UserSignOutRequest{
			RefreshToken: refreshToken,
		})
		if err != nil {
			if errors.Is(err, service.ErrSessionOnInvalidate) {
				return fiber.ErrBadRequest
			}
			return fiber.ErrInternalServerError
		}
		c.Cookie(&fiber.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
		})
		return c.JSON(fiber.Map{
			"message": "logged out successfully",
		})
	}
}
