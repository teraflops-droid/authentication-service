package service

import (
	"authentication/config"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JWTService interface {
	GenerateTokens(email string, isUser bool) (string, string, error)
	RenewToken(refreshTokenString string) (string, error)
	ValidateToken(encodedToken string) (*jwt.Token, error)
}

type authCustomClaims struct {
	Name string `json:"name"`
	User bool   `json:"user"`
	jwt.RegisteredClaims
}

type jwtServices struct {
	secretKey     string
	refreshSecret string
	issuer        string
}

func JWTAuthService() JWTService {
	return &jwtServices{
		secretKey:     getSecretKey(),
		refreshSecret: getRefreshSecret(),
		issuer:        "Admin",
	}
}

func getSecretKey() string {
	getConfig := config.GetConfig()
	secret := getConfig.GetString("authen.secret")
	if secret == "" {
		secret = "secret"
	}
	return secret
}
func getRefreshSecret() string {
	getConfig := config.GetConfig()
	refreshSecret := getConfig.GetString("authen.refresh")
	if refreshSecret == "" {
		refreshSecret = "refresh_secret"
	}
	return refreshSecret
}
func (service *jwtServices) GenerateTokens(email string, isUser bool) (string, string, error) {
	// Generate Access Token
	accessTokenClaims := &authCustomClaims{
		email,
		isUser,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
			Issuer:    service.issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	// Sign and get the complete encoded access token as a string
	accessTokenString, err := accessToken.SignedString([]byte(service.secretKey))
	if err != nil {
		return "", "", err
	}

	// Generate Refresh Token
	refreshTokenClaims := &authCustomClaims{
		email,
		isUser,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 30)), // Adjust expiration time as needed
			Issuer:    service.issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

	// Sign and get the complete encoded refresh token as a string
	refreshTokenString, err := refreshToken.SignedString([]byte(service.refreshSecret))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

func (service *jwtServices) RenewToken(refreshTokenString string) (string, error) {
	// Validate and parse the refresh token
	refreshToken, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, isvalid := token.Method.(*jwt.SigningMethodHMAC); !isvalid {
			return nil, fmt.Errorf("Invalid refresh token")
		}
		return []byte(service.refreshSecret), nil
	})

	if err != nil {
		return "", err
	}

	// Check if the refresh token is valid
	if claims, ok := refreshToken.Claims.(*authCustomClaims); ok && refreshToken.Valid {
		// Generate a new access token
		newAccessTokenClaims := &authCustomClaims{
			claims.Name,
			claims.User,
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 15)), // Adjust expiration time as needed
				Issuer:    service.issuer,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessTokenClaims)

		// Sign and get the complete encoded access token as a string
		newAccessTokenString, err := newAccessToken.SignedString([]byte(service.secretKey))
		if err != nil {
			return "", err
		}

		return newAccessTokenString, nil
	}

	return "", fmt.Errorf("Invalid refresh token")
}

func (service *jwtServices) ValidateToken(encodedToken string) (*jwt.Token, error) {
	// Parse and validate the token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, isvalid := token.Method.(*jwt.SigningMethodHMAC); !isvalid {
			return nil, fmt.Errorf("Invalid token")
		}
		return []byte(service.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
