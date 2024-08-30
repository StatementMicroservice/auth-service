package com.cbl.statement.security.consts;

public class ExceptionMsg {

    public static final String USER_ALREADY_EXIST = "User with this email/username already exists.";
    public static final String USER_NOT_FOUND_REGISTER = "The username or email: '%s' provided does not exist. Please register first.";
    public static final String USER_NOT_FOUND = "The username or email: '%s' provided does not exist.";
    public static final String USER_NOT_FOUND_DURING_TOKEN_VALIDATION = "The username or email: '%s' does not exist in DB during token validation.";
    public static final String VERIFY_TOKEN_TYPE = "Please verify your token type";
    public static final String REFRESH_TOKEN_NOT_FOUND = "No refresh token found in DB for the given refresh token in the request.";
    public static final String CREDENTIALS_REQUIRED = "Credential Required. Please provide credentials.";
    public static final String REFRESH_TOKEN_NOT_FOUND_DURING_LOGOUT = "Refresh token not found during logout.";
    public static final String MISSING_BEARER_TOKEN = "Bearer token is missing in the authorization header.";
    public static final String INCORRECT_CREDENTIALS = "The provided credentials are incorrect.";
    public static final String REFRESH_TOKEN_ALREADY_REVOKED = "Refresh token already revoked.";
    public static final String AUTHENTICATION_FAILED = "Authentication failed";
    public static final String INVALID_BEARER_TOKEN = "Invalid Token. Auth header is not starts with 'Bearer'";
    public static final String INVALID_TOKEN = "Invalid Token.";
    public static final String UNSUPPORTED_AUTHORITIES = "Unsupported authorities claim type";
    public static final String TOKEN_EXPIRED = "Token is expired.";
    public static final String REFRESH_TOKEN_EXPIRED = "Refresh token is expired.";
    public static final String PRIVILEGE_ALREADY_EXIST = "Privilege: %s already exits.";
    public static final String ROLE_ALREADY_EXIST = "Role: %s already exists.";
}
