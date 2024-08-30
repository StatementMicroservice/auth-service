package com.cbl.statement.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDto {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private long accessTokenExpiry;

    @JsonProperty("refresh_token_expiry")
    private long refreshTokenExpiry;

    @JsonProperty("token_type")
    private OAuth2AccessToken.TokenType tokenType;

    @JsonProperty("user_name")
    private String userName;
}
