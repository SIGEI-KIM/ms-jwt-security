package com.sigei.ms_jwt_security.config;

import com.sigei.ms_jwt_security.dblayer.entity.Token;
import com.sigei.ms_jwt_security.dblayer.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomLogoutHandler.class);

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("No Authorization header found or header does not start with Bearer");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        String token = authHeader.substring(7);
        Optional<Token> storedTokenOpt = tokenRepository.findByAccessToken(token);

        if (storedTokenOpt.isEmpty()) {
            logger.warn("Token not found in the repository");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        try {
            Token storedToken = storedTokenOpt.get();
            storedToken.setLoggedOut(true);
            tokenRepository.save(storedToken);
            logger.info("Token invalidated successfully for token: {}", token);
            response.setStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            logger.error("Error during token invalidation", e);
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }
}
