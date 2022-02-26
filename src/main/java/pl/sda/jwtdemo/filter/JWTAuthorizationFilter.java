package pl.sda.jwtdemo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.replace("Bearer ", "");

        DecodedJWT decodedJWT = null;

        try {
            decodedJWT = JWT.require(Algorithm.HMAC256("alamakota"))
                    .build()
                    .verify(token);
        } catch (JWTVerificationException ex) {
            response.getWriter().write(ex.getLocalizedMessage());
            response.getWriter().flush();
            response.getWriter().close();

            // TODO: why Access is denied?

            chain.doFilter(request, response);
            return;
        }

        String username = decodedJWT.getSubject();

        if (username != null) {
            UsernamePasswordAuthenticationToken user =
                    new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
            SecurityContextHolder.getContext().setAuthentication(user);
        }

        chain.doFilter(request, response);
    }
}
