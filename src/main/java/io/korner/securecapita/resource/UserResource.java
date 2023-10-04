package io.korner.securecapita.resource;

import io.korner.securecapita.domain.HttpResponse;
import io.korner.securecapita.domain.User;
import io.korner.securecapita.domain.UserPrincipal;
import io.korner.securecapita.dto.UserDTO;
import io.korner.securecapita.dtomapper.UserDTOMapper;
import io.korner.securecapita.exceptions.ApiException;
import io.korner.securecapita.form.LoginForm;
import io.korner.securecapita.provider.TokenProvider;
import io.korner.securecapita.service.RoleService;
import io.korner.securecapita.service.UserService;
import io.korner.securecapita.utils.ExceptionUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

import static java.time.LocalTime.now;
import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping(path = "/user")
@RequiredArgsConstructor
@Slf4j
public class UserResource {
    private final UserService userService;
    private final RoleService roleService;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final HttpServletRequest request;
    private final HttpServletResponse response;

    private static final String TOKEN_PREFIX = "Bearer ";

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> register(@RequestBody @Valid User user){
        UserDTO userDTO = userService.createUser(user);
        return ResponseEntity.created(getUri()).body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userDTO))
                        .message("User created")
                        .status(CREATED)
                        .statusCode(CREATED.value())
                        .build());
    }

    @PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginForm loginForm){
        Authentication authentication = authenticate(loginForm.getEmail(), loginForm.getPassword());
        UserDTO user = getAuthenticatedUser(authentication);
        return user.isUsingMfa() ? sendVerificationCode(user) : sendResponse(user);
    }

    @GetMapping("/verify/code/{email}/{code}")
    public ResponseEntity<HttpResponse> verifyCode(@PathVariable String email, @PathVariable String code){
        UserDTO user = userService.verifyCode(email, code);
        return sendResponse(user);
    }

    @GetMapping("/profile")
    public ResponseEntity<HttpResponse> profile(Authentication authentication){
        UserDTO user = userService.getUserByEmail(authentication.getName());
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Profile retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    // START - To reset password when the user is not logged in

    @GetMapping("/reset-password/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable String email){
        userService.resetPassword(email);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message("Email sent. Please check your email to reset your password")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/verify/password/{key}")
    public ResponseEntity<HttpResponse> verifyPasswordUrl(@PathVariable String key){
        UserDTO user = userService.verifyPasswordUrlKey(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Please enter a new password.")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PostMapping("/reset-password/{key}/{password}/{confirmPassword}")
    public ResponseEntity<HttpResponse> renewPassword(@PathVariable String key, @PathVariable String password, @PathVariable String confirmPassword){
        userService.renewPassword(key, password, confirmPassword);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message("Password reset successfully.")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    // END - To reset password when the user is not logged in

    @GetMapping("/verify/account/{key}")
    public ResponseEntity<HttpResponse> verifyAccount(@PathVariable String key){
        UserDTO user = userService.verifyAccountKey(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message(user.isEnabled() ? "Account already verified." : "Account verified.")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/refresh/token")
    public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request){
        if(isHeaderTokenValid(request)){
            String token = request.getHeader(HttpHeaders.AUTHORIZATION).substring(TOKEN_PREFIX.length());
            UserDTO user = userService.getUserByEmail(tokenProvider.getSubject(token, request));
            return ResponseEntity.ok().body(
                    HttpResponse.builder()
                            .timeStamp(LocalDateTime.now().toString())
                            .message("Token refreshed.")
                            .data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrinciple(user)), "refresh_token", token))
                            .status(OK)
                            .statusCode(OK.value())
                            .build());
        }
        return ResponseEntity.badRequest().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .reason("Refresh token missing or invalid")
                        .developerMessage("Refresh token missing or invalid")
                        .status(BAD_REQUEST)
                        .statusCode(BAD_REQUEST.value())
                        .build());
    }

    @RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleError(HttpServletRequest request) {
        return new ResponseEntity<>(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .reason("There is no mapping for a " + request.getMethod() + " request for this path "+ request.getRequestURI())
                        .status(NOT_FOUND)
                        .statusCode(NOT_FOUND.value())
                        .build(), NOT_FOUND);
    }

    /*@RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleErrorV2(HttpServletRequest request) {
        return ResponseEntity.badRequest().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .reason("There is no mapping for a " + request.getMethod() + " request for this path "+ request.getRequestURI())
                        .status(BAD_REQUEST)
                        .statusCode(BAD_REQUEST.value())
                        .build());
    }*/
    private ResponseEntity<HttpResponse> sendResponse(UserDTO user) {
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrinciple(user)), "refresh_token", tokenProvider.createRefreshToken(getUserPrinciple(user))))
                        .message("Login success")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    private boolean isHeaderTokenValid(HttpServletRequest request) {
        String requestHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        return requestHeader != null
                && requestHeader.startsWith(TOKEN_PREFIX)
                && tokenProvider.isValidToken(
                        tokenProvider.getSubject(requestHeader.substring(TOKEN_PREFIX.length()), request),
                        requestHeader.substring(TOKEN_PREFIX.length())
                );
    }

    private UserPrincipal getUserPrinciple(UserDTO user) {
        return new UserPrincipal(UserDTOMapper.toUser(userService.getUserByEmail(user.getEmail())), roleService.getRoleByUserId(user.getId()));
    }

    //TODO: handle Twilio exception

    private UserDTO getAuthenticatedUser(Authentication authentication){
        return ((UserPrincipal) authentication.getPrincipal()).getUser();
    }

    private Authentication authenticate(String email, String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            return authentication;
        }catch (Exception exception){
            throw new ApiException(exception.getMessage());
        }
    }
    private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO user) {
        userService.sendVerificationCode(user);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Verification code sent")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    private URI getUri() {
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/<userId>").toUriString());
    }
}
