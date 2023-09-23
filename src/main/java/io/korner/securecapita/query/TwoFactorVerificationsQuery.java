package io.korner.securecapita.query;

public class TwoFactorVerificationsQuery {
    public static final String SELECT_CODE_EXPIRATION_QUERY = "SELECT expiration_date < NOW() AS is_expired FROM TwoFactorVerifications tfv WHERE tfv.code = :code";
}
