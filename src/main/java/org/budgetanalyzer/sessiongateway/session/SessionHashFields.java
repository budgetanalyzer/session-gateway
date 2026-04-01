package org.budgetanalyzer.sessiongateway.session;

/** Constants for Redis hash field names in the session data structure. */
public final class SessionHashFields {

  /** User's internal ID from the permission service. */
  public static final String USER_ID = "user_id";

  /** User's IDP subject identifier (e.g. auth0|abc123). */
  public static final String IDP_SUB = "idp_sub";

  /** User's email address. */
  public static final String EMAIL = "email";

  /** User's display name. */
  public static final String DISPLAY_NAME = "display_name";

  /** User's profile picture URL. */
  public static final String PICTURE = "picture";

  /** Comma-separated list of user roles. */
  public static final String ROLES = "roles";

  /** Comma-separated list of user permissions. */
  public static final String PERMISSIONS = "permissions";

  /** IDP refresh token for grant validation. */
  public static final String REFRESH_TOKEN = "refresh_token";

  /** Unix epoch seconds when the IDP access token expires. */
  public static final String TOKEN_EXPIRES_AT = "token_expires_at";

  /** Unix epoch seconds when the session was created. */
  public static final String CREATED_AT = "created_at";

  /** Unix epoch seconds when the session expires. */
  public static final String EXPIRES_AT = "expires_at";

  private SessionHashFields() {}
}
