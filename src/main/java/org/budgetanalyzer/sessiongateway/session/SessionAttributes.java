package org.budgetanalyzer.sessiongateway.session;

/** Constants for session attribute keys used across the session gateway. */
public final class SessionAttributes {

  /** Session attribute key for the user's internal ID. */
  public static final String SESSION_USER_ID = "INTERNAL_USER_ID";

  /** Session attribute key for the user's roles. */
  public static final String SESSION_ROLES = "INTERNAL_ROLES";

  /** Session attribute key for the user's permissions. */
  public static final String SESSION_PERMISSIONS = "INTERNAL_PERMISSIONS";

  private SessionAttributes() {}
}
