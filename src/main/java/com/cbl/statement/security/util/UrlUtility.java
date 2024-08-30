package com.cbl.statement.security.util;

public class UrlUtility {

    public static final String BASE_URL = "/city-statement/auth";
    public static final String BASE_URL_API = "/city-statement/auth/api";
    public static final String BASE_URL_SERVICE_TO_SERVICE_API = "/city-statement/auth/service-to-service/api";
    public static final String VERSION_1 = "/v1";
    public static final String AUTH_CONTROLLER = BASE_URL+VERSION_1;
    public static final String DUMMY_DASHBOARD_CONTROLLER = BASE_URL_API+VERSION_1;
    public static final String USER_DETAILS_CONTROLLER = BASE_URL_SERVICE_TO_SERVICE_API+"/user-details"+VERSION_1;
}
