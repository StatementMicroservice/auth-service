package com.cbl.statement.security.util;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class HostAddressUtil {
    public static String getHostAddress() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            return "localhost";
        }
    }
}
