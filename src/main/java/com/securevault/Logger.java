package com.securevault;

import java.nio.file.Path;

public class Logger {
    private static final StringBuilder logs = new StringBuilder();

    public static void init(Path logFile, char[] key) throws Exception {
    }

    public static synchronized void log(String message, LogType logType) {
        logs.append("");
    }

    public static void close() {
    }

    public enum LogType {
        SEVERE, ERROR, WARN, INFO
    }
}
