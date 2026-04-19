package com.securevault.configurations;

class LockdownModeException extends RuntimeException {
    LockdownModeException(String message) {
        super(message);
    }
}
