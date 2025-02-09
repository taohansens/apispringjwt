package br.com.hansensoft.apibackend.exception.service;

public class AuthException extends RuntimeException {
    public AuthException(String message) {
        super(message);
    }
}