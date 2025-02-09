package br.com.hansensoft.apibackend.exception.service;

public class AccountException extends RuntimeException {
    public AccountException(String message) {
        super(message);
    }
}