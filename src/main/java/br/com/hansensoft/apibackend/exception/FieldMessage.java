package br.com.hansensoft.apibackend.exception;

import lombok.*;

@NoArgsConstructor @AllArgsConstructor
@Getter @Setter
public class FieldMessage {
    private String fieldName;
    private String message;
}