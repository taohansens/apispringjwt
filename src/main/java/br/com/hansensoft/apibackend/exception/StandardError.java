package br.com.hansensoft.apibackend.exception;

import java.time.Instant;
import lombok.*;

@NoArgsConstructor
@Getter @Setter
public class StandardError {
    private Instant timestamp;
    private Integer status;
    private String error;
    private String message;
    private String path;
}