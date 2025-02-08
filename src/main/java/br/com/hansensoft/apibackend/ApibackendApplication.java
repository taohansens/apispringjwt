package br.com.hansensoft.apibackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories(basePackages = "br.com.hansensoft.apibackend.repository.jpa")
@EnableJdbcRepositories(basePackages = "br.com.hansensoft.apibackend.repository.jdbc")
public class ApibackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApibackendApplication.class, args);
	}

}
