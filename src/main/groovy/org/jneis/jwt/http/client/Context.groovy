package org.jneis.jwt.http.client

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

@Configuration
class Context {

    @Bean
    RestTemplate restTemplate() {
        return new RestTemplate()
    }

}
