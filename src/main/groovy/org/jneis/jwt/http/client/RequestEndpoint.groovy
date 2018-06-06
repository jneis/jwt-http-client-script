package org.jneis.jwt.http.client

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpMethod
import org.springframework.http.RequestEntity
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate

@RestController
class RequestEndpoint {

    @Autowired
    RestTemplate template

    @Autowired
    PrivateKeyProvider keys

    @PostMapping('/get')
    Response get(@RequestBody Request request) {
        def jwt = JWT.create()
                .withKeyId(keys.kid)
                .withClaim('path', request.path)
                .withIssuedAt(new Date())
                .sign(Algorithm.RSA256(keys))

        def headers = new LinkedMultiValueMap()

        request.headers.each {
            headers.add(it.key, it.value)
        }
        headers.add('Authorization', 'Bearer ' + jwt)

        def uri = new URI(request.url)
        def requestEntity = new RequestEntity(headers, HttpMethod.GET, uri)
        def responseEntity = template.exchange(requestEntity, String)
        def status = responseEntity.statusCode
        def responseHeaders = new LinkedHashMap()
        responseEntity.headers.each {
            responseHeaders.put(it.key, it.value.join(','))
        }

        return new Response(
                headers: responseHeaders,
                status: "${status.value()} ${status.reasonPhrase}",
                body: responseEntity.body
        )
    }

}
