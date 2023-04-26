package de.mtg.jzlint.domains;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class PublicSuffixHTTP {

    public static void main(String[] args) throws IOException {

        final String url = "https://publicsuffix.org/list/public_suffix_list.dat";
        final RestTemplate restTemplate = new RestTemplate();
        final UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        final ResponseEntity<byte[]> publicSuffixResponse = restTemplate.getForEntity(builder.toUriString(), byte[].class);

        if (publicSuffixResponse.getStatusCode().is2xxSuccessful()) {

            String filename = "jzlint/src/main/resources/public_suffix_list.dat";

            System.out.printf("Writing file to %s%n", filename);

            Files.write(Paths.get(filename), publicSuffixResponse.getBody());
        }

    }

}
