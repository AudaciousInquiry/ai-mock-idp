/*
 * Copyright (c) 2020 Audacious Inquiry, LLC
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.ainq.mockidp.util;

import com.ainq.mockidp.model.User;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import lombok.extern.slf4j.Slf4j;

/**
 * Reads user information from the YAML files.
 * Location is specified via MOCK_USERS_DIR environment variable
 * @author esharapov
 */
@Slf4j
@Component
public class ReadUsers {
    public static final String MOCK_USERS_DIR = "MOCK_USERS_DIR";
    public static final String DOCKER_DATA = "/data";

    private static final LinkOption[] NO_FOLLOW = new LinkOption[]{ LinkOption.NOFOLLOW_LINKS};

    /**
     * Returns a path from which to read files. 
     * @return
     */
    public String findResourcesLocation () {
        String mockUsersDir = System.getenv(MOCK_USERS_DIR);
        if( mockUsersDir != null && !mockUsersDir.isEmpty() && Files.exists(Paths.get(mockUsersDir), NO_FOLLOW)){
            return mockUsersDir;
        } else if ( Files.exists(Paths.get(DOCKER_DATA), NO_FOLLOW)) {
            return DOCKER_DATA; 
        }else {
            return (new java.io.File(".")).getAbsolutePath();
        }
    }

    public User loadUserFromYaml(Path path) {
        Yaml yaml = new Yaml();
        User user = null;
        // sees fishy only at first glance
        try {
            try (InputStream is = Files.newInputStream(path)) {
                user = yaml.loadAs(is, User.class);
            }
        } catch (IOException e) {
        }
        return user;
    }

    /**
     * Returns list of users read from YAML resources
     * @return
     * @throws IOException
     */
    public List<User> getUsers ( ) throws IOException {
        try (Stream<Path> paths = Files.walk(Paths.get(findResourcesLocation()))) {
            return paths.filter(Files::isRegularFile)
                .sorted(Comparator.comparing(p -> p.toFile().getName(), Comparator.naturalOrder()))
                // only yml files 
                .filter( path -> path.toString().endsWith("yml"))
                .map(this::loadUserFromYaml)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        } 
 
    }
    
}