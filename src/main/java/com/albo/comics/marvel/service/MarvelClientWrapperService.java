package com.albo.comics.marvel.service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import com.albo.comics.marvel.domain.CharacterDOS;
import com.albo.comics.marvel.repository.CharacterRepository;
import com.albo.comics.marvel.vo.remote.character.Character;
import com.albo.comics.marvel.vo.remote.character.MarvelCharacterResponse;
import com.albo.comics.marvel.vo.remote.comicsByCharacter.MarvelComicResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import io.quarkus.cache.CacheResult;

/**
 * Utility service that wraps requests to Marvel API with enhanced security features
 */
@AwplicationScoped
public class MarvelClientWrapperService {

    private static final Logger LOG = Logger.getLogger(MarvelClientWrapperService.class);
    
    // Security constants
    private static final int MAX_NICKNAME_LENGTH = 100;
    private static final int MAX_LIMIT_VALUE = 100;
    private static final int MAX_OFFSET_VALUE = 10000;
    private static final String ALPHANUMERIC_PATTERN = "^[a-zA-Z0-9\\s\\-]+$";

    @Inject
    @RestClient
    MarvelApiClientService marvelApiClientService;

    @Inject
    CharacterRepository characterRepository;

    @ConfigProperty(name = "marvel.api.key.public")
    private String publicKey;

    @ConfigProperty(name = "marvel.api.key.private")
    private String privateKey;

    /**
     * Generates a secure timestamp for API authentication
     * @return current timestamp as string
     */
    private String getTimeStamp() {
        return String.valueOf(System.currentTimeMillis());
    }

    /**
     * Generates MD5 hash for Marvel API authentication
     * @param timeStamp the timestamp to include in hash
     * @return MD5 hash string
     * @throws IllegalArgumentException if API keys are not properly configured
     */
    private String getHash(String timeStamp) {
        if (timeStamp == null || timeStamp.trim().isEmpty()) {
            throw new IllegalArgumentException("Timestamp cannot be null or empty");
        }
        
        if (privateKey == null || publicKey == null) {
            LOG.error("API keys are not properly configured");
            throw new IllegalStateException("API keys must be configured");
        }
        
        StringBuilder apiKeys = new StringBuilder(timeStamp);
        apiKeys.append(privateKey);
        apiKeys.append(publicKey);

        return DigestUtils.md5Hex(apiKeys.toString());
    }

    /**
     * Validates and sanitizes input parameters for API calls
     * @param id character ID
     * @param limit result limit
     * @param offset result offset
     * @throws IllegalArgumentException if parameters are invalid
     */
    private void validateApiParameters(Long id, Integer limit, Integer offset) {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Character ID must be a positive number");
        }
        
        if (limit != null && (limit <= 0 || limit > MAX_LIMIT_VALUE)) {
            throw new IllegalArgumentException("Limit must be between 1 and " + MAX_LIMIT_VALUE);
        }
        
        if (offset != null && (offset < 0 || offset > MAX_OFFSET_VALUE)) {
            throw new IllegalArgumentException("Offset must be between 0 and " + MAX_OFFSET_VALUE);
        }
    }

    /**
     * Validates and sanitizes character name input
     * @param name character name to validate
     * @return sanitized name
     * @throws IllegalArgumentException if name is invalid
     */
    private String validateAndSanitizeName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Character name cannot be null or empty");
        }
        
        String sanitizedName = name.trim();
        
        if (sanitizedName.length() > MAX_NICKNAME_LENGTH) {
            throw new IllegalArgumentException("Character name exceeds maximum length of " + MAX_NICKNAME_LENGTH);
        }
        
        if (!sanitizedName.matches(ALPHANUMERIC_PATTERN)) {
            throw new IllegalArgumentException("Character name contains invalid characters");
        }
        
        return sanitizedName;
    }

    /**
     * Safely handles API errors without exposing sensitive information
     * @param e exception to handle
     * @param operation description of the operation being performed
     */
    private void handleApiError(Exception e, String operation) {
        // Log detailed error information for debugging, but don't expose it to clients
        LOG.errorf("API error during %s: %s", operation, e.getMessage());
        LOG.debug("Full stack trace", e);
    }

    @CacheResult(cacheName = "api-comics-by-character-cache")
    public MarvelComicResponse getComicsByCharacterId(Long id, Integer limit, Integer offset) {
        try {
            // Validate input parameters
            validateApiParameters(id, limit, offset);
            
            String ts = getTimeStamp();
            LOG.debugf("Requesting Comic data for character with id %s. Limit = [%s]. Offset = [%s]", 
                id, limit, offset);
            
            MarvelComicResponse response = marvelApiClientService.getComicsByIdCharacter(
                id, limit, offset, ts, publicKey, getHash(ts));
                
            if (response == null) {
                LOG.warnf("Null response received for character ID: %s", id);
            }
            
            return response;
            
        } catch (IllegalArgumentException e) {
            LOG.warnf("Invalid parameters for getComicsByCharacterId: %s", e.getMessage());
            throw e;
        } catch (Exception e) {
            handleApiError(e, "getComicsByCharacterId");
            return null;
        }
    }

    @CacheResult(cacheName = "api-character-name-cache")
    public Character getRemoteCharacterByName(String name) {
        try {
            // Validate and sanitize input
            String sanitizedName = validateAndSanitizeName(name);
            
            String ts = getTimeStamp();
            LOG.debugf("Requesting Character data for character %s", sanitizedName);
            
            MarvelCharacterResponse response = marvelApiClientService.getByName(
                sanitizedName, ts, publicKey, getHash(ts));

            if (response != null && "200".equals(response.getCode()) && 
                response.getResponseData() != null && 
                response.getResponseData().getCharacters() != null && 
                !response.getResponseData().getCharacters().isEmpty()) {
                    
                return (Character) response.getResponseData().getCharacters().toArray()[0];
            } else {
                LOG.warnf("No valid character data found for name: %s", sanitizedName);
            }
            
            return null;
            
        } catch (IllegalArgumentException e) {
            LOG.warnf("Invalid character name: %s", e.getMessage());
            throw e;
        } catch (Exception e) {
            handleApiError(e, "getRemoteCharacterByName");
            return null;
        }
    }

    @CacheResult(cacheName = "api-character-alias-cache")
    public Character getRemoteCharacterByAlias(String alias) {
        try {
            // Validate and sanitize input
            String sanitizedAlias = validateAndSanitizeName(alias);
            
            CharacterDO character = characterRepository.findByAlias(sanitizedAlias);
            
            if (character == null) {
                LOG.warnf("No character found with alias: %s", sanitizedAlias);
                return null;
            }
            
            return this.getRemoteCharacterByName(character.getName());
            
        } catch (IllegalArgumentException e) {
            LOG.warnf("Invalid character alias: %s", e.getMessage());
            throw e;
        } catch (Exception e) {
            handleApiError(e, "getRemoteCharacterByAlias");
            return null;
        }
    }
}