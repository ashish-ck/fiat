package com.netflix.spinnaker.fiat.permissions;

import java.time.Duration;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties("fiat.redis")
public class RedisPermissionRepositoryConfigProps {

  private String prefix = "spinnaker:fiat";

  @NestedConfigurationProperty private Repository repository = new Repository();

  private boolean storePermissionsAsString;

  @Data
  public static class Repository {
    private Duration getPermissionTimeout = Duration.ofSeconds(1);
    private Duration checkLastModifiedTimeout = Duration.ofMillis(50);
    private int scanCount = 10000;
  }
}
