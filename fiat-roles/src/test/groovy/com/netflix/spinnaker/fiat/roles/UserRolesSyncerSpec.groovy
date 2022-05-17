/*
 * Copyright 2016 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.fiat.roles

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.netflix.spectator.api.NoopRegistry
import com.netflix.spectator.api.Registry
import com.netflix.spinnaker.fiat.config.ResourceProvidersHealthIndicator
import com.netflix.spinnaker.fiat.config.UnrestrictedResourceConfig
import com.netflix.spinnaker.fiat.config.UserRolesSyncerConfig
import com.netflix.spinnaker.fiat.model.UserPermission
import com.netflix.spinnaker.fiat.model.resources.Account
import com.netflix.spinnaker.fiat.model.resources.Application
import com.netflix.spinnaker.fiat.model.resources.BuildService
import com.netflix.spinnaker.fiat.model.resources.Role
import com.netflix.spinnaker.fiat.model.resources.ServiceAccount
import com.netflix.spinnaker.fiat.permissions.ExternalUser
import com.netflix.spinnaker.fiat.permissions.PermissionResolutionException
import com.netflix.spinnaker.fiat.permissions.PermissionsResolver
import com.netflix.spinnaker.fiat.permissions.RedisPermissionRepositoryConfigProps
import com.netflix.spinnaker.fiat.permissions.RedisPermissionsRepository
import com.netflix.spinnaker.fiat.providers.ResourceProvider
import com.netflix.spinnaker.kork.discovery.DiscoveryStatusListener
import com.netflix.spinnaker.kork.jedis.EmbeddedRedis
import com.netflix.spinnaker.kork.jedis.JedisClientDelegate
import com.netflix.spinnaker.kork.jedis.lock.RedisLockManager
import com.netflix.spinnaker.kork.lock.LockManager
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.boot.actuate.health.Health
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Unroll

import java.time.Clock
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class UserRolesSyncerSpec extends Specification {

  private static final String UNRESTRICTED = UnrestrictedResourceConfig.UNRESTRICTED_USERNAME;

  @Shared
  Registry registry = new NoopRegistry()

  LockManager lockManager

  @Shared
  @AutoCleanup("destroy")
  EmbeddedRedis embeddedRedis

  @Shared
  ObjectMapper objectMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)

  @Shared
  Jedis jedis

  @Shared
  RedisPermissionsRepository repo

  def setupSpec() {
    embeddedRedis = EmbeddedRedis.embed()
    jedis = embeddedRedis.jedis
    jedis.flushDB()
  }

  def setup() {
    repo = new RedisPermissionsRepository(
        objectMapper,
        new JedisClientDelegate(embeddedRedis.pool as JedisPool),
        [new Application(), new Account(), new ServiceAccount(), new Role(), new BuildService()],
        new RedisPermissionRepositoryConfigProps(prefix: "unittests"),
        RetryRegistry.ofDefaults()
    )

    lockManager = new RedisLockManager(
            null, // will fall back to running node name
            Clock.systemDefaultZone(),
            registry,
            objectMapper,
            new JedisClientDelegate(embeddedRedis.pool as JedisPool),
            Optional.empty(),
            Optional.empty())

  }

  def cleanup() {
    jedis.flushDB()
  }

  @Unroll
  def "should update user roles & add service accounts"() {
    setup:
    def extRoleA = new Role("extRoleA").setSource(Role.Source.EXTERNAL)
    def extRoleB = new Role("extRoleB").setSource(Role.Source.EXTERNAL)
    def extRoleC = new Role("extRoleC").setSource(Role.Source.EXTERNAL)
    def user1 = new UserPermission()
        .setId("user1")
        .setAccounts([new Account().setName("account1")] as Set)
        .setRoles([extRoleA] as Set)
    def user2 = new UserPermission()
        .setId("user2")
        .setAccounts([new Account().setName("account2")] as Set)
        .setRoles([extRoleB] as Set)
    def user3 = new UserPermission()
        .setId("user3")
        .setAccounts([new Account().setName("account3")] as Set)
        .setRoles([extRoleC] as Set)
    def unrestrictedUser = new UserPermission()
        .setId(UnrestrictedResourceConfig.UNRESTRICTED_USERNAME)
        .setAccounts([new Account().setName("unrestrictedAccount")] as Set)

    def abcServiceAcct = new UserPermission().setId("abc").setRoles([extRoleC] as Set)
    def xyzServiceAcct = new UserPermission().setId("xyz@domain.com")

    repo.put(user1)
    repo.put(user2)
    repo.put(user3)
    repo.put(unrestrictedUser)

    def newUser2 = new UserPermission()
        .setId("user2")
        .setAccounts([new Account().setName("accountX")] as Set)
        .setRoles([extRoleB] as Set)
    def newUser3 = new UserPermission()
        .setId("user3")
        .setAccounts([new Account().setName("accountX")] as Set)
        .setRoles([extRoleC] as Set)

    def serviceAccountProvider = Mock(ResourceProvider) {
      getAll() >> [new ServiceAccount().setName("abc").setMemberOf(["extRoleC"]),
                   new ServiceAccount().setName("xyz@domain.com")]
    }

    def permissionsResolver = Mock(PermissionsResolver)

    UserRolesSyncerConfig config =  new UserRolesSyncerConfig()
    config.getSynchronization().setEnabled(synchronizeUserRoleSync)
    @Subject
    def syncer = new UserRolesSyncer(
        new DiscoveryStatusListener(true),
        registry,
        lockManager,
        repo,
        permissionsResolver,
        serviceAccountProvider,
        new AlwaysUpHealthIndicator(),
        new JedisClientDelegate(embeddedRedis.pool as JedisPool),
        config
    )

    expect:
    repo.getAllById() == [
        "user1"       : user1.merge(unrestrictedUser),
        "user2"       : user2.merge(unrestrictedUser),
        "user3"       : user3.merge(unrestrictedUser),
        (UNRESTRICTED): unrestrictedUser
    ]

    when:
    syncer.syncAndReturn(syncRoles)

    then:
    permissionsResolver.resolve(_ as List) >> {
      if (fullsync) {
        ["user1"         : user1,
         "user2"         : newUser2,
         "user3"         : newUser3,
         "abc"           : abcServiceAcct,
         "xyz@domain.com": xyzServiceAcct]
      } else {
        ["user3"         : newUser3,
         "abc"           : abcServiceAcct]
      }
    }
    permissionsResolver.resolveUnrestrictedUser() >> unrestrictedUser

    expect:
    def expectedResult
    if (fullsync) {
      expectedResult = [
              "user1"         : user1.merge(unrestrictedUser),
              "user2"         : newUser2.merge(unrestrictedUser),
              "user3"         : newUser3.merge(unrestrictedUser),
              "abc"           : abcServiceAcct.merge(unrestrictedUser),
              "xyz@domain.com": xyzServiceAcct.merge(unrestrictedUser),
              (UNRESTRICTED)  : unrestrictedUser
      ]
    } else {
      expectedResult = [
              "user1"         : user1.merge(unrestrictedUser),
              "user2"         : user2.merge(unrestrictedUser),
              "user3"         : newUser3.merge(unrestrictedUser),
              "abc"           : abcServiceAcct.merge(unrestrictedUser),
              (UNRESTRICTED)  : unrestrictedUser
      ]
    }
    repo.getAllById() == expectedResult

    where:
    syncRoles    | fullsync  | synchronizeUserRoleSync
    null         | true      | false
    []           | true      | false
    ["extrolec"] | false     | false
    null         | true      | true
    []           | true      | true
    ["extrolec"] | true      | true
  }

  @Unroll
  def "should update user roles & add service accounts when invoked by concurrent requests"() {
    setup:
    def extRoleA = new Role("extRoleA").setSource(Role.Source.EXTERNAL)
    def extRoleB = new Role("extRoleB").setSource(Role.Source.EXTERNAL)
    def extRoleC = new Role("extRoleC").setSource(Role.Source.EXTERNAL)
    def user1 = new UserPermission()
            .setId("user1")
            .setAccounts([new Account().setName("account1")] as Set)
            .setRoles([extRoleA] as Set)
    def user2 = new UserPermission()
            .setId("user2")
            .setAccounts([new Account().setName("account2")] as Set)
            .setRoles([extRoleB] as Set)
    def user3 = new UserPermission()
            .setId("user3")
            .setAccounts([new Account().setName("account3")] as Set)
            .setRoles([extRoleC] as Set)
    def unrestrictedUser = new UserPermission()
            .setId(UnrestrictedResourceConfig.UNRESTRICTED_USERNAME)
            .setAccounts([new Account().setName("unrestrictedAccount")] as Set)

    def abcServiceAcct = new UserPermission().setId("abc").setRoles([extRoleC] as Set)
    def xyzServiceAcct = new UserPermission().setId("xyz@domain.com")

    repo.put(user1)
    repo.put(user2)
    repo.put(user3)
    repo.put(unrestrictedUser)

    def newUser2 = new UserPermission()
            .setId("user2")
            .setAccounts([new Account().setName("accountX")] as Set)
            .setRoles([extRoleB] as Set)
    def newUser3 = new UserPermission()
            .setId("user3")
            .setAccounts([new Account().setName("accountX")] as Set)
            .setRoles([extRoleC] as Set)

    def serviceAccountProvider = Mock(ResourceProvider) {
      getAll() >> [new ServiceAccount().setName("abc").setMemberOf(["extRoleC"]),
                   new ServiceAccount().setName("xyz@domain.com")]
    }

    def permissionsResolver = Mock(PermissionsResolver)

    def extUsers
    def expectedResolveOutput
    def expectedResult
    if (synchronizeUserRolesSync || (syncRoles == null || syncRoles.isEmpty())) {
      extUsers = [
              new ExternalUser()
                      .setId(user1.id)
                      .setExternalRoles([new Role("extrolea").setSource(Role.Source.EXTERNAL)] as List<Role>),
              new ExternalUser()
                      .setId(user2.id)
                      .setExternalRoles([new Role("extroleb").setSource(Role.Source.EXTERNAL)] as List<Role>),
              new ExternalUser()
                      .setId(abcServiceAcct.id)
                      .setExternalRoles([new Role("extrolec").setSource(Role.Source.EXTERNAL)] as List<Role>),
              new ExternalUser()
                      .setId(xyzServiceAcct.id)
                      .setExternalRoles([]),
              new ExternalUser()
                      .setId(user3.id)
                      .setExternalRoles([new Role("extrolec").setSource(Role.Source.EXTERNAL)] as List<Role>)
      ]

      expectedResolveOutput = [
              "user1"         : user1,
              "user2"         : newUser2,
              "user3"         : newUser3,
              "abc"           : abcServiceAcct,
              "xyz@domain.com": xyzServiceAcct
      ]

      expectedResult = [
              "user1"         : user1.merge(unrestrictedUser),
              "user2"         : newUser2.merge(unrestrictedUser),
              "user3"         : newUser3.merge(unrestrictedUser),
              "abc"           : abcServiceAcct.merge(unrestrictedUser),
              "xyz@domain.com": xyzServiceAcct.merge(unrestrictedUser),
              (UNRESTRICTED)  : unrestrictedUser
      ]
    } else {
      extUsers =  [
              new ExternalUser()
                      .setId(abcServiceAcct.id)
                      .setExternalRoles([new Role("extrolec").setSource(Role.Source.EXTERNAL)] as List<Role>),
              new ExternalUser()
                      .setId(user3.id)
                      .setExternalRoles([new Role("extrolec").setSource(Role.Source.EXTERNAL)] as List<Role>)
      ]
      expectedResolveOutput = [
              "user3"         : newUser3,
              "abc"           : abcServiceAcct
      ]

      expectedResult = [
              "user1"         : user1.merge(unrestrictedUser),
              "user2"         : user2.merge(unrestrictedUser),
              "user3"         : newUser3.merge(unrestrictedUser),
              "abc"           : abcServiceAcct.merge(unrestrictedUser),
              (UNRESTRICTED)  : unrestrictedUser
      ]
    }

    UserRolesSyncerConfig config =  new UserRolesSyncerConfig()
    config.getSynchronization().setEnabled(synchronizeUserRolesSync)

    @Subject
    def syncer = new UserRolesSyncer(
            new DiscoveryStatusListener(true),
            registry,
            lockManager,
            repo,
            permissionsResolver,
            serviceAccountProvider,
            new AlwaysUpHealthIndicator(),
            new JedisClientDelegate(embeddedRedis.pool as JedisPool),
            config
    )

    expect:
    repo.getAllById() == [
            "user1"       : user1.merge(unrestrictedUser),
            "user2"       : user2.merge(unrestrictedUser),
            "user3"       : user3.merge(unrestrictedUser),
            (UNRESTRICTED): unrestrictedUser
    ]

    when:
    def results = new ArrayList(10)
    def futures = new ArrayList(10)

    def threadPool = Executors.newFixedThreadPool(10)
    try {
      10.times {
        futures.add(threadPool.submit({ ->
          syncer.syncAndReturn(syncRoles)
        } as Callable))
      }
      futures.each {results.add(it.get())}
    } finally {
      threadPool.shutdown()
    }

    then:
    permissionsResolver.resolve(extUsers) >> expectedResolveOutput
    permissionsResolver.resolveUnrestrictedUser() >> unrestrictedUser

    expect:
    repo.getAllById() == expectedResult

    results.each {
      assert it == extUsers.size()
    }

    where:
    syncRoles    | synchronizeUserRolesSync
    null         | true
    []           | true
    ["extrolec"] | true
    null         | false
    []           | false
    ["extrolec"] | false
  }

  @Unroll
  def "should handle exceptions when handling concurrent requests"() {
    setup:
    def extRoleA = new Role("extRoleA").setSource(Role.Source.EXTERNAL)
    def extRoleB = new Role("extRoleB").setSource(Role.Source.EXTERNAL)
    def extRoleC = new Role("extRoleC").setSource(Role.Source.EXTERNAL)
    def user1 = new UserPermission()
            .setId("user1")
            .setAccounts([new Account().setName("account1")] as Set)
            .setRoles([extRoleA] as Set)
    def user2 = new UserPermission()
            .setId("user2")
            .setAccounts([new Account().setName("account2")] as Set)
            .setRoles([extRoleB] as Set)
    def user3 = new UserPermission()
            .setId("user3")
            .setAccounts([new Account().setName("account3")] as Set)
            .setRoles([extRoleC] as Set)
    def unrestrictedUser = new UserPermission()
            .setId(UnrestrictedResourceConfig.UNRESTRICTED_USERNAME)
            .setAccounts([new Account().setName("unrestrictedAccount")] as Set)

    repo.put(user1)
    repo.put(user2)
    repo.put(user3)
    repo.put(unrestrictedUser)

    def serviceAccountProvider = Mock(ResourceProvider) {
      getAll() >> [new ServiceAccount().setName("abc").setMemberOf(["extRoleC"]),
                   new ServiceAccount().setName("xyz@domain.com")]
    }

    def permissionsResolver = Mock(PermissionsResolver)

    UserRolesSyncerConfig config =  new UserRolesSyncerConfig()
    config.getSynchronization().setEnabled(synchronizeUserRolesSync)
    config.setSyncDelayTimeoutMs(50)

    @Subject
    def syncer = new UserRolesSyncer(
            new DiscoveryStatusListener(true),
            registry,
            lockManager,
            repo,
            permissionsResolver,
            serviceAccountProvider,
            new AlwaysUpHealthIndicator(),
            new JedisClientDelegate(embeddedRedis.pool as JedisPool),
            config
    )

    expect:
    repo.getAllById() == [
            "user1"       : user1.merge(unrestrictedUser),
            "user2"       : user2.merge(unrestrictedUser),
            "user3"       : user3.merge(unrestrictedUser),
            (UNRESTRICTED): unrestrictedUser
    ]

    when:
    def results = new ArrayList(2)
    def futures = new ArrayList(2)

    def threadPool = Executors.newFixedThreadPool(2)
    try {
      2.times {
        futures.add(threadPool.submit({ ->
          syncer.syncAndReturn(syncRoles)
        } as Callable))
      }
      futures.each {results.add(it.get())}
    } finally {
      threadPool.shutdown()
    }

    then:
    permissionsResolver.resolve(_ as List) >> {
      throw new PermissionResolutionException("permission resolution failed from provider")
    }
    permissionsResolver.resolveUnrestrictedUser() >> unrestrictedUser

    expect:
    results.each {
      assert it == 0
    }

    where:
    syncRoles    | synchronizeUserRolesSync
    ["extrolec"] | true
    ["extrolec"] | false
  }

  @Unroll
  def "should only schedule sync when in-service"() {
    given:
    def lockManager = Mock(LockManager)
    def userRolesSyncer = new UserRolesSyncer(
        new DiscoveryStatusListener(discoveryStatusEnabled),
        registry,
        lockManager,
        null,
        null,
        null,
        new AlwaysUpHealthIndicator(),
        new JedisClientDelegate(embeddedRedis.pool as JedisPool),
        new UserRolesSyncerConfig()
    )

    when:
    userRolesSyncer.schedule()

    then:
    (shouldAcquireLock ? 1 : 0) * lockManager.acquireLock(_, _)

    where:
    discoveryStatusEnabled                         || shouldAcquireLock
    true                                           || true
    false                                          || false
  }

  class AlwaysUpHealthIndicator extends ResourceProvidersHealthIndicator {
    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
      builder.up()
    }
  }
}
