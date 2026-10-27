/**
  * Licensed to the Apache Software Foundation (ASF) under one or more
  * contributor license agreements.  See the NOTICE file distributed with
  * this work for additional information regarding copyright ownership.
  * The ASF licenses this file to You under the Apache License, Version 2.0
  * (the "License"); you may not use this file except in compliance with
  * the License.  You may obtain a copy of the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
package kafka.server

import kafka.utils.TestUtils
import org.apache.kafka.common.TopicPartition
import org.apache.kafka.common.config.TopicConfig
import org.apache.kafka.common.protocol.{ApiKeys, Errors}
import org.apache.kafka.common.requests.{FetchMetadata => JFetchMetadata}
import org.apache.kafka.server.config.ServerConfigs
import org.junit.jupiter.api.Assertions._
import org.junit.jupiter.api.Test

import java.util.Properties
import scala.jdk.CollectionConverters._
import scala.util.Using

/**
  * Tests that fetch requests over max.partitions.per.fetch.session are served
  * without a fetch session instead of failing.
  */
class FetchSessionPartitionLimitTest extends BaseFetchRequestTest {

  private val maxPartitionsPerFetchSession = 5
  private val version = ApiKeys.FETCH.latestVersion()
  private val FetchSessionPartitionLimitExceededPerSec = "FetchSessionPartitionLimitExceededPerSec"

  override def brokerPropertyOverrides(properties: Properties): Unit = {
    super.brokerPropertyOverrides(properties)
    properties.put(ServerConfigs.MAX_PARTITIONS_PER_FETCH_SESSION_CONFIG, maxPartitionsPerFetchSession.toString)
  }

  @Test
  def testFullFetchExceedingLimitFallsBackToSessionless(): Unit = {
    val topicPartitions = createTopics(numTopics = 1, numPartitions = maxPartitionsPerFetchSession + 1).keySet.toSeq
    val topicNames = getTopicIds().map(_.swap).asJava
    val leaderId = brokers.head.config.brokerId

    val fetchResponse = sendFetchRequest(leaderId,
      createConsumerFetchRequest(Int.MaxValue, 1024, topicPartitions, Map.empty, version, metadata = JFetchMetadata.INITIAL))

    assertEquals(Errors.NONE, fetchResponse.error())
    assertEquals(JFetchMetadata.INVALID_SESSION_ID, fetchResponse.sessionId())
    assertEquals(topicPartitions.size, fetchResponse.responseData(topicNames, version).size())
  }

  @Test
  def testIncrementalFetchExceedingLimitClosesSessionAndFallsBack(): Unit = {
    val allPartitions = createTopics(numTopics = 2, numPartitions = maxPartitionsPerFetchSession)
    val topicNames = getTopicIds().map(_.swap).asJava
    val leaderId = brokers.head.config.brokerId
    val initialPartitions = allPartitions.keySet.filter(_.topic == "topic0").toSeq.sortBy(_.partition).take(2)
    val growthPartitions = allPartitions.keySet.filter(_.topic == "topic1").toSeq.sortBy(_.partition)
    assertTrue(initialPartitions.size + growthPartitions.size > maxPartitionsPerFetchSession)

    val initialResponse = sendFetchRequest(leaderId,
      createConsumerFetchRequest(Int.MaxValue, 1024, initialPartitions, Map.empty, version, metadata = JFetchMetadata.INITIAL))
    assertEquals(Errors.NONE, initialResponse.error())
    assertNotEquals(JFetchMetadata.INVALID_SESSION_ID, initialResponse.sessionId())

    val growthResponse = sendFetchRequest(leaderId,
      createConsumerFetchRequest(Int.MaxValue, 1024, growthPartitions, Map.empty, version,
        metadata = new JFetchMetadata(initialResponse.sessionId(), 1)))

    assertEquals(Errors.NONE, growthResponse.error())
    assertEquals(JFetchMetadata.INVALID_SESSION_ID, growthResponse.sessionId())
    assertEquals((initialPartitions ++ growthPartitions).toSet,
      growthResponse.responseData(topicNames, version).keySet().asScala.toSet)

    val followUpResponse = sendFetchRequest(leaderId,
      createConsumerFetchRequest(Int.MaxValue, 1024, Seq.empty, Map.empty, version,
        metadata = new JFetchMetadata(initialResponse.sessionId(), 1)))
    assertEquals(Errors.FETCH_SESSION_ID_NOT_FOUND, followUpResponse.error())
  }

  @Test
  def testReplicationKeepsWorkingWhenFollowerSessionExceedsLimit(): Unit = {
    val leaderId = brokers.head.config.brokerId
    val follower = brokers(1)
    val assignment = (0 until maxPartitionsPerFetchSession - 1).map(_ -> Seq(leaderId, follower.config.brokerId)).toMap
    val topicConfig = java.util.Map.of(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "2")
    val limitHitsBefore = TestUtils.meterCount(FetchSessionPartitionLimitExceededPerSec)
    Using.resource(createAdminClient()) { admin =>
      Seq("small", "growth").foreach { topic =>
        TestUtils.createTopicWithAdmin(admin, topic, brokers, controllerServers,
          replicaAssignment = assignment, topicConfig = topicConfig)
      }
    }
    val partitions = Seq("small", "growth").flatMap(topic => assignment.keys.map(new TopicPartition(topic, _)))
    TestUtils.waitUntilTrue(() => TestUtils.meterCount(FetchSessionPartitionLimitExceededPerSec) > limitHitsBefore,
      "the follower's fetch session should have exceeded the configured limit")

    initProducer()
    produceData(partitions, numMessagesPerPartition = 1)
    TestUtils.waitUntilTrue(() => partitions.forall(tp => follower.replicaManager.localLog(tp).exists(_.logEndOffset == 1L)),
      "the follower should replicate every partition despite its fetch session exceeding the limit")
    partitions.foreach { tp =>
      assertEquals(Set(leaderId, follower.config.brokerId),
        brokers.head.replicaManager.onlinePartition(tp).get.inSyncReplicaIds, s"ISR of $tp should stay full")
    }
  }
}
