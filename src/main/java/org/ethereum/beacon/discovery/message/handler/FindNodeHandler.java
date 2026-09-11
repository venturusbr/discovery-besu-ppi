/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.message.handler;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ethereum.beacon.discovery.message.FindNodeMessage;
import org.ethereum.beacon.discovery.message.NodesMessage;
import org.ethereum.beacon.discovery.pipeline.handler.IncomingDataPacker;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeSession;

public class FindNodeHandler implements MessageHandler<FindNodeMessage> {
  private static final Logger LOG = LogManager.getLogger(FindNodeHandler.class);

  /**
   * NODES responses are split across several messages to stay below the packet size limit, and the
   * total number of messages is reported in each one.
   *
   * <p>Records cannot be assumed to be the 300 bytes allowed by EIP-778: a record of the hybrid
   * {@code vnt} scheme is over ten times that. Batches are therefore bounded both by this count and
   * by the actual serialized size of the records.
   */
  private static final int MAX_NODES_PER_MESSAGE = 4;

  /** Bytes reserved within a packet for the header, message framing and encryption overhead. */
  private static final int PACKET_OVERHEAD = 80;

  /**
   * Implementations should limit the number of nodes in the result set. The recommended result
   * limit for FINDNODE queries is 16 nodes.
   */
  private static final int MAX_TOTAL_NODES_PER_RESPONSE = 16;

  public FindNodeHandler() {}

  @Override
  public void handle(FindNodeMessage message, NodeSession session) {
    List<NodeRecord> nodeRecordInfos =
        message.getDistances().stream()
            .distinct()
            .flatMap(session::getNodeRecordsInBucket)
            .limit(MAX_TOTAL_NODES_PER_RESPONSE)
            .collect(Collectors.toList());

    List<List<NodeRecord>> nodeRecordBatches = batchToFitPackets(nodeRecordInfos);

    LOG.trace(
        () ->
            String.format(
                "Sending %s nodes in reply to request with distances %s in session %s",
                nodeRecordInfos.size(), message.getDistances(), session));

    List<List<NodeRecord>> nonEmptyNodeRecordsList =
        nodeRecordBatches.isEmpty() ? singletonList(emptyList()) : nodeRecordBatches;

    nonEmptyNodeRecordsList.forEach(
        recordsList ->
            session.sendOutgoingOrdinary(
                new NodesMessage(
                    message.getRequestId(), nonEmptyNodeRecordsList.size(), recordsList)));
  }

  private static List<List<NodeRecord>> batchToFitPackets(final List<NodeRecord> nodeRecords) {
    final int budget = IncomingDataPacker.MAX_PACKET_SIZE - PACKET_OVERHEAD;
    final List<List<NodeRecord>> batches = new ArrayList<>();
    List<NodeRecord> batch = new ArrayList<>();
    int batchSize = 0;
    for (final NodeRecord nodeRecord : nodeRecords) {
      final int recordSize = nodeRecord.serialize().size();
      final boolean batchIsFull =
          batch.size() >= MAX_NODES_PER_MESSAGE || batchSize + recordSize > budget;
      if (!batch.isEmpty() && batchIsFull) {
        batches.add(batch);
        batch = new ArrayList<>();
        batchSize = 0;
      }
      batch.add(nodeRecord);
      batchSize += recordSize;
    }
    if (!batch.isEmpty()) {
      batches.add(batch);
    }
    return batches;
  }
}
