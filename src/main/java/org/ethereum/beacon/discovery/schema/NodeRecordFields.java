/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import com.google.common.collect.ImmutableSet;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

/**
 * Field accessors shared by {@link IdentitySchemaInterpreter} implementations.
 *
 * <p>These helpers only read the transport related fields of a record, which are defined by <a
 * href="https://eips.ethereum.org/EIPS/eip-778">EIP-778</a> itself rather than by an identity
 * scheme, so every scheme interprets them the same way.
 */
final class NodeRecordFields {

  private static final Logger LOG = LogManager.getLogger();

  static final ImmutableSet<String> ADDRESS_IP_V4_FIELD_NAMES =
      ImmutableSet.of(EnrField.IP_V4, EnrField.UDP);

  static final ImmutableSet<String> ADDRESS_IP_V6_FIELD_NAMES =
      ImmutableSet.of(EnrField.IP_V6, EnrField.UDP_V6);

  private NodeRecordFields() {}

  static Optional<InetSocketAddress> addressFromFields(
      final NodeRecord nodeRecord, final String ipField, final String portField) {
    if (!nodeRecord.containsKey(ipField) || !nodeRecord.containsKey(portField)) {
      return Optional.empty();
    }
    final Bytes ipBytes = (Bytes) nodeRecord.get(ipField);
    final int port = (int) nodeRecord.get(portField);
    try {
      return Optional.of(new InetSocketAddress(getInetAddress(ipBytes), port));
    } catch (final UnknownHostException e) {
      LOG.trace("Unable to resolve host: {}", ipBytes);
      return Optional.empty();
    }
  }

  static InetAddress getInetAddress(final Bytes address) throws UnknownHostException {
    return InetAddress.getByAddress(address.toArrayUnsafe());
  }

  static Stream<EnrField> streamAllFields(final NodeRecord nodeRecord) {
    final List<EnrField> fields = new ArrayList<>();
    nodeRecord.forEachField((name, value) -> fields.add(new EnrField(name, value)));
    return fields.stream();
  }

  static List<EnrField> getAllFieldsThatMatch(
      final NodeRecord nodeRecord, final Predicate<? super EnrField> predicate) {
    return streamAllFields(nodeRecord).filter(predicate).collect(Collectors.toList());
  }
}
