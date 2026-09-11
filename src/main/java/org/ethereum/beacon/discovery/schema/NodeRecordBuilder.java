/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ethereum.beacon.discovery.schema;

import static com.google.common.base.Preconditions.checkArgument;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.crypto.Signer;

public class NodeRecordBuilder {

  private final List<EnrField> fields = new ArrayList<>();
  private NodeRecordFactory nodeRecordFactory = NodeRecordFactory.DEFAULT;
  private Optional<Signer> signer = Optional.empty();
  private UInt64 seq = UInt64.ONE;
  private IdentitySchema identitySchema = IdentitySchema.V4;

  public NodeRecordBuilder nodeRecordFactory(final NodeRecordFactory nodeRecordFactory) {
    this.nodeRecordFactory = nodeRecordFactory;
    return this;
  }

  public NodeRecordBuilder seq(final UInt64 seq) {
    this.seq = seq;
    return this;
  }

  public NodeRecordBuilder seq(final int seq) {
    return seq(UInt64.valueOf(seq));
  }

  public NodeRecordBuilder identitySchema(final IdentitySchema identitySchema) {
    this.identitySchema = identitySchema;
    return this;
  }

  /** Sets the compressed secp256k1 public key of a {@code v4} record. */
  public NodeRecordBuilder publicKey(final Bytes publicKey) {
    fields.add(new EnrField(EnrField.PKEY_SECP256K1, publicKey));
    return this;
  }

  /**
   * Sets the hybrid secp256k1 + ML-DSA-44 public key and switches the record to the {@code vnt}
   * identity scheme.
   */
  public NodeRecordBuilder hybridPublicKey(final Bytes publicKey) {
    identitySchema(IdentitySchema.VNT);
    fields.add(new EnrField(EnrField.PKEY_SECP256K1_MLDSA44, publicKey));
    return this;
  }

  public NodeRecordBuilder signer(final Signer signer) {
    this.signer = Optional.of(signer);
    return this;
  }

  public NodeRecordBuilder address(final String ipAddress, final int port) {
    return address(ipAddress, port, port);
  }

  public NodeRecordBuilder address(final String ipAddress, final int udpPort, final int tcpPort) {
    return address(ipAddress, udpPort, tcpPort, Optional.empty());
  }

  public NodeRecordBuilder address(
      final String ipAddress, final int udpPort, final int tcpPort, final int quicPort) {
    return address(ipAddress, udpPort, tcpPort, Optional.of(quicPort));
  }

  public NodeRecordBuilder address(
      final String ipAddress,
      final int udpPort,
      final int tcpPort,
      final Optional<Integer> quicPort) {
    try {
      final InetAddress inetAddress = InetAddress.getByName(ipAddress);
      addFieldsForAddress(fields, inetAddress, udpPort, Optional.of(tcpPort), quicPort);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Unable to resolve address: " + ipAddress);
    }
    return this;
  }

  public NodeRecordBuilder customField(final String fieldName, final Bytes value) {
    fields.add(new EnrField(fieldName, value));
    return this;
  }

  static void addFieldsForAddress(
      final List<EnrField> fields,
      final InetAddress inetAddress,
      final int udpPort,
      final Optional<Integer> newTcpPort,
      final Optional<Integer> newQuicPort) {
    final Bytes address = Bytes.wrap(inetAddress.getAddress());
    final boolean isIpV6 = inetAddress instanceof Inet6Address;
    fields.add(new EnrField(isIpV6 ? EnrField.IP_V6 : EnrField.IP_V4, address));
    fields.add(new EnrField(isIpV6 ? EnrField.UDP_V6 : EnrField.UDP, udpPort));
    newTcpPort.ifPresent(
        tcpPort -> fields.add(new EnrField(isIpV6 ? EnrField.TCP_V6 : EnrField.TCP, tcpPort)));
    newQuicPort.ifPresent(
        quicPort -> fields.add(new EnrField(isIpV6 ? EnrField.QUIC_V6 : EnrField.QUIC, quicPort)));
  }

  static void addCustomField(
      final List<EnrField> fields, final String fieldName, final Bytes value) {
    fields.add(new EnrField(fieldName, value));
  }

  public NodeRecord build() {
    // the public key is derived from the signer unless it was supplied explicitly, which the vnt
    // scheme needs since a hybrid key cannot be derived from the classic secret key alone
    signer
        .filter(unused -> !hasPublicKeyField())
        .ifPresent(
            s ->
                fields.add(
                    new EnrField(publicKeyFieldName(), s.deriveCompressedPublicKeyFromPrivate())));
    fields.add(new EnrField(EnrField.ID, identitySchema));
    final NodeRecord nodeRecord = nodeRecordFactory.createFromValues(seq, fields);
    signer.ifPresent(nodeRecord::sign);
    checkArgument(
        nodeRecord.isValid(),
        "Generated node record was not valid. Ensure all required fields were supplied");
    return nodeRecord;
  }

  private String publicKeyFieldName() {
    return identitySchema == IdentitySchema.VNT
        ? EnrField.PKEY_SECP256K1_MLDSA44
        : EnrField.PKEY_SECP256K1;
  }

  private boolean hasPublicKeyField() {
    final String fieldName = publicKeyFieldName();
    return fields.stream().anyMatch(field -> field.getName().equals(fieldName));
  }
}
