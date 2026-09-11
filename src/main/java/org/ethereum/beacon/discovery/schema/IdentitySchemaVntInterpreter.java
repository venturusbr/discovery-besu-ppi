/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import static org.ethereum.beacon.discovery.schema.NodeRecordBuilder.addCustomField;
import static org.ethereum.beacon.discovery.schema.NodeRecordFields.ADDRESS_IP_V4_FIELD_NAMES;
import static org.ethereum.beacon.discovery.schema.NodeRecordFields.ADDRESS_IP_V6_FIELD_NAMES;
import static org.ethereum.beacon.discovery.schema.NodeRecordFields.addressFromFields;
import static org.ethereum.beacon.discovery.schema.NodeRecordFields.getAllFieldsThatMatch;

import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.util.Functions;

/**
 * Interpreter for the {@code vnt} identity scheme: a node record carrying a hybrid secp256k1 +
 * ML-DSA-44 key pair, signed with a hybrid signature.
 *
 * <p>The scheme mirrors {@code v4} except that the {@link EnrField#PKEY_SECP256K1} field is
 * replaced by {@link EnrField#PKEY_SECP256K1_MLDSA44}, which holds both the classical and the
 * post-quantum public key.
 *
 * <p>This class deliberately owns none of the hybrid cryptography. Signing is delegated to the
 * {@link Signer} supplied by the caller (Besu), and signature verification is left to the caller as
 * well - see {@link #isValid(NodeRecord)}.
 */
public class IdentitySchemaVntInterpreter implements IdentitySchemaInterpreter {

  private static final Logger LOG = LogManager.getLogger();

  /**
   * A {@code vnt} record does not fit in the 300 bytes allowed by EIP-778: the ML-DSA-44 public key
   * alone is 1312 bytes and its signature 2420 bytes, so a minimal record is already around 3.9kB.
   * The limit below leaves room for the classical key material, the transport fields and any
   * encoding overhead of the hybrid key format.
   */
  public static final int MAX_ENCODED_SIZE = 7500;

  /**
   * Layout of the hybrid public key: the uncompressed secp256k1 key followed by the ML-DSA-44 key.
   * Matches Besu's {@code CompositePublicKey}, which concatenates the encoding of each key.
   */
  private static final int SECP256K1_UNCOMPRESSED_SIZE = 64;

  private static final int MLDSA44_PUBKEY_SIZE = 1312;

  public static final int HYBRID_PUBKEY_SIZE = SECP256K1_UNCOMPRESSED_SIZE + MLDSA44_PUBKEY_SIZE;

  private final LoadingCache<Bytes, Bytes> nodeIdCache =
      CacheBuilder.newBuilder()
          .maximumSize(4000)
          .build(CacheLoader.from(IdentitySchemaVntInterpreter::calculateNodeIdImpl));

  @Override
  public IdentitySchema getScheme() {
    return IdentitySchema.VNT;
  }

  @Override
  public int getMaxEncodedSize() {
    return MAX_ENCODED_SIZE;
  }

  /**
   * Checks the record is structurally a {@code vnt} record.
   *
   * <p>Unlike {@link IdentitySchemaV4Interpreter#isValid(NodeRecord)} this does <b>not</b> verify
   * the signature: hybrid verification lives in Besu, which owns the ML-DSA-44 implementation.
   * Callers that receive records from the network must verify the signature themselves.
   */
  @Override
  public boolean isValid(final NodeRecord nodeRecord) {
    if (!IdentitySchemaInterpreter.super.isValid(nodeRecord)) {
      return false;
    }
    if (nodeRecord.get(EnrField.PKEY_SECP256K1_MLDSA44) == null) {
      LOG.trace(
          "Field {} does not exist but required for scheme {}",
          EnrField.PKEY_SECP256K1_MLDSA44,
          getScheme());
      return false;
    }
    return true;
  }

  @Override
  public Bytes getNodeId(final NodeRecord nodeRecord) {
    final Bytes pkey = (Bytes) nodeRecord.get(EnrField.PKEY_SECP256K1_MLDSA44);
    Preconditions.checkNotNull(pkey, "Missing PKEY_SECP256K1_MLDSA44 field");
    return nodeIdCache.getUnchecked(pkey);
  }

  /**
   * Extracts the classical half of the hybrid key and returns it compressed, which is the form the
   * handshake's ID signature verification expects.
   */
  @Override
  public Bytes getSecp256k1PublicKey(final NodeRecord nodeRecord) {
    final Bytes hybridKey = (Bytes) nodeRecord.get(EnrField.PKEY_SECP256K1_MLDSA44);
    Preconditions.checkNotNull(hybridKey, "Missing PKEY_SECP256K1_MLDSA44 field");
    Preconditions.checkArgument(
        hybridKey.size() == HYBRID_PUBKEY_SIZE,
        "Hybrid public key of size %s does not match the expected layout of %s bytes",
        hybridKey.size(),
        HYBRID_PUBKEY_SIZE);
    final Bytes classicalKey = hybridKey.slice(0, SECP256K1_UNCOMPRESSED_SIZE);
    return Bytes.wrap(Functions.publicKeyToPoint(classicalKey).getEncoded(true));
  }

  @Override
  public Bytes calculateNodeId(final Bytes publicKey) {
    return nodeIdCache.getUnchecked(publicKey);
  }

  /** The node id is the keccak256 hash of the whole hybrid public key, as stored in the record. */
  private static Bytes calculateNodeIdImpl(final Bytes publicKey) {
    return Functions.hashKeccak(publicKey);
  }

  /**
   * Signs the record with the caller supplied {@link Signer}.
   *
   * <p>The scheme only defines <i>what</i> is signed - the keccak256 hash of the signature-less RLP
   * encoding, exactly as in {@code v4}. <i>How</i> it is signed is entirely up to the {@link
   * Signer} implementation, which for this scheme is expected to produce a hybrid secp256k1 +
   * ML-DSA-44 signature.
   */
  @Override
  public void sign(final NodeRecord nodeRecord, final Signer signer) {
    final Bytes signature = signer.sign(Functions.hashKeccak(nodeRecord.serializeNoSignature()));
    nodeRecord.setSignature(signature);
  }

  @Override
  public Optional<InetSocketAddress> getUdpAddress(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V4, EnrField.UDP);
  }

  @Override
  public Optional<InetSocketAddress> getUdp6Address(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.UDP_V6)
        .or(() -> addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.UDP));
  }

  @Override
  public Optional<InetSocketAddress> getTcpAddress(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V4, EnrField.TCP);
  }

  @Override
  public Optional<InetSocketAddress> getTcp6Address(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.TCP_V6)
        .or(() -> addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.TCP));
  }

  @Override
  public Optional<InetSocketAddress> getQuicAddress(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V4, EnrField.QUIC);
  }

  @Override
  public Optional<InetSocketAddress> getQuic6Address(final NodeRecord nodeRecord) {
    return addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.QUIC_V6)
        .or(() -> addressFromFields(nodeRecord, EnrField.IP_V6, EnrField.QUIC));
  }

  @Override
  public NodeRecord createWithNewAddress(
      final NodeRecord nodeRecord,
      final InetSocketAddress newAddress,
      final Optional<Integer> newTcpPort,
      final Optional<Integer> newQuicPort,
      final Signer signer) {
    final List<EnrField> fields =
        getAllFieldsThatMatch(
            nodeRecord,
            field -> {
              // don't match the address fields that we are going to change
              final Set<String> addressFieldsToChange =
                  newAddress.getAddress() instanceof Inet6Address
                      ? ADDRESS_IP_V6_FIELD_NAMES
                      : ADDRESS_IP_V4_FIELD_NAMES;
              return !addressFieldsToChange.contains(field.getName());
            });
    NodeRecordBuilder.addFieldsForAddress(
        fields, newAddress.getAddress(), newAddress.getPort(), newTcpPort, newQuicPort);
    final NodeRecord newRecord = NodeRecord.fromValues(this, nodeRecord.getSeq().add(1), fields);
    sign(newRecord, signer);
    return newRecord;
  }

  @Override
  public NodeRecord createWithUpdatedCustomField(
      final NodeRecord nodeRecord, final String fieldName, final Bytes value, final Signer signer) {
    final List<EnrField> fields =
        getAllFieldsThatMatch(nodeRecord, field -> !field.getName().equals(fieldName));
    addCustomField(fields, fieldName, value);
    final NodeRecord newRecord = NodeRecord.fromValues(this, nodeRecord.getSeq().add(1), fields);
    sign(newRecord, signer);
    return newRecord;
  }
}
