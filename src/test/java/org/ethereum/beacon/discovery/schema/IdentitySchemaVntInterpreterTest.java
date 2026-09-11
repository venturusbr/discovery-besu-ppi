/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Test;

class IdentitySchemaVntInterpreterTest {

  private static final Bytes COMPRESSED_SECP256K1_PUB_KEY =
      Bytes.fromHexString("0x02197B9014C6C0500CF168BD1F17A3B4A1307251849A5ECEEE0B5EBC76A7EBDB37");

  /**
   * Besu's {@code CompositePublicKey} layout: the uncompressed secp256k1 key (64 bytes) followed by
   * the ML-DSA-44 public key (1312 bytes).
   */
  private static final Bytes HYBRID_PUB_KEY =
      Bytes.concatenate(uncompressed(COMPRESSED_SECP256K1_PUB_KEY), repeat((byte) 0x2a, 1312));

  /** secp256k1 signature (64 bytes) concatenated with an ML-DSA-44 signature (2420 bytes). */
  private static final Bytes HYBRID_SIGNATURE = repeat((byte) 0x7b, 64 + 2420);

  private final IdentitySchemaVntInterpreter interpreter = new IdentitySchemaVntInterpreter();
  private final NodeRecordFactory factory = NodeRecordFactory.DEFAULT;
  private final RecordingSigner signer = new RecordingSigner();

  @Test
  public void shouldDeriveNodeIdFromTheWholeHybridKey() {
    final NodeRecord record = buildRecord();

    assertThat(record.getNodeId()).isEqualTo(Functions.hashKeccak(HYBRID_PUB_KEY));
    assertThat(interpreter.calculateNodeId(HYBRID_PUB_KEY)).isEqualTo(record.getNodeId());
  }

  @Test
  public void shouldSignHashOfSignatureLessEncodingWithSuppliedSigner() {
    final NodeRecord record = buildRecord();

    assertThat(record.getSignature()).isEqualTo(HYBRID_SIGNATURE);
    assertThat(signer.lastMessageHash)
        .isEqualTo(Functions.hashKeccak(record.serializeNoSignature()));
  }

  @Test
  public void shouldRoundTripRecordThroughEnrEncoding() {
    final NodeRecord record = buildRecord();

    final NodeRecord decoded = factory.fromEnr(record.asEnr());

    assertThat(decoded).isEqualTo(record);
    assertThat(decoded.getIdentityScheme()).isEqualTo(IdentitySchema.VNT);
    assertThat(decoded.get(EnrField.PKEY_SECP256K1_MLDSA44)).isEqualTo(HYBRID_PUB_KEY);
    assertThat(decoded.getNodeId()).isEqualTo(record.getNodeId());
    assertThat(decoded.getUdpAddress()).contains(new InetSocketAddress("127.0.0.1", 30303));
    assertThat(decoded.getTcpAddress()).contains(new InetSocketAddress("127.0.0.1", 30304));
  }

  @Test
  public void shouldRejectRecordWithoutHybridKey() {
    final NodeRecord record =
        NodeRecord.fromValues(
            interpreter, UInt64.ONE, List.of(new EnrField(EnrField.ID, IdentitySchema.VNT)));

    assertThat(record.isValid()).isFalse();
  }

  @Test
  public void shouldAllowRecordsLargerThanTheEip778Limit() {
    final NodeRecord record = buildRecord();

    assertThat(record.serialize().size()).isGreaterThan(NodeRecord.MAX_ENCODED_SIZE);
    assertThat(record.serialize().size()).isLessThanOrEqualTo(interpreter.getMaxEncodedSize());
  }

  @Test
  public void shouldStillEnforceTheEip778LimitForV4Records() {
    assertThatThrownBy(
            () ->
                new NodeRecordBuilder()
                    .publicKey(Bytes.fromHexString("0x" + "02".repeat(33)))
                    .customField("oversized", repeat((byte) 0x01, 400))
                    .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exceeds maximum encoded size");
  }

  @Test
  public void shouldReSignWhenAddressChanges() {
    final NodeRecord record = buildRecord();

    // mirrors DiscoverySystemBuilder, which carries the existing tcp/quic ports over
    final NodeRecord updated =
        record.withNewAddress(
            new InetSocketAddress("127.0.0.2", 30305),
            record.getTcpAddress().map(InetSocketAddress::getPort),
            Optional.empty(),
            signer);

    assertThat(updated.getSeq()).isEqualTo(record.getSeq().add(1));
    assertThat(updated.getUdpAddress()).contains(new InetSocketAddress("127.0.0.2", 30305));
    assertThat(updated.getTcpAddress()).contains(new InetSocketAddress("127.0.0.2", 30304));
    assertThat(updated.getNodeId()).isEqualTo(record.getNodeId());
    assertThat(signer.lastMessageHash)
        .isEqualTo(Functions.hashKeccak(updated.serializeNoSignature()));
  }

  @Test
  public void shouldReSignWhenCustomFieldChanges() {
    final NodeRecord record = buildRecord();

    final NodeRecord updated = record.withUpdatedCustomField("eth2", Bytes.of(1, 2, 3), signer);

    assertThat(updated.getSeq()).isEqualTo(record.getSeq().add(1));
    assertThat(updated.get("eth2")).isEqualTo(Bytes.of(1, 2, 3));
    assertThat(updated.isValid()).isTrue();
  }

  @Test
  public void shouldExtractCompressedSecp256k1KeyForTheHandshake() {
    final NodeRecord record = buildRecord();

    assertThat(record.getSecp256k1PublicKey()).isEqualTo(COMPRESSED_SECP256K1_PUB_KEY);
  }

  @Test
  public void shouldRejectHybridKeyThatDoesNotMatchTheExpectedLayout() {
    final NodeRecord record =
        NodeRecord.fromValues(
            interpreter,
            UInt64.ONE,
            List.of(
                new EnrField(EnrField.ID, IdentitySchema.VNT),
                new EnrField(EnrField.PKEY_SECP256K1_MLDSA44, repeat((byte) 0x2a, 100))));

    assertThatThrownBy(record::getSecp256k1PublicKey)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not match the expected layout");
  }

  private NodeRecord buildRecord() {
    return new NodeRecordBuilder()
        .nodeRecordFactory(factory)
        .hybridPublicKey(HYBRID_PUB_KEY)
        .signer(signer)
        .address("127.0.0.1", 30303, 30304)
        .build();
  }

  /** The 64 byte x||y form, which is what Besu's {@code SECPPublicKey.getEncoded()} returns. */
  private static Bytes uncompressed(final Bytes compressedKey) {
    return Bytes.wrap(Functions.publicKeyToPoint(compressedKey).getEncoded(false)).slice(1);
  }

  private static Bytes repeat(final byte value, final int length) {
    final byte[] bytes = new byte[length];
    Arrays.fill(bytes, value);
    return Bytes.wrap(bytes);
  }

  /** Stands in for the hybrid signer that Besu supplies. */
  private static class RecordingSigner implements Signer {
    private Bytes32 lastMessageHash;

    @Override
    public Bytes sign(final Bytes32 messageHash) {
      this.lastMessageHash = messageHash;
      return HYBRID_SIGNATURE;
    }

    @Override
    public Bytes deriveECDHKeyAgreement(final Bytes destPubKey) {
      throw new UnsupportedOperationException("Not used by the vnt scheme tests");
    }

    @Override
    public Bytes deriveCompressedPublicKeyFromPrivate() {
      return HYBRID_PUB_KEY;
    }
  }
}
