/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import java.net.InetSocketAddress;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.crypto.Signer;

/**
 * Interprets identity schema of ethereum node record:
 *
 * <ul>
 *   <li>derives node id from node record
 *   <li>>signs node record
 *   <li>verifies signature of node record
 * </ul>
 */
public interface IdentitySchemaInterpreter {

  IdentitySchemaInterpreter V4 = new IdentitySchemaV4Interpreter();
  IdentitySchemaInterpreter VNT = new IdentitySchemaVntInterpreter();

  /** Returns supported scheme */
  IdentitySchema getScheme();

  /**
   * Maximum size, in bytes, of the RLP encoding of a record of this scheme. Records larger than
   * this are rejected.
   *
   * <p>Defaults to the {@link NodeRecord#MAX_ENCODED_SIZE} limit mandated by EIP-778. Schemes based
   * on post-quantum keys carry far more key and signature material and override this.
   */
  default int getMaxEncodedSize() {
    return NodeRecord.MAX_ENCODED_SIZE;
  }

  /* Signs nodeRecord, modifying it */
  void sign(NodeRecord nodeRecord, Signer signer);

  /** Verifies that `nodeRecord` is of scheme implementation */
  default boolean isValid(NodeRecord nodeRecord) {
    return nodeRecord.getIdentityScheme().equals(getScheme());
  }

  /** Delivers nodeId according to identity scheme scheme */
  Bytes getNodeId(NodeRecord nodeRecord);

  /**
   * The compressed secp256k1 public key of the record.
   *
   * <p>The discv5 handshake is classical regardless of the identity scheme: it needs this key for
   * the ECDH key agreement and to verify the ID signature. Schemes that keep the classical key
   * inside a hybrid key override this to extract it.
   */
  default Bytes getSecp256k1PublicKey(NodeRecord nodeRecord) {
    return (Bytes) nodeRecord.get(EnrField.PKEY_SECP256K1);
  }

  Optional<InetSocketAddress> getUdpAddress(NodeRecord nodeRecord);

  Optional<InetSocketAddress> getUdp6Address(NodeRecord nodeRecord);

  Optional<InetSocketAddress> getTcpAddress(NodeRecord nodeRecord);

  Optional<InetSocketAddress> getTcp6Address(NodeRecord nodeRecord);

  Optional<InetSocketAddress> getQuicAddress(NodeRecord nodeRecord);

  Optional<InetSocketAddress> getQuic6Address(NodeRecord nodeRecord);

  NodeRecord createWithNewAddress(
      NodeRecord nodeRecord,
      InetSocketAddress newAddress,
      Optional<Integer> newTcpPort,
      Optional<Integer> newQuicPort,
      Signer signer);

  NodeRecord createWithUpdatedCustomField(
      NodeRecord nodeRecord, String newAddress, Bytes value, Signer signer);

  Bytes calculateNodeId(Bytes publicKey);
}
