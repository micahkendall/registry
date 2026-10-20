# Cardano native token registry

This repository is a Plutarch implementation in progress for ordinary Cardano native assets. The intended registry is an ordered UTxO linked list whose nodes **pack several token content references**. A content reference stores the raw native-asset subject (`policyId || assetName`) and a Blake2b-256 hash of its canonical CIP-26 JSON. It may also store the content length and ordered segment hashes. A **hash-only lazy entry** stores zero length and an empty segment-hash list; it can be registered before anyone has the full JSON.

## Content and upload format

The planner canonicalizes the complete CIP-26 JSON as UTF-8 with sorted keys and compact separators, then splits it into segments of at most 12,000 bytes. The full `contentHash` is Blake2b-256 of the canonical JSON. Each segment hash is `blake2b_256(0x01 || segmentBytes)`. Anyone may later publish a **segment manifest** UTxO giving the length and ordered segment hashes for a hash-only entry, then publish each segment preimage as a separate UTxO in any order. A preimage is accepted by clients only when its subject, index, segment hash, and bytes match a manifest or the optional layout already in the node. Clients reconstruct all segments and check the original full content hash; a false manifest cannot complete an entry. CIP-26 properties such as `name` and `description` are supported when present; extension-only token entries are supported too. The supported file limit is 380,000 bytes, matching the reference server validator and covering the Cardano Foundation registry’s 370 KB submission guidance; its maximum needs 32 separate segments. No Merkle proof or one-transaction full-file verification is needed.

The JSON retains the CIP-26 `subject`, optional `name`, `description`, `policy`, `preimage`, `ticker`, `url`, `logo`, and `decimals`, plus arbitrary extension properties. Each property retains its JSON `value`, `sequenceNumber`, and optional annotated signatures. The special `preimage` object in CIP-26 is distinct from the registry's individually uploaded content segments. Clients check that optional claim by hashing its base16 `msg` with the declared algorithm and comparing the result with the subject. They check signatures separately before showing metadata as trusted.

`Registry.OnChain` defines three datum variants at a shared registry address: packed linked-list nodes, preimage items, and segment manifests. An output at that address with **no datum** is a treasury UTxO. It must contain only ADA when spent. The current packing bound is eight content references per node, each with at most 32 segment hashes. Nodes cover half-open subject ranges: the root starts at the empty byte string, and the final upper bound is 61 bytes of `ff`. A full node can be split at the first subject of the right node. A CBOR sizing test keeps a full 12,000-byte preimage datum below 13 KB. The official Cardano CLI built and signed an offline 12,000-byte preimage upload at 12,688 CBOR bytes. With sampled preprod parameters, its minimum output ADA was 54,685,280 lovelace. An offline balanced estimate for a synthetic maximum packed split with three key witnesses measured 14,792 bytes against a 16,384-byte transaction limit. The transaction emitted by the actual operation builder measured 14,755 bytes under the same assumptions; the two node outputs needed at least 22,058,580 and 27,467,630 lovelace. These estimates use fake UTxOs and supplied execution units, so they do not prove ledger acceptance or actual fees and execution budgets.

The CLI large-upload smoke check separately serialized and signed all 32 segment transactions for a 380,000-byte CIP-26 document. Its largest signed transaction was 12,657 bytes; the largest minimum output ADA under sampled preprod parameters was 54,551,670 lovelace. Each transaction used a distinct synthetic funding outref, so this verifies serialization and sizing of the individual uploads, not live submission or chain sequencing.

The maximum packed-split Plutarch test evaluates the registry spend, node NFT mint, and governance NFT spend against the same synthetic transaction context. Plutus Ledger API V3 evaluation with sampled preprod cost-model parameters measured a combined 937,183,842 steps and 2,531,920 memory units, compared with sampled per-transaction limits of 10,000,000,000 steps and 17,500,000 memory units. `registry_budget_check.py` extracts the V3 cost model from the supplied protocol parameters, reruns the three scripts, and checks their combined budget. CI uses the checked-in `tests/fixtures/preprod-v3-20261020.json` sample; live transaction evaluation is still required.

The actual treasury transaction builder also passed an offline Cardano CLI estimate with a full 12,000-byte preimage, a no-datum treasury spend, and a governance NFT spend. Its signed synthetic transaction was 13,143 bytes against the same 16,384-byte limit; the preimage output needed at least 54,547,360 lovelace. The supplied execution units are estimates, so the result does not prove ledger acceptance.

## Governance and ADA

The governance NFT is held by a Plutarch multisig script. Its rule interpreter supports aicone-style signer, all-of, any-of, threshold, before, after, and script-withdrawal branches. The interpreter offers transaction-signatory and annotated Ed25519 payload modes; governance spending currently uses transaction signatories, so authorization is bound to the transaction. A governed spend must return the NFT to the same multisig address; the old rule may authorize changing the continuing rule. The one-shot mint policy and governance validator both reject a rule with a path that could succeed using only time conditions or an empty threshold; every successful path must require a signer or script withdrawal.

`Registry.Validator` dispatches spends at the shared address. A list-node insert must spend the governance NFT, preserve the node NFT, and reconstruct the exact ordered list with one new subject. A governed update replaces exactly one subject's content commitment. A full-node split additionally requires a new node NFT named by its lower-bound hash. `Registry.Policies` creates the governance NFT and empty root node through one-shot seed UTxOs, and permits a later node NFT mint only for an exact governed split. Preimage and manifest spends are governed; publishing either is permissionless. Preimage bytes must match their segment hash. `Registry.Treasury` checks that a no-datum treasury input contains only ADA, that the governance NFT is spent from its multisig address, and that total ADA taken from registry-address inputs is at most ADA returned to that address plus transaction fees and Cardano treasury donation. This allows treasury ADA to become minimum ADA in new registry or preimage UTxOs, and lets the registry recover ADA into no-datum treasury UTxOs. It forbids net ADA leakage to external outputs under the aggregate accounting rule.

For an aicone-style `script` rule, register the authorizing Plutus V3 script as a stake credential and publish it as a reference script. A withdrawal spec JSON file names the exact script, its reference UTxO, and its redeemer: `{"scriptFile":"withdrawal.plutus","reference":"TXID#INDEX","redeemerFile":"withdrawal.redeemer.json"}`. Pass `--withdrawal-spec witness.json` to `registry_operation_tx.py`, `registry_governance_tx.py`, or `registry_treasury_tx.py`; repeat it when a threshold rule needs several script branches. The builders verify that each script hash appears in the **current** governance rule and add a zero-lovelace withdrawal witness at its CIP-19 reward address. The withdrawal script itself decides whether to authorize the transaction. See the [cardano-node reference-script withdrawal example](https://github.com/IntersectMBO/cardano-node/blob/master/scripts/babbage/staking-example/claim-script-staking-rewards.sh).

The generated zero-lovelace withdrawal flags were accepted by Cardano CLI 11.4.0.0 in an offline `build-estimate` transaction with a reference-script witness and supplied execution units. This checks transaction serialization only; the synthetic witness was not evaluated or submitted, and the stake credential must be registered before use on-chain.

The script dependency order is acyclic: compile the generic multisig validator, then its one-shot NFT policy, then the node NFT policy, then the registry validator. The governance datum names its NFT; the registry validator derives its own address from its spent input. The node policy's bootstrap branch cannot know the registry script address yet, so deployment must place the one-shot root NFT at the later compiled registry address. Bootstrap outputs must be checked before broadcasting.

`registry-export` emits parameterized Plutus V3 text envelopes. Its script bytes use Plutarch's serialized CBOR directly; the Haskell suite checks that the ledger API deserializes them. Use two distinct unspent seed references, one for each one-shot policy. Pass the **governance script hash**, not an address, to the policy and registry commands. After each export, `registry_script_hash.py` prints its 28-byte script hash; for a minting policy this is its policy ID. The hash covers the serialized CBOR script with the [Conway ledger's V3 language tag](https://github.com/IntersectMBO/cardano-ledger/blob/master/eras/conway/impl/cddl/data/conway.cddl).

The deployment preparer runs those four exports in order and writes a `manifest.json` to a new directory. It derives mainnet and testnet enterprise script addresses from the final script hashes, using [CIP-19](https://cips.cardano.org/cip/CIP-0019) encoding:

```sh
python3 tools/registry_deployment.py SEED1_TXID#INDEX SEED2_TXID#INDEX GOV_TOKEN_HEX deployment-output
```

It creates local artifacts only. Use real, distinct UTxOs that the bootstrap transactions will consume; send the root-node NFT to the exact `registryAddresses` entry for the chosen network and the governance NFT to the matching `governanceAddresses` entry. Check the governance datum and both bootstrap outputs against the manifest before minting. Both preview and preprod use the testnet address; their network magic still differs for CLI transactions.

`registry_data.py` writes Cardano CLI detailed-schema datum and redeemer files. The encoding was checked against Plutarch: content references and packed nodes are Plutus lists; registry datum variants are tagged constructors. A governance rule file uses one JSON key per rule, for example `{"atLeast":{"required":2,"rules":[{"signature":"<28-byte-key-hash-hex>"},{"signature":"<another-key-hash-hex>"}]}}`. Supported keys are `signature`, `allOf`, `anyOf`, `atLeast`, `before`, `after`, and `script`; time values are POSIX milliseconds.

```sh
python3 tools/registry_data.py governance deployment-output/manifest.json rule.json governance-data
python3 tools/registry_data.py root root-data
python3 tools/registry_data.py uploads upload-plan.json upload-data
python3 tools/registry_data.py operation list-plan.json commitment.json operation-data
```

Build the two one-shot mints as **separate** transactions after creating the governance and root datum files. The bootstrap builder verifies the minting script hash, destination address, NFT name, datum and redeemer against the deployment manifest. It rejects an initial governance rule that has an authorization path with no signer or script withdrawal. Use enough ADA to meet the real minimum UTxO requirement and sign each transaction with the owner of its seed input. Add `--extra-funding-utxo` if the seed alone cannot fund its output and fee.

```sh
python3 tools/registry_bootstrap_tx.py deployment-output/manifest.json deployment-output \
  governance-data governance COLLATERAL_TXID#INDEX PAYER_CHANGE_ADDRESS \
  10000000 governance-bootstrap.body --network testnet --testnet-magic 1 --build
python3 tools/registry_bootstrap_tx.py deployment-output/manifest.json deployment-output \
  root-data root COLLATERAL_TXID#INDEX PAYER_CHANGE_ADDRESS \
  10000000 root-bootstrap.body --network testnet --testnet-magic 1 --build
```

The segment manifest and each preimage datum are separate files, so each output can be funded in its own transaction. A hash-only commitment can be created without the JSON. Once the JSON is available, generate the full upload plan and compare it with that commitment before publishing. An insert or update emits old and successor node datums plus a spend redeemer. A split also emits the right node datum and node-policy mint redeemer.

```sh
python3 tools/registry_content.py --subject POLICY_ID_AND_ASSET_NAME_HEX \
  --content-hash BLAKE2B_256_HEX > commitment.json
python3 tools/registry_content.py metadata.json --expect-commitment commitment.json > upload-plan.json
python3 tools/registry_data.py uploads upload-plan.json upload-data
```

For a hash-only entry, publish the manifest after generating the upload files. It requires one payer-funded transaction and no governance spend. The individual segment uploads follow the same process as before.

```sh
python3 tools/registry_manifest_tx.py deployment-output/manifest.json upload-plan.json upload-data \
  FUNDING_TXID#INDEX PAYER_CHANGE_ADDRESS MANIFEST_MIN_ADA_LOVELACE manifest.body \
  --network testnet --testnet-magic 1 --build
```

For each preimage, `registry_tx.py` checks the selected datum against the upload plan and deployment manifest, then prints a `cardano-cli latest transaction build` command for one unsigned transaction body. Add `--build` to invoke the CLI. The funding UTxO and change address belong to the uploader; the output amount must cover the actual minimum UTxO requirement. Sign and submit each body with the payer's wallet before selecting the next funding UTxO. Publishing a preimage requires no governance spend.

To resume a partial upload, query the **complete** registry address and pass `next` as the segment index with `--registry-snapshot`. The command verifies that the current list commitment matches the upload plan, counts only preimage UTxOs with the exact expected bytes and hash, and chooses the first missing index. Query again after each confirmed transaction; when all segments exist, it stops with an `already published` message. This also works for hash-only entries before a manifest is published.

```sh
python3 tools/registry_tx.py deployment-output/manifest.json upload-plan.json upload-data \
  0 FUNDING_TXID#INDEX PAYER_CHANGE_ADDRESS SEGMENT_MIN_ADA_LOVELACE upload-000.body \
  --network testnet --testnet-magic 1 --build
cardano-cli conway query utxo --address REGISTRY_ADDRESS --testnet-magic 1 --output-json > registry-utxos.json
python3 tools/registry_tx.py deployment-output/manifest.json upload-plan.json upload-data \
  next FUNDING_TXID#INDEX PAYER_CHANGE_ADDRESS SEGMENT_MIN_ADA_LOVELACE upload-next.body \
  --network testnet --testnet-magic 1 --registry-snapshot registry-utxos.json --build
```

Before governed operations, publish the registry, governance, and node-policy scripts as separate **reference-script UTxOs**. The full-node split carries large packed-node datums and redeemers; including all three script bodies in that transaction could exceed the transaction-size limit. `registry_reference_tx.py` prepares one unsigned reference-script publication body per call. Keep these reference UTxOs unspent and record their confirmed outrefs.

```sh
python3 tools/registry_reference_tx.py deployment-output/manifest.json deployment-output registry \
  FUNDING_TXID#INDEX SCRIPT_HOLDER_ADDRESS PAYER_CHANGE_ADDRESS 10000000 registry-ref.body \
  --network testnet --testnet-magic 1 --build
```

For an insert, update, or split, query the complete registry and governance addresses, then generate a list plan from the registry snapshot. `registry_operation_tx.py` checks the old node, current governance NFT and rule datum, datum/redeemer files, exported script hashes, and ADA retained in successor nodes. It builds an unsigned body with both script spends via reference scripts, the payer input, collateral, the continuing NFTs, and a new node NFT for a split. Pass every key hash needed by the multisig rule with `--signer-hash`; pass slot bounds when the rule uses time predicates. A split needs `--right-lovelace` and `--node-policy-ref` as well. To fund the new node's minimum ADA from a no-datum treasury UTxO in the **same transaction**, pass `--treasury-utxo TXID#INDEX`. If some of that treasury input should remain as a no-datum UTxO, also pass `--treasury-change-lovelace AMOUNT`. The builder checks that the node outputs and treasury change retain at least all ADA from the spent registry node and treasury input; the payer funds fees. The CLI checks actual minimum ADA and transaction budgets when `--build` runs.

```sh
cardano-cli conway query utxo --address GOVERNANCE_ADDRESS --testnet-magic 1 --output-json > governance-utxos.json
python3 tools/registry_operation_tx.py deployment-output/manifest.json list-plan.json \
  commitment.json operation-data governance-data registry-utxos.json governance-utxos.json \
  deployment-output FUNDING_TXID#INDEX COLLATERAL_TXID#INDEX PAYER_CHANGE_ADDRESS \
  10000000 registry-operation.body --network testnet --testnet-magic 1 \
  --registry-script-ref REGISTRY_REF_TXID#INDEX \
  --governance-script-ref GOVERNANCE_REF_TXID#INDEX \
  --signer-hash SIGNER_KEY_HASH --build
```

To rotate governance, generate the new datum from a semantic multisig rule and query the current governance UTxO. The transaction spends the NFT under the **old** rule and returns it with the **new** inline rule at the same address, retaining its ADA. Supply signer hashes and validity bounds required by the old rule. The builder checks the current NFT UTxO, script hash, requested new datum, and that every successful path of the new rule requires a signer or script withdrawal.

```sh
python3 tools/registry_data.py governance deployment-output/manifest.json new-rule.json new-governance-data
cardano-cli conway query utxo --address GOVERNANCE_ADDRESS --testnet-magic 1 --output-json > governance-utxos.json
python3 tools/registry_governance_tx.py deployment-output/manifest.json governance-utxos.json \
  new-rule.json new-governance-data deployment-output FUNDING_TXID#INDEX \
  COLLATERAL_TXID#INDEX PAYER_CHANGE_ADDRESS governance-rotation.body \
  --governance-script-ref GOVERNANCE_REF_TXID#INDEX \
  --network testnet --testnet-magic 1 --signer-hash OLD_SIGNER_KEY_HASH --build
```

To spend treasury ADA on transaction fees, donate it to the Cardano treasury, or fund one metadata upload output, query both script addresses and select one or more **no-datum, ADA-only** UTxOs at the registry address. The builder spends the governance NFT under its current rule, returns that NFT with its existing datum and ADA, and directs all change to the registry address as a new no-datum treasury UTxO. It accepts no external funding input. Use external collateral and enough treasury ADA to leave a valid change output after fees, any donation, and any new metadata output. The CLI checks the actual fee and minimum ADA when building; inspect the resulting body before signing.

```sh
cardano-cli conway query utxo --address REGISTRY_ADDRESS --testnet-magic 1 --output-json > registry-utxos.json
cardano-cli conway query utxo --address GOVERNANCE_ADDRESS --testnet-magic 1 --output-json > governance-utxos.json
python3 tools/registry_treasury_tx.py deployment-output/manifest.json registry-utxos.json \
  governance-utxos.json governance-data deployment-output COLLATERAL_TXID#INDEX \
  treasury.body --treasury-utxo TREASURY_TXID#INDEX \
  --registry-script-ref REGISTRY_REF_TXID#INDEX \
  --governance-script-ref GOVERNANCE_REF_TXID#INDEX \
  --network testnet --testnet-magic 1 --donation-lovelace 2000000 \
  --signer-hash GOVERNANCE_SIGNER_KEY_HASH --build
```

To have the treasury pay the minimum ADA for one independently uploaded segment, use the same command with `--fund-upload-plan upload-plan.json --fund-upload-data-dir upload-data --fund-upload-index 0 --fund-upload-lovelace SEGMENT_MIN_ADA_LOVELACE` and omit the donation flag if no donation is intended. Omit `--fund-upload-index` to fund the segment manifest instead. The builder checks the selected datum against the upload plan. This path requires governance authorization; the payer-funded upload commands above remain permissionless. A 12 KB segment required 54,685,280 lovelace under the sampled preprod parameters, so select treasury inputs with enough ADA for that output and fees.

```sh
cabal run registry-export -- governance governance.plutus
python3 tools/registry_script_hash.py governance.plutus
cabal run registry-export -- governance-policy SEED1_TXID#INDEX GOV_TOKEN_HEX GOV_SCRIPT_HASH governance-policy.plutus
python3 tools/registry_script_hash.py governance-policy.plutus
cabal run registry-export -- node-policy SEED2_TXID#INDEX GOV_POLICY_ID GOV_TOKEN_HEX GOV_SCRIPT_HASH node-policy.plutus
python3 tools/registry_script_hash.py node-policy.plutus
cabal run registry-export -- registry GOV_POLICY_ID GOV_TOKEN_HEX GOV_SCRIPT_HASH NODE_POLICY_ID registry.plutus
python3 tools/registry_script_hash.py registry.plutus
```

## Planner and checks

```sh
python3 tools/registry_content.py entry.json --lazy   # full segment layout, no preimage bytes
python3 tools/registry_content.py --subject SUBJECT_HEX --content-hash FULL_HASH_HEX  # hash only
python3 tools/registry_content.py entry.json          # preimage upload plan
python3 tools/registry_content.py entry.json --expect-commitment lazy.json
python3 tools/registry_list.py commitment.json         # insert or split plan from empty root
python3 tools/registry_list.py commitment.json --state prior-plan.json
cardano-cli conway query utxo --address REGISTRY_ADDRESS --testnet-magic NETWORK_MAGIC --output-json > registry-utxos.json
python3 tools/registry_state.py registry-utxos.json REGISTRY_ADDRESS NODE_POLICY_ID > verified-state.json
python3 tools/registry_state.py registry-utxos.json REGISTRY_ADDRESS NODE_POLICY_ID \
  --include-metadata --trusted-keys trusted-keys.json > verified-with-attestations.json
python3 tools/registry_attestation.py entry.json trusted-keys.json
python3 tools/registry_list.py commitment.json --state verified-state.json
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -s tests -v
cabal test all
cardano-cli conway query protocol-parameters --testnet-magic 1 \
  --socket-path CARDANO_NODE_SOCKET --out-file protocol-params.json
python3 tools/registry_cli_smoke.py deployment-output/manifest.json --protocol-params protocol-params.json
python3 tools/registry_cli_smoke.py deployment-output/manifest.json --protocol-params protocol-params.json --large-upload
python3 tools/registry_split_size.py deployment-output/manifest.json protocol-params.json
python3 tools/registry_budget_check.py protocol-params.json
python3 tools/registry_treasury_size.py deployment-output/manifest.json protocol-params.json
```

Query the **complete** registry address, not a single node. The state reader verifies the root-to-tail NFT link chain and reports which independently published segments match each live content commitment. Its `complete` flag also checks the reconstructed JSON and full content hash. With `--trusted-keys`, it reports separate per-property `attestations` results and `preimageClaimValid` when the optional generic claim is present. The keys file can be a JSON array of globally trusted public keys or an object mapping each native-token subject to its own array of trusted keys, for example `{"<subject-hex>":["<public-key-hex>"]}`. For an entry without `policy`, each property needs one valid Ed25519 signature from the keys trusted for that subject. With a native `policy`, the client verifies its policy ID against the subject and evaluates the native script using each property's valid signers; time locks are considered satisfiable as CIP-26 requires. The standalone attestation command exits unsuccessfully when a property lacks authorization or a present preimage claim fails. Extension values may contain JSON floats: the client checks RFC 8949 preferred-width CBOR signatures and exact-value float64 encodings. Install the Python crypto dependencies with `python3 -m pip install -r requirements.txt`; PyCryptodome supplies Keccak, which differs from SHA-3; Pillow decodes PNG logos to reject malformed image data. Neither the on-chain content hash nor a `complete` result establishes the metadata author's identity. It ignores unrelated outputs at the shared address and records their outrefs. The list planner carries the verified old-node outref into its action; re-query before building a transaction because another insert or update can spend that node first. For mainnet, replace `--testnet-magic NETWORK_MAGIC` with `--mainnet`.

The content planner produces upload data and the list planner computes successor nodes; the state reader parses a supplied `cardano-cli` snapshot but does not contact a node itself. The exporter creates complete scripts and the data generator creates matching datum/redeemer files. The unsigned transaction builders cover bootstrap mints, permissionless manifests and individual segment uploads, governed insert, update, and split with optional treasury funding, governance rule rotation, and treasury-funded uploads, fees or donation. Governed transaction builders accept registered Plutus V3 script-withdrawal witnesses through `--withdrawal-spec`; live node validation of that path is still required. The client verifies trusted CIP-26 property signatures, native-policy signer authorization, and optional generic hash-preimage claims, including the reference implementation's byte encoding for PNG logos. Tests cover predicate evaluation, ledger deserialization, V3 cost-model evaluation of a maximum-sized packed split, treasury conservation, governed insertion, independent segment spending, snapshot-to-plan reconstruction, command generation, a published CIP-26 signature, a published native-policy ID, and Keccak claim verification. The optional CLI smoke check compares all four exported script hashes and four addresses with the official CLI, signs one synthetic preimage upload by default, and can sign all 32 segments of a 380,000-byte entry. The split-size check uses `build-estimate` and supplied protocol parameters to balance the largest packed split with three key witnesses, check the actual operation builder command, and calculate minimum ADA for its outputs. Its UTxOs and execution units are synthetic. Live transaction builds, signing/submission, on-chain execution budgets, and live-chain integration tests are not yet verified. This checkout is **not deployable**.

## Sources

- [CIP-26](https://cips.cardano.org/cip/CIP-0026)
- [Cardano Foundation token registry](https://github.com/cardano-foundation/cardano-token-registry)
- [Reference registry's 380,000-byte file limit](https://github.com/input-output-hk/offchain-metadata-tools/blob/master/metadata-lib/src/Cardano/Metadata/Validation/Rules.hs)
- [aicone multisig rules](https://github.com/SundaeSwap-finance/aicone/blob/main/lib/sundae/multisig.ak)
