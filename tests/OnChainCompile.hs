{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import Data.ByteString qualified as BS
import Data.ByteString.Short qualified as SBS
import Control.Monad.Except (runExceptT)
import Control.Monad.Writer.Strict (runWriter)
import Numeric (readHex)
import Plutarch.Builtin.Crypto (pblake2b_256)
import Plutarch.Evaluate (evalTerm)
import Plutarch.Internal.Term (Config (NoTracing), compile)
import Plutarch.LedgerApi.AssocMap qualified as AssocMap
import Plutarch.LedgerApi.Interval qualified as Interval
import Plutarch.LedgerApi.V3
import Plutarch.LedgerApi.Value qualified as LedgerValue
import Plutarch.Prelude
import Plutarch.Script (serialiseScript)
import PlutusLedgerApi.V3 qualified as V3
import Registry.Governance (PGovernanceDatum (..), PMultisig (..), psafeRule, psatisfied, psatisfiedPayload, pvalidateGovernanceSpend)
import Registry.Treasury (pgovernedAdaConservation, pvalidateTreasurySpend)
import Registry.Validator (PRegistryAction (..), pvalidateRegistrySpend)
import Registry.Policies (PNodeMintAction (..), pvalidateGovernanceMint, pvalidateNodeMint)
import Registry.OnChain (PContentRef (..), PPackedNode (..), PPreimage (..), PRegistryDatum (..), psegmentHash, pvalidManifest, pvalidPackedInsert, pvalidPackedSplit, pvalidPackedUpdate, pvalidPreimage)
import System.Environment (lookupEnv)

main :: IO ()
main = do
  check "segment hash" (compile NoTracing psegmentHash)
  check "independent preimage" (compile NoTracing pvalidPreimage)
  check "independent segment manifest" (compile NoTracing pvalidManifest)
  check "packed list insertion" (compile NoTracing pvalidPackedInsert)
  check "packed list split" (compile NoTracing pvalidPackedSplit)
  check "packed list update" (compile NoTracing pvalidPackedUpdate)
  check "multisig interpreter" (compile NoTracing psatisfied)
  check "multisig payload interpreter" (compile NoTracing psatisfiedPayload)
  check "multisig rule safety" (compile NoTracing psafeRule)
  check "governance NFT validator" (compile NoTracing pvalidateGovernanceSpend)
  check "treasury conservation validator" (compile NoTracing pvalidateTreasurySpend)
  check "shared registry validator" (compile NoTracing pvalidateRegistrySpend)
  check "one-shot governance NFT policy" (compile NoTracing pvalidateGovernanceMint)
  check "root and split node NFT policy" (compile NoTracing pvalidateNodeMint)
  behavior
  contextBehavior
  where
    check label result = case result of
      Left err -> fail (label <> ": " <> show err)
      Right script -> case (V3.deserialiseScript (V3.MajorProtocolVersion 11)
        (serialiseScript script) :: Either V3.ScriptDecodeError V3.ScriptForEvaluation) of
        Left err -> fail (label <> ": ledger deserialization failed: " <> show err)
        Right _ -> putStrLn (label <> ": compiled and ledger-deserialized ("
          <> show (SBS.length (serialiseScript script)) <> " bytes)")

behavior :: IO ()
behavior = do
  let bytes = BS.pack [97, 98, 99]
      expected = decodeHex "dc4de427ae6bedec4d12128a638a811251ab883c1636e5e835dd7e4dc4f5f43d"
      subject = BS.replicate 28 0
      preimage hashValue = pcon (PPreimage (pdata (pconstant subject)) (pdata 0)
        (pdata (pconstant hashValue)) (pdata (pconstant bytes)))
      ref number = pcon (PContentRef
        (pdata (pconstant (BS.replicate 27 0 <> BS.singleton number)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 100)
        (pdata (pcons # pdata (pconstant (BS.replicate 32 2)) # pcon PNil)))
      hashOnlyRef number = pcon (PContentRef
        (pdata (pconstant (BS.replicate 27 0 <> BS.singleton number)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 0)
        (pdata (pcon PNil)))
      refs numbers = foldr (\number tailRefs -> pcons # pdata (ref number) # tailRefs) (pcon PNil) numbers
      node lower upper numbers = pcon (PPackedNode
        (pdata (pconstant lower)) (pdata (pconstant upper)) (pdata (refs numbers)))
      upper = BS.replicate 61 255
      subject5 = BS.replicate 27 0 <> BS.singleton 5
      badRef = pcon (PContentRef
        (pdata (pconstant subject5))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 12001)
        (pdata (pcons # pdata (pconstant (BS.replicate 32 2)) # pcon PNil)))
      badNode = pcon (PPackedNode
        (pdata (pconstant BS.empty)) (pdata (pconstant upper))
        (pdata (pcons # pdata (ref 1) # (pcons # pdata (ref 3) # (pcons # pdata badRef # pcon PNil)))))
  assert "segment hash matches Python golden" $ plift
    (psegmentHash # pconstant bytes #== pconstant expected)
  let expectedRefData = V3.List
        [ V3.B (BS.replicate 27 0 <> BS.singleton 5)
        , V3.B (BS.replicate 32 1)
        , V3.I 100
        , V3.List [V3.B (BS.replicate 32 2)]
        ]
  assert "content-reference data layout matches CLI files" $
    plift (pforgetData (pdata (ref 5))) == expectedRefData
  assert "registry datum tag matches CLI files" $
    plift (pforgetData (pdata (pcon (PListItem (pdata (node "" upper [5]))))))
      == V3.Constr 0 [V3.List [V3.B BS.empty, V3.B upper, V3.List [expectedRefData]]]
  assert "manifest datum tag matches CLI files" $
    plift (pforgetData (pdata (pcon (PManifestItem (pdata (ref 5))))))
      == V3.Constr 2 [expectedRefData]
  assert "insert redeemer tag matches CLI files" $
    plift (pforgetData (pdata (pcon (PInsertAction (pdata (ref 5)) (pdata 0)))))
      == V3.Constr 0 [expectedRefData, V3.I 0]
  assert "root node token matches Python golden" $ plift
    (pblake2b_256 # pconstant "" #== pconstant (decodeHex "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"))
  assert "preimage accepts matching hash" $ plift (pvalidPreimage # preimage expected)
  assert "preimage rejects altered hash" $ not $ plift
    (pvalidPreimage # preimage (BS.replicate 32 0))
  let key1 = pcon (PPubKeyHash (pconstant (BS.replicate 28 21)))
      key2 = pcon (PPubKeyHash (pconstant (BS.replicate 28 22)))
      scriptHash = pcon (PScriptHash (pconstant (BS.replicate 28 23)))
      scriptCred = pcon (PScriptCredential (pdata scriptHash))
      signed = pcons # pdata key1 # pcon PNil
      scriptRule = pcon (PScript (pdata scriptHash))
      thresholdRule = pcon (PAtLeast (pdata 1)
        (pdata (pcons # pdata (pcon (PSignature (pdata key2)))
          # (pcons # pdata (pcon (PSignature (pdata key1))) # pcon PNil))))
      withdrawals = AssocMap.psingleton # scriptCred # pcon (PLovelace 0)
  assert "aicone script withdrawal branch accepts matching credential" $ plift
    (psatisfied # scriptRule # (pcon PNil) # Interval.punbounded # withdrawals)
  assert "aicone script withdrawal branch rejects absent credential" $ not $ plift
    (psatisfied # scriptRule # (pcon PNil) # Interval.punbounded # AssocMap.pempty)
  assert "aicone threshold tolerates an absent signer first" $ plift
    (psatisfied # thresholdRule # signed # Interval.punbounded # AssocMap.pempty)
  assert "signature rule requires an authority witness" $ plift
    (psafeRule # pcon (PSignature (pdata key1)))
  assert "script rule requires an authority witness" $ plift (psafeRule # scriptRule)
  assert "time-only rule cannot govern the NFT" $ not $ plift
    (psafeRule # pcon (PBefore (pdata (pcon (PPosixTime 100)))))
  assert "empty all-of rule cannot govern the NFT" $ not $ plift
    (psafeRule # pcon (PAllOf (pdata (pcon PNil))))
  assert "zero-of rule cannot govern the NFT" $ not $ plift
    (psafeRule # pcon (PAtLeast (pdata 0) (pdata (pcon PNil))))
  assert "threshold with a time-only path cannot govern the NFT" $ not $ plift
    (psafeRule # pcon (PAtLeast (pdata 1)
      (pdata (pcons # pdata (pcon (PBefore (pdata (pcon (PPosixTime 100)))))
        # (pcons # pdata (pcon (PSignature (pdata key1))) # pcon PNil)))))
  assert "threshold needing a signer can govern the NFT" $ plift
    (psafeRule # pcon (PAtLeast (pdata 2)
      (pdata (pcons # pdata (pcon (PBefore (pdata (pcon (PPosixTime 100)))))
        # (pcons # pdata (pcon (PSignature (pdata key1))) # pcon PNil)))))
  assert "manifest accepts segment layout" $ plift (pvalidManifest # ref 5)
  assert "manifest rejects hash-only placeholder" $ not $ plift (pvalidManifest # hashOnlyRef 5)
  assert "packed insertion accepts hash-only commitment" $ plift
    (pvalidPackedInsert # node "" upper [1, 3]
      # pcon (PPackedNode (pdata (pconstant BS.empty)) (pdata (pconstant upper))
        (pdata (pcons # pdata (ref 1) # (pcons # pdata (ref 3) # (pcons # pdata (hashOnlyRef 5) # pcon PNil)))))
      # hashOnlyRef 5 # 2)
  assert "packed insertion accepts ordered subject" $ plift
    (pvalidPackedInsert # node "" upper [1, 3]
      # node "" upper [1, 3, 5] # ref 5 # 2)
  assert "packed insertion rejects duplicate subject" $ not $ plift
    (pvalidPackedInsert # node "" upper [1, 3]
      # node "" upper [1, 3, 3] # ref 3 # 2)
  assert "packed insertion rejects inconsistent content length" $ not $ plift
    (pvalidPackedInsert # node "" upper [1, 3]
      # badNode # badRef # 2)
  assert "packed split accepts exact two-node partition" $ plift
    (pvalidPackedSplit # node "" upper [1, 2, 3, 4, 6, 7, 8, 9]
      # node "" subject5 [1, 2, 3, 4]
      # node subject5 upper [5, 6, 7, 8, 9]
      # ref 5 # 4)
  assert "packed split rejects shifted boundary" $ not $ plift
    (pvalidPackedSplit # node "" upper [1, 2, 3, 4, 6, 7, 8, 9]
      # node "" (BS.replicate 28 0) [1, 2, 3, 4]
      # node (BS.replicate 28 0) upper [5, 6, 7, 8, 9]
      # ref 5 # 4)
  assert "packed update replaces one commitment" $ plift
    (pvalidPackedUpdate # node "" upper [1, 3]
      # pcon (PPackedNode (pdata (pconstant (BS.empty))) (pdata (pconstant upper))
        (pdata (pcons # pdata (ref 1) # (pcons # pdata (pcon (PContentRef
          (pdata (pconstant (BS.replicate 27 0 <> BS.singleton 3)))
          (pdata (pconstant (BS.replicate 32 4)))
          (pdata 100)
          (pdata (pcons # pdata (pconstant (BS.replicate 32 5)) # pcon PNil)))) # pcon PNil))))
      # pcon (PContentRef
          (pdata (pconstant (BS.replicate 27 0 <> BS.singleton 3)))
          (pdata (pconstant (BS.replicate 32 4)))
          (pdata 100)
          (pdata (pcons # pdata (pconstant (BS.replicate 32 5)) # pcon PNil)))
      # 1)
  let heavyHashes = foldr (\number rest ->
        pcons # pdata (pconstant (BS.replicate 31 0 <> BS.singleton number)) # rest)
        (pcon PNil) [0 .. 31]
      heavyRef number = pcon (PContentRef
        (pdata (pconstant (BS.replicate 27 0 <> BS.singleton number)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 380000)
        (pdata heavyHashes))
      oversizeRef = pcon (PContentRef
        (pdata (pconstant (BS.replicate 27 0 <> BS.singleton 5)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 380001)
        (pdata heavyHashes))
      heavyNode lower bound numbers = pcon (PPackedNode
        (pdata (pconstant lower)) (pdata (pconstant bound))
        (pdata (foldr (\number rest -> pcons # pdata (heavyRef number) # rest) (pcon PNil) numbers)))
      worstSplit = pvalidPackedSplit
        # heavyNode "" upper [1, 2, 3, 4, 6, 7, 8, 9]
        # heavyNode "" subject5 [1, 2, 3, 4]
        # heavyNode subject5 upper [5, 6, 7, 8, 9]
        # heavyRef 5 # 4
  assert "380000-byte content reference accepted" $ plift (pvalidManifest # heavyRef 5)
  assert "380001-byte content reference rejected" $ not $ plift (pvalidManifest # oversizeRef)
  assert "32-hash packed split evaluates" $ plift worstSplit
  case evalTerm NoTracing worstSplit of
    Right (Right _, budget, _) -> putStrLn ("32-hash packed split budget: " <> show budget)
    Right (Left err, _, _) -> fail ("32-hash split evaluation failed: " <> show err)
    Left err -> fail ("32-hash split did not compile: " <> show err)

assert :: String -> Bool -> IO ()
assert label passed = if passed then putStrLn (label <> ": passed") else fail label

decodeHex :: String -> BS.ByteString
decodeHex [] = BS.empty
decodeHex (a : b : rest) = BS.cons (fromIntegral (fst (head (readHex [a, b])))) (decodeHex rest)
decodeHex _ = error "odd hexadecimal length"

contextBehavior :: IO ()
contextBehavior = do
  let govCS = pcon (PCurrencySymbol (pconstant (BS.replicate 28 10)))
      govTN = pcon (PTokenName (pconstant "GOV"))
      registryAddress = scriptAddress 11
      governanceAddress = scriptAddress 12
      oldRef = outRef 1
      govRef = outRef 2
      treasuryInput = input oldRef (output registryAddress 10 False)
      authorityInput = input govRef (output governanceAddress 2 True)
      makeContextWithDonation returned withAuthority donation = pcon (PScriptContext
        (txInfoWithMintAndDonation
          (if withAuthority then [treasuryInput, authorityInput] else [treasuryInput])
          [output registryAddress returned False] 2 [] pemptyMintValue donation)
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript oldRef (pcon PDNothing))))
      makeContext returned withAuthority = makeContextWithDonation returned withAuthority (pcon PDNothing)
      conservation returned = pgovernedAdaConservation # govCS # govTN
        # governanceAddress # registryAddress # makeContext returned True
      donated returned = pgovernedAdaConservation # govCS # govTN
        # governanceAddress # registryAddress
        # makeContextWithDonation returned True (pcon (PDJust (pdata (pcon (PLovelace 3)))))
  assert "governed ADA stays at registry or pays fee" $ plift (conservation 8)
  assert "governed ADA cannot leak externally" $ not $ plift (conservation 7)
  assert "governed ADA may pay Cardano treasury donation" $ plift (donated 5)
  assert "donation cannot hide additional ADA leakage" $ not $ plift (donated 4)
  assert "treasury spend requires governance NFT" $ not $ plift
    (pgovernedAdaConservation # govCS # govTN # governanceAddress
      # registryAddress # makeContext 8 False)
  case evalTerm NoTracing (pvalidateTreasurySpend # govCS # govTN # governanceAddress # makeContext 8 True) of
    Right (Right _, _, _) -> putStrLn "treasury validator accepts conserved spend: passed"
    Right (Left err, _, _) -> fail ("treasury validator rejected conserved spend: " <> show err)
    Left err -> fail ("treasury validator did not compile: " <> show err)
  let fundedDatumOutput = pcon (PTxOut registryAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 8)))
        (pcon (POutputDatum (pcon (PDatum (pforgetData (pdata (pconstant @PInteger 42)))))))
        (pcon PDNothing))
      fundedContext = pcon (PScriptContext
        (txInfo [treasuryInput, authorityInput] [fundedDatumOutput] 2)
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript oldRef (pcon PDNothing))))
  case evalTerm NoTracing (pvalidateTreasurySpend # govCS # govTN # governanceAddress # fundedContext) of
    Right (Right _, _, _) -> putStrLn "treasury validator funds a datum-bearing registry output: passed"
    Right (Left err, _, _) -> fail ("treasury validator rejected datum-funded spend: " <> show err)
    Left err -> fail ("treasury datum-funded spend did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateTreasurySpend # govCS # govTN # governanceAddress # makeContext 7 True) of
    Right (Left _, _, _) -> putStrLn "treasury validator rejects ADA leak: passed"
    Right (Right _, _, _) -> fail "treasury validator accepted ADA leak"
    Left err -> fail ("treasury validator did not compile: " <> show err)
  let nodeCS = pcon (PCurrencySymbol (pconstant (BS.replicate 28 13)))
      nodeTN = pcon (PTokenName (pblake2b_256 # pconstant ""))
      subject number = BS.replicate 27 0 <> BS.singleton number
      ref number = pcon (PContentRef
        (pdata (pconstant (subject number)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 100)
        (pdata (pcons # pdata (pconstant (BS.replicate 32 2)) # pcon PNil)))
      nodeAt lower upper numbers = pcon (PPackedNode
        (pdata (pconstant lower)) (pdata (pconstant upper))
        (pdata (foldr (\number rest -> pcons # pdata (ref number) # rest) (pcon PNil) numbers)))
      inlineAt lower upper numbers = pcon (PDatum (pforgetData (pdata (pcon (PListItem (pdata (nodeAt lower upper numbers)))))))
      inline numbers = inlineAt BS.empty (BS.replicate 61 255) numbers
      nodeOutputAt lower upper numbers token = pcon (PTxOut registryAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 10
            <> LedgerValue.psingletonSortedValue # nodeCS # token # 1)))
        (pcon (POutputDatum (inlineAt lower upper numbers))) (pcon PDNothing))
      nodeOutput numbers = nodeOutputAt BS.empty (BS.replicate 61 255) numbers nodeTN
      listContext newNumbers = pcon (PScriptContext
        (txInfo [input oldRef (nodeOutput [1]), authorityInput] [nodeOutput newNumbers] 2)
        (pcon (PRedeemer (pforgetData (pdata (pcon (PInsertAction (pdata (ref 2)) (pdata 1)))))))
        (pcon (PSpendingScript oldRef (pcon (PDJust (pdata (inline [1])))))))
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # listContext [1, 2]) of
    Right (Right _, _, _) -> putStrLn "shared validator accepts governed insert: passed"
    Right (Left err, _, _) -> fail ("shared validator rejected insert: " <> show err)
    Left err -> fail ("shared validator did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # listContext [1, 1, 2]) of
    Right (Left _, _, _) -> putStrLn "shared validator rejects altered entries: passed"
    Right (Right _, _, _) -> fail "shared validator accepted altered entries"
    Left err -> fail ("shared validator did not compile: " <> show err)
  let preimageBytes = pconstant "independent-upload"
      preimageDatum segmentDigest = pcon (PDatum (pforgetData (pdata (pcon (PPreimageItem
        (pdata (pcon (PPreimage (pdata (pconstant (subject 1))) (pdata 0)
          (pdata segmentDigest) (pdata preimageBytes)))))))))
      preimageOutput segmentDigest = pcon (PTxOut registryAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 10)))
        (pcon (POutputDatum (preimageDatum segmentDigest))) (pcon PDNothing))
      preimageContext segmentDigest = pcon (PScriptContext
        (txInfo [input oldRef (preimageOutput segmentDigest), authorityInput]
          [output registryAddress 8 False] 2)
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript oldRef (pcon (PDJust (pdata (preimageDatum segmentDigest)))))))
      goodDigest = psegmentHash # preimageBytes
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # preimageContext goodDigest) of
    Right (Right _, _, _) -> putStrLn "shared validator accepts separately uploaded segment spend: passed"
    Right (Left err, _, _) -> fail ("shared validator rejected segment spend: " <> show err)
    Left err -> fail ("segment spend validator did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # preimageContext (pconstant (BS.replicate 32 0))) of
    Right (Left _, _, _) -> putStrLn "shared validator rejects mismatched segment preimage: passed"
    Right (Right _, _, _) -> fail "shared validator accepted mismatched segment preimage"
    Left err -> fail ("segment spend validator did not compile: " <> show err)
  let signer = pcon (PPubKeyHash (pconstant (BS.replicate 28 21)))
      rule = pcon (PSignature (pdata signer))
      govDatum = pcon (PDatum (pforgetData (pdata (pcon (PGovernanceDatum
        (pdata govCS) (pdata govTN) (pdata rule))))))
      govOutput = pcon (PTxOut governanceAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 2
            <> LedgerValue.psingletonSortedValue # govCS # govTN # 1)))
        (pcon (POutputDatum govDatum)) (pcon PDNothing))
      govContext signers = pcon (PScriptContext
        (txInfoWithSigners [input govRef govOutput] [govOutput] 1 signers)
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript govRef (pcon (PDJust (pdata govDatum))))))
  case evalTerm NoTracing (pvalidateGovernanceSpend # govContext [signer]) of
    Right (Right _, _, _) -> putStrLn "multisig accepts authorized NFT continuation: passed"
    Right (Left err, _, _) -> fail ("multisig rejected signer: " <> show err)
    Left err -> fail ("multisig did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # govContext []) of
    Right (Left _, _, _) -> putStrLn "multisig rejects missing signer: passed"
    Right (Right _, _, _) -> fail "multisig accepted missing signer"
    Left err -> fail ("multisig did not compile: " <> show err)
  let withdrawalHash = pcon (PScriptHash (pconstant (BS.replicate 28 23)))
      withdrawalRule = pcon (PScript (pdata withdrawalHash))
      withdrawalDatum = pcon (PDatum (pforgetData (pdata (pcon (PGovernanceDatum
        (pdata govCS) (pdata govTN) (pdata withdrawalRule))))))
      withdrawalOutput = pcon (PTxOut governanceAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 2
            <> LedgerValue.psingletonSortedValue # govCS # govTN # 1)))
        (pcon (POutputDatum withdrawalDatum)) (pcon PDNothing))
      withdrawalCredential = pcon (PScriptCredential (pdata withdrawalHash))
      withdrawalContext withWitness = pcon (PScriptContext
        (txInfoWithWithdrawals [input govRef withdrawalOutput] [withdrawalOutput] 1
          (if withWitness
            then AssocMap.psingleton # withdrawalCredential # pcon (PLovelace 0)
            else AssocMap.pempty))
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript govRef (pcon (PDJust (pdata withdrawalDatum))))))
  case evalTerm NoTracing (pvalidateGovernanceSpend # withdrawalContext True) of
    Right (Right _, _, _) -> putStrLn "governance NFT accepts script withdrawal authority: passed"
    Right (Left err, _, _) -> fail ("governance rejected withdrawal authority: " <> show err)
    Left err -> fail ("governance withdrawal validator did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # withdrawalContext False) of
    Right (Left _, _, _) -> putStrLn "governance NFT rejects absent withdrawal authority: passed"
    Right (Right _, _, _) -> fail "governance accepted absent withdrawal authority"
    Left err -> fail ("governance withdrawal validator did not compile: " <> show err)
  let nextSigner = pcon (PPubKeyHash (pconstant (BS.replicate 28 22)))
      nextRule = pcon (PSignature (pdata nextSigner))
      nextDatum = pcon (PDatum (pforgetData (pdata (pcon (PGovernanceDatum
        (pdata govCS) (pdata govTN) (pdata nextRule))))))
      rotatedOutput = pcon (PTxOut governanceAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 2
            <> LedgerValue.psingletonSortedValue # govCS # govTN # 1)))
        (pcon (POutputDatum nextDatum)) (pcon PDNothing))
      unsafeRule = pcon (PBefore (pdata (pcon (PPosixTime 100))))
      unsafeDatum = pcon (PDatum (pforgetData (pdata (pcon (PGovernanceDatum
        (pdata govCS) (pdata govTN) (pdata unsafeRule))))))
      unsafeOutput = pcon (PTxOut governanceAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 2
            <> LedgerValue.psingletonSortedValue # govCS # govTN # 1)))
        (pcon (POutputDatum unsafeDatum)) (pcon PDNothing))
      rotationContext signers successor = pcon (PScriptContext
        (txInfoWithSigners [input govRef govOutput] [successor] 1 signers)
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript govRef (pcon (PDJust (pdata govDatum))))))
  case evalTerm NoTracing (pvalidateGovernanceSpend # rotationContext [signer] rotatedOutput) of
    Right (Right _, _, _) -> putStrLn "governance rotates under old signer: passed"
    Right (Left err, _, _) -> fail ("governance rejected authorized rotation: " <> show err)
    Left err -> fail ("governance rotation did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # rotationContext [nextSigner] rotatedOutput) of
    Right (Left _, _, _) -> putStrLn "governance rotation rejects new signer alone: passed"
    Right (Right _, _, _) -> fail "governance rotation accepted only the new signer"
    Left err -> fail ("governance rotation did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # rotationContext [signer] unsafeOutput) of
    Right (Left _, _, _) -> putStrLn "governance rotation rejects witness-free next rule: passed"
    Right (Right _, _, _) -> fail "governance rotation accepted a witness-free next rule"
    Left err -> fail ("governance safety validator did not compile: " <> show err)
  let seedRef = outRef 9
      seedInput = input seedRef (output (scriptAddress 23) 4 False)
      governanceMintContext withSeed successor = pcon (PScriptContext
        (txInfoWithMint (if withSeed then [seedInput] else []) [successor] 1 []
          (psingletonMintValue # govCS # govTN # 1))
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PMintingScript (pdata govCS))))
  case evalTerm NoTracing (pvalidateGovernanceMint # seedRef # govTN # governanceAddress # governanceMintContext True govOutput) of
    Right (Right _, _, _) -> putStrLn "governance NFT policy accepts seeded mint: passed"
    Right (Left err, _, _) -> fail ("governance mint rejected seed: " <> show err)
    Left err -> fail ("governance mint did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceMint # seedRef # govTN # governanceAddress # governanceMintContext False govOutput) of
    Right (Left _, _, _) -> putStrLn "governance NFT policy rejects missing seed: passed"
    Right (Right _, _, _) -> fail "governance mint accepted missing seed"
    Left err -> fail ("governance mint did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceMint # seedRef # govTN # governanceAddress # governanceMintContext True unsafeOutput) of
    Right (Left _, _, _) -> putStrLn "governance mint rejects witness-free initial rule: passed"
    Right (Right _, _, _) -> fail "governance mint accepted a witness-free initial rule"
    Left err -> fail ("governance mint safety did not compile: " <> show err)
  let nodeBootstrapContext numbers = pcon (PScriptContext
        (txInfoWithMint [seedInput] [nodeOutput numbers] 1 []
          (psingletonMintValue # nodeCS # nodeTN # 1))
        (pcon (PRedeemer (pforgetData (pdata (pcon PBootstrap)))))
        (pcon (PMintingScript (pdata nodeCS))))
  case evalTerm NoTracing (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress # nodeBootstrapContext []) of
    Right (Right _, _, _) -> putStrLn "node policy accepts empty seeded root: passed"
    Right (Left err, _, _) -> fail ("node bootstrap rejected empty root: " <> show err)
    Left err -> fail ("node bootstrap did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress # nodeBootstrapContext [1]) of
    Right (Left _, _, _) -> putStrLn "node policy rejects nonempty root: passed"
    Right (Right _, _, _) -> fail "node bootstrap accepted nonempty root"
    Left err -> fail ("node bootstrap did not compile: " <> show err)
  let boundary = subject 5
      rightTN = pcon (PTokenName (pblake2b_256 # pconstant boundary))
      leftOutput = nodeOutputAt BS.empty boundary [1, 2, 3, 4] nodeTN
      rightOutput numbers = nodeOutputAt boundary (BS.replicate 61 255) numbers rightTN
      oldFull = nodeOutput [1, 2, 3, 4, 6, 7, 8, 9]
      splitInfo rightNumbers = txInfoWithMint
        [input oldRef oldFull, input govRef govOutput]
        [leftOutput, rightOutput rightNumbers, govOutput]
        2 [signer] (psingletonMintValue # nodeCS # rightTN # 1)
      splitMintContext rightNumbers = pcon (PScriptContext
        (splitInfo rightNumbers)
        (pcon (PRedeemer (pforgetData (pdata (pcon (PMintSplit
          (pdata (ref 5)) (pdata 4) (pdata (pconstant BS.empty)) (pdata (pconstant boundary))))))))
        (pcon (PMintingScript (pdata nodeCS))))
      splitSpendContext rightNumbers = pcon (PScriptContext
        (splitInfo rightNumbers)
        (pcon (PRedeemer (pforgetData (pdata (pcon (PSplitAction
          (pdata (ref 5)) (pdata 4) (pdata (pconstant boundary))))))))
        (pcon (PSpendingScript oldRef (pcon (PDJust (pdata (inline [1, 2, 3, 4, 6, 7, 8, 9])))))))
      splitGovContext = pcon (PScriptContext
        (splitInfo [5, 6, 7, 8, 9])
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript govRef (pcon (PDJust (pdata govDatum))))))
  case evalTerm NoTracing (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress # splitMintContext [5, 6, 7, 8, 9]) of
    Right (Right _, _, _) -> putStrLn "node policy accepts exact governed split: passed"
    Right (Left err, _, _) -> fail ("node policy rejected exact split: " <> show err)
    Left err -> fail ("node split policy did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # splitSpendContext [5, 6, 7, 8, 9]) of
    Right (Right _, _, _) -> putStrLn "registry validator accepts exact governed split: passed"
    Right (Left err, _, _) -> fail ("registry validator rejected exact split: " <> show err)
    Left err -> fail ("registry split validator did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # splitGovContext) of
    Right (Right _, _, _) -> putStrLn "governance NFT continues during split: passed"
    Right (Left err, _, _) -> fail ("governance rejected split: " <> show err)
    Left err -> fail ("governance split validator did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress # splitMintContext [5, 6, 7, 8, 8]) of
    Right (Left _, _, _) -> putStrLn "node policy rejects corrupted split: passed"
    Right (Right _, _, _) -> fail "node policy accepted corrupted split"
    Left err -> fail ("node split policy did not compile: " <> show err)
  let maxSubject number = BS.replicate 59 0 <> BS.singleton number
      maxBoundary = maxSubject 5
      maxRightTN = pcon (PTokenName (pblake2b_256 # pconstant maxBoundary))
      maxHashes = foldr (\number rest ->
        pcons # pdata (pconstant (BS.replicate 31 0 <> BS.singleton number)) # rest)
        (pcon PNil) [0 .. 31]
      maxRef number = pcon (PContentRef
        (pdata (pconstant (maxSubject number)))
        (pdata (pconstant (BS.replicate 32 1)))
        (pdata 380000) (pdata maxHashes))
      maxNode lower upper numbers = pcon (PPackedNode
        (pdata (pconstant lower)) (pdata (pconstant upper))
        (pdata (foldr (\number rest -> pcons # pdata (maxRef number) # rest)
          (pcon PNil) numbers)))
      maxDatum lower upper numbers = pcon (PDatum (pforgetData (pdata
        (pcon (PListItem (pdata (maxNode lower upper numbers)))))))
      maxOutput lower upper numbers token = pcon (PTxOut registryAddress
        (pdata (LedgerValue.ptoLedgerValue #
          (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # 10
            <> LedgerValue.psingletonSortedValue # nodeCS # token # 1)))
        (pcon (POutputDatum (maxDatum lower upper numbers))) (pcon PDNothing))
      maxOldNumbers = [1, 2, 3, 4, 6, 7, 8, 9]
      maxOld = maxOutput BS.empty (BS.replicate 61 255) maxOldNumbers nodeTN
      maxLeft = maxOutput BS.empty maxBoundary [1, 2, 3, 4] nodeTN
      maxRight = maxOutput maxBoundary (BS.replicate 61 255) [5, 6, 7, 8, 9] maxRightTN
      maxInfo = txInfoWithMint [input oldRef maxOld, input govRef govOutput]
        [maxLeft, maxRight, govOutput] 2 [signer]
        (psingletonMintValue # nodeCS # maxRightTN # 1)
      maxSpendContext = pcon (PScriptContext maxInfo
        (pcon (PRedeemer (pforgetData (pdata (pcon (PSplitAction
          (pdata (maxRef 5)) (pdata 4) (pdata (pconstant maxBoundary))))))))
        (pcon (PSpendingScript oldRef (pcon (PDJust
          (pdata (maxDatum BS.empty (BS.replicate 61 255) maxOldNumbers)))))))
      maxMintContext = pcon (PScriptContext maxInfo
        (pcon (PRedeemer (pforgetData (pdata (pcon (PMintSplit
          (pdata (maxRef 5)) (pdata 4) (pdata (pconstant BS.empty))
          (pdata (pconstant maxBoundary))))))))
        (pcon (PMintingScript (pdata nodeCS))))
      maxGovernanceContext = pcon (PScriptContext maxInfo
        (pcon (PRedeemer (pforgetData (pdata (pconstant @PInteger 0)))))
        (pcon (PSpendingScript govRef (pcon (PDJust (pdata govDatum))))))
  case evalTerm NoTracing (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS # maxSpendContext) of
    Right (Right _, budget, _) -> putStrLn ("maximum packed registry split budget: " <> show budget)
    Right (Left err, _, _) -> fail ("maximum registry split failed: " <> show err)
    Left err -> fail ("maximum registry split did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress # maxMintContext) of
    Right (Right _, budget, _) -> putStrLn ("maximum packed node mint budget: " <> show budget)
    Right (Left err, _, _) -> fail ("maximum node mint failed: " <> show err)
    Left err -> fail ("maximum node mint did not compile: " <> show err)
  case evalTerm NoTracing (pvalidateGovernanceSpend # maxGovernanceContext) of
    Right (Right _, budget, _) -> putStrLn ("maximum packed split governance budget: " <> show budget)
    Right (Left err, _, _) -> fail ("maximum split governance spend failed: " <> show err)
    Left err -> fail ("maximum split governance spend did not compile: " <> show err)
  modelPath <- lookupEnv "REGISTRY_V3_COST_MODEL"
  case modelPath of
    Nothing -> pure ()
    Just path -> do
      values <- map read . words <$> readFile path
      majorText <- lookupEnv "REGISTRY_PROTOCOL_MAJOR"
      major <- case majorText of
        Just value -> pure (read value)
        Nothing -> fail "REGISTRY_PROTOCOL_MAJOR is required with REGISTRY_V3_COST_MODEL"
      let (contextResult, warnings) = runWriter (runExceptT (V3.mkEvaluationContext values))
      case contextResult of
        Left err -> fail ("V3 ledger cost model failed: " <> show err)
        Right context -> do
          if null warnings then pure () else fail "V3 cost model has warnings"
          ledgerBudget major context "registry spend"
            (pvalidateRegistrySpend # govCS # govTN # governanceAddress # nodeCS)
            (plift (pforgetData (pdata maxSpendContext)))
          ledgerBudget major context "node mint"
            (pvalidateNodeMint # seedRef # govCS # govTN # governanceAddress)
            (plift (pforgetData (pdata maxMintContext)))
          ledgerBudget major context "governance spend" pvalidateGovernanceSpend
            (plift (pforgetData (pdata maxGovernanceContext)))
  where
    ledgerBudget :: Integer -> V3.EvaluationContext -> String
      -> (forall s. Term s (PScriptContext :--> PUnit)) -> V3.Data -> IO ()
    ledgerBudget major context label term datum = case compile NoTracing term of
      Left err -> fail (label <> " did not compile: " <> show err)
      Right script ->
        case V3.deserialiseScript (V3.MajorProtocolVersion (fromInteger major)) (serialiseScript script) of
          Left err -> fail (label <> " did not deserialize: " <> show err)
          Right evaluatedScript -> case V3.evaluateScriptCounting
            (V3.MajorProtocolVersion (fromInteger major)) V3.Quiet context evaluatedScript datum of
            (_, Left err) -> fail (label <> " ledger evaluation failed: " <> show err)
            (_, Right budget) -> putStrLn ("maximum packed " <> label <> " ledger budget: " <> show budget)
    scriptAddress number = pcon (PAddress
      (pcon (PScriptCredential (pdata (pcon (PScriptHash (pconstant (BS.replicate 28 number)))))))
      (pcon PDNothing))
    outRef number = pcon (PTxOutRef
      (pdata (pcon (PTxId (pconstant (BS.replicate 32 number))))) (pdata 0))
    output address ada withNft = pcon (PTxOut address
      (pdata (LedgerValue.ptoLedgerValue #
        (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # ada
          <> if withNft
             then LedgerValue.psingletonSortedValue
               # pcon (PCurrencySymbol (pconstant (BS.replicate 28 10)))
               # pcon (PTokenName (pconstant "GOV")) # 1
             else mempty)))
      (pcon PNoOutputDatum) (pcon PDNothing))
    input ref resolved = pcon (PTxInInfo ref resolved)
    txInfo ins outs fee = txInfoWithSigners ins outs fee []
    txInfoWithSigners ins outs fee signers = txInfoWithMint ins outs fee signers pemptyMintValue
    txInfoWithMint ins outs fee signers minted =
      txInfoWithMintAndDonation ins outs fee signers minted (pcon PDNothing)
    txInfoWithMintAndDonation ins outs fee signers minted donation =
      txInfoWithAll ins outs fee signers minted donation AssocMap.pempty
    txInfoWithWithdrawals ins outs fee withdrawals =
      txInfoWithAll ins outs fee [] pemptyMintValue (pcon PDNothing) withdrawals
    txInfoWithAll ins outs fee signers minted donation withdrawals = pcon (PTxInfo
      (pdata (foldr (\item rest -> pcons # pdata item # rest) (pcon PNil) ins))
      (pdata (pcon PNil))
      (pdata (foldr (\item rest -> pcons # pdata item # rest) (pcon PNil) outs))
      (pdata (pcon (PLovelace fee)))
      (pdata minted)
      (pdata (pcon PNil))
      (pdata withdrawals)
      Interval.punbounded
      (pdata (foldr (\signer rest -> pcons # pdata signer # rest) (pcon PNil) signers))
      (pdata AssocMap.pempty)
      (pdata AssocMap.pempty)
      (pdata (pcon (PTxId (pconstant (BS.replicate 32 3)))))
      (pdata AssocMap.pempty)
      (pdata (pcon PNil))
      (pcon PDNothing)
      donation)
