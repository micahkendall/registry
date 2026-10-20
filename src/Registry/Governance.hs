{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Multisig rule language matching aicone's signature, threshold, time and
-- script-withdrawal alternatives. This module deliberately uses no Aiken code.
module Registry.Governance (PMultisig (..), PAnnotatedSignature (..), PGovernanceDatum (..), psatisfied, psatisfiedPayload, psafeRule, pvalidateGovernanceSpend) where

import GHC.Generics (Generic)
import Generics.SOP qualified as SOP
import Plutarch.LedgerApi.AssocMap qualified as AssocMap
import Plutarch.LedgerApi.Interval qualified as Interval
import Plutarch.LedgerApi.V3
import Plutarch.Builtin.Value (punValueData)
import Plutarch.Builtin.Crypto (pblake2b_224, pverifyEd25519Signature)
import Plutarch.LedgerApi.V3.Value qualified as Value
import Plutarch.Prelude
import Plutarch.Unsafe (punsafeCoerce)

data PMultisig (s :: S)
  = PSignature (Term s (PAsData PPubKeyHash))
  | PAllOf (Term s (PAsData (PBuiltinList (PAsData PMultisig))))
  | PAnyOf (Term s (PAsData (PBuiltinList (PAsData PMultisig))))
  | PAtLeast (Term s (PAsData PInteger)) (Term s (PAsData (PBuiltinList (PAsData PMultisig))))
  | PBefore (Term s (PAsData PPosixTime))
  | PAfter (Term s (PAsData PPosixTime))
  | PScript (Term s (PAsData PScriptHash))
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataStruct PMultisig

data PAnnotatedSignature (s :: S) = PAnnotatedSignature
  { pverificationKey :: Term s (PAsData PByteString)
  , psignature :: Term s (PAsData PByteString)
  }
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataRec PAnnotatedSignature

-- | The NFT identity lives in the datum so this script can be compiled before
-- the one-shot minting policy (and hence its currency symbol) is known.
data PGovernanceDatum (s :: S) = PGovernanceDatum
  { pgovCurrency :: Term s (PAsData PCurrencySymbol)
  , pgovToken :: Term s (PAsData PTokenName)
  , pgovRule :: Term s (PAsData PMultisig)
  }
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataRec PGovernanceDatum

-- | Interpret a multisig rule using transaction signatories, validity range,
-- and the set of script withdrawals. Missing signers return False so AtLeast
-- can count satisfied branches without aborting, as in aicone. In the
-- witness-free safety pass, time branches are treated as possible and script
-- branches as unavailable.
psatisfiedBy ::
  Term s
    ( (PAsData PPubKeyHash :--> PBool)
        :--> PBool
        :--> PMultisig
        :--> PInterval PPosixTime
        :--> PUnsortedMap PCredential PLovelace
        :--> PBool
    )
psatisfiedBy = phoistAcyclic $ plam $ \signatureLeaf withoutWitness rule range withdrawals ->
  (pfixHoisted #$ plam $ \self candidate ->
    pmatch candidate $ \case
      PSignature keyHash -> signatureLeaf # keyHash
      PAllOf scripts -> pall # (plam $ \script -> self # pfromData script) # pfromData scripts
      PAnyOf scripts -> pany # (plam $ \script -> self # pfromData script) # pfromData scripts
      PAtLeast required scripts ->
        let passed = pfilter # (plam $ \script -> self # pfromData script) # pfromData scripts
         in (pfromData required #>= 0) #&& (plength # passed #>= pfromData required)
      PBefore time -> pif withoutWitness (pconstant True) $ pmatch range $ \interval ->
        pmatch (pinterval'to interval) $ \(PUpperBound upper inclusive) ->
          pmatch upper $ \case
            PFinite bound ->
              pif (pfromData inclusive)
                (pfromData bound #<= pfromData time)
                (pfromData bound #< pfromData time)
            _ -> pconstant False
      PAfter time -> pif withoutWitness (pconstant True) $ pmatch range $ \interval ->
        pmatch (pinterval'from interval) $ \(PLowerBound lower inclusive) ->
          pmatch lower $ \case
            PFinite bound ->
              pif (pfromData inclusive)
                (pfromData time #<= pfromData bound)
                (pfromData time #< pfromData bound)
            _ -> pconstant False
      PScript scriptHash ->
        pif withoutWitness (pconstant False) $ pmatch
          (AssocMap.plookup # pcon (PScriptCredential scriptHash) # AssocMap.punsafeCoerceToSortedMap withdrawals)
          $ \case
            PJust _ -> pconstant True
            PNothing -> pconstant False
  ) # rule

psatisfied ::
  Term s
    ( PMultisig
        :--> PBuiltinList (PAsData PPubKeyHash)
        :--> PInterval PPosixTime
        :--> PUnsortedMap PCredential PLovelace
        :--> PBool
    )
psatisfied = phoistAcyclic $ plam $ \rule signers range withdrawals ->
  psatisfiedBy # (plam $ \keyHash -> pelem # keyHash # signers)
    # pconstant False # rule # range # withdrawals

-- | aicone's payload mode: every signer leaf may be satisfied by a matching
-- annotated Ed25519 signature over the supplied bytes. An absent or invalid
-- signature is False, which is necessary for AnyOf/AtLeast semantics.
psatisfiedPayload ::
  Term s
    ( PMultisig
        :--> PByteString
        :--> PBuiltinList (PAsData PAnnotatedSignature)
        :--> PInterval PPosixTime
        :--> PUnsortedMap PCredential PLovelace
        :--> PBool
    )
psatisfiedPayload = phoistAcyclic $ plam $ \rule payload signatures range withdrawals ->
  let leaf = plam $ \keyHash ->
        pany # (plam $ \signatureData ->
          pmatch (pfromData signatureData) $ \annotated ->
            let publicKey = pfromData (pverificationKey annotated)
                signature = pfromData (psignature annotated)
             in (plengthBS # publicKey #== 32)
                  #&& (plengthBS # signature #== 64)
                  #&& (pblake2b_224 # publicKey #== pto (pfromData keyHash))
                  #&& (pverifyEd25519Signature # publicKey # payload # signature)) # signatures
   in psatisfiedBy # leaf # pconstant False # rule # range # withdrawals

-- | Conservatively reject a rule with any path that could succeed without a
-- signer or script-withdrawal witness. Time branches may be true at some
-- validity interval, so they count as witness-free for this check.
psafeRule :: Term s (PMultisig :--> PBool)
psafeRule = plam $ \rule -> pnot #
  (psatisfiedBy # (plam $ \_ -> pconstant False) # pconstant True
    # rule # Interval.punbounded # AssocMap.pempty)

-- | The governance NFT remains at this multisig address after every spend.
-- The old datum authorizes the transaction; the continuing inline datum may
-- install a new rule under that authorization.
pvalidateGovernanceSpend :: Term s (PScriptContext :--> PUnit)
pvalidateGovernanceSpend = plam $ \ctx ->
  pmatch ctx $ \scriptCtx ->
    pmatch (pscriptContext'scriptInfo scriptCtx) $ \case
      PSpendingScript ownRef datumMaybe -> pmatch datumMaybe $ \case
        PDJust datum ->
          let info = pscriptContext'txInfo scriptCtx
              inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
              outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
              oldInputs = pfilter # (plam $ \inData ->
                pmatch (pfromData inData) $ \input -> ptxInInfo'outRef input #== ownRef) # inputs
              oldOutput = pmatch (pfromData (phead # oldInputs)) $ \input -> ptxInInfo'resolved input
              oldDatum = pfromData (punsafeCoerce @(PAsData PGovernanceDatum) (pto datum))
              govCS = pmatch oldDatum $ \d -> pfromData (pgovCurrency d)
              govTN = pmatch oldDatum $ \d -> pfromData (pgovToken d)
              rule = pmatch oldDatum $ \d -> pfromData (pgovRule d)
              successors = pfilter # (plam $ \outData ->
                pmatch (pfromData outData) $ \out ->
                  Value.pvalueOf # govCS # govTN # (punValueData # pforgetData (ptxOut'value out)) #== 1) # outputs
              newOutput = pfromData (phead # successors)
              validRule = pmatch info $ \i ->
                psatisfied # rule # pfromData (ptxInfo'signatories i)
                  # ptxInfo'validRange i # pfromData (ptxInfo'wdrl i)
              valid =
                (plength # oldInputs #== 1)
                  #&& (pmatch oldOutput $ \out -> Value.pvalueOf # govCS # govTN # (punValueData # pforgetData (ptxOut'value out)) #== 1)
                  #&& (pmatch info $ \i -> Value.pvalueOf # govCS # govTN # (punValueData # pforgetData (ptxInfo'mint i)) #== 0)
                  #&& (plength # successors #== 1)
                  #&& (pmatch oldOutput $ \oldOut -> pmatch newOutput $ \newOut ->
                    ptxOut'address oldOut #== ptxOut'address newOut)
                  #&& (pmatch newOutput $ \out -> pmatch (ptxOut'datum out) $ \case
                    POutputDatum inlineDatum ->
                      pmatch (pfromData (punsafeCoerce @(PAsData PGovernanceDatum) (pto inlineDatum))) $ \newDatum ->
                        (pgovCurrency newDatum #== pdata govCS)
                          #&& (pgovToken newDatum #== pdata govTN)
                          #&& (psafeRule # pfromData (pgovRule newDatum))
                    _ -> pconstant False)
                  #&& validRule
           in pif valid (pconstant ()) perror
        _ -> perror
      _ -> perror
