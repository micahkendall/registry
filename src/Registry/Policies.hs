{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}

-- | One-shot minting of the governance NFT. Consuming a designated seed UTxO
-- makes a second mint or a later burn impossible under this policy.
module Registry.Policies (PNodeMintAction (..), pvalidateGovernanceMint, pvalidateNodeMint) where

import Data.ByteString qualified as BS
import GHC.Generics (Generic)
import Generics.SOP qualified as SOP
import Plutarch.Builtin.Value (punValueData)
import Plutarch.Builtin.Crypto (pblake2b_256)
import Plutarch.LedgerApi.AssocMap qualified as AssocMap
import Plutarch.LedgerApi.V3
import Plutarch.LedgerApi.V3.Value qualified as Value
import Plutarch.Prelude
import Plutarch.Unsafe (punsafeCoerce)
import Registry.OnChain
import Registry.Governance (PGovernanceDatum (..), psafeRule)
import Registry.Treasury (pgovernedAdaConservation)

data PNodeMintAction (s :: S)
  = PBootstrap
  | PMintSplit (Term s (PAsData PContentRef)) (Term s (PAsData PInteger)) (Term s (PAsData PByteString)) (Term s (PAsData PByteString))
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataStruct PNodeMintAction

pOwnMintExactlyOne :: Term s (PCurrencySymbol :--> PTokenName :--> PTxInfo :--> PBool)
pOwnMintExactlyOne = phoistAcyclic $ plam $ \ownCS tokenName info ->
  let minted = pmatch info $ \i -> pfromData (ptxInfo'mint i)
      ownTokens = AssocMap.plookup # ownCS # pto (pto minted)
   in pmatch ownTokens $ \case
        PJust tokenMap -> tokenMap #== AssocMap.psingleton # tokenName # (1 :: Term s PInteger)
        PNothing -> pconstant False

pNodeFromOutput :: Term s (PTxOut :--> PPackedNode)
pNodeFromOutput = phoistAcyclic $ plam $ \out ->
  pmatch out $ \o ->
    pmatch (ptxOut'datum o) $ \case
      POutputDatum inlineDatum ->
        pmatch (pfromData (punsafeCoerce @(PAsData PRegistryDatum) (pto inlineDatum))) $ \case
          PListItem nodeData -> pfromData nodeData
          _ -> perror
      _ -> perror

-- | One root is created by consuming a designated seed UTxO. Subsequent
-- mints are possible only when a full node is split exactly, with governance
-- authority and ADA conservation checked in the same transaction.
pvalidateNodeMint ::
  Term s
    ( PTxOutRef
        :--> PCurrencySymbol
        :--> PTokenName
        :--> PAddress
        :--> PScriptContext
        :--> PUnit
    )
pvalidateNodeMint = plam $ \seedRef govCS govTN govAddress ctx ->
  pmatch ctx $ \scriptCtx ->
    pmatch (pscriptContext'scriptInfo scriptCtx) $ \case
      PMintingScript ownCSData ->
        let ownCS = pfromData ownCSData
            info = pscriptContext'txInfo scriptCtx
            inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
            outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
            action = pfromData (punsafeCoerce @(PAsData PNodeMintAction) (pto (pscriptContext'redeemer scriptCtx)))
            nodeToken lower = pcon (PTokenName (pblake2b_256 # lower))
            rootTN = nodeToken (pconstant "")
            atNode token out = pmatch out $ \o ->
              Value.pvalueOf # ownCS # token
                # (punValueData # pforgetData (ptxOut'value o)) #== 1
            rootOutputs = pfilter # (plam $ \outData -> atNode rootTN (pfromData outData)) # outputs
            rootOutput = pfromData (phead # rootOutputs)
            rootAtScript = pmatch rootOutput $ \out ->
              pmatch (ptxOut'address out) $ \address ->
                pmatch (paddress'credential address) $ \case
                  PScriptCredential _ -> pconstant True
                  _ -> pconstant False
            rooted = pmatch (pNodeFromOutput # rootOutput) $ \node ->
              (plowerBound node #== pdata (pconstant ""))
                #&& (pnextBound node #== pdata (pconstant (BS.replicate 61 0xff)))
                #&& (plength # pfromData (pentries node) #== 0)
            seedSpent = pany # (plam $ \inputData ->
              pmatch (pfromData inputData) $ \input -> ptxInInfo'outRef input #== seedRef) # inputs
            valid = pmatch action $ \case
              PBootstrap ->
                seedSpent
                  #&& (pOwnMintExactlyOne # ownCS # rootTN # info)
                  #&& (plength # rootOutputs #== 1)
                  #&& rootAtScript
                  #&& rooted
              PMintSplit entryData indexData oldLowerData boundaryData ->
                let oldTN = nodeToken (pfromData oldLowerData)
                    rightTN = nodeToken (pfromData boundaryData)
                    oldInputs = pfilter # (plam $ \inputData ->
                      pmatch (pfromData inputData) $ \input ->
                        atNode oldTN (ptxInInfo'resolved input)) # inputs
                    oldInput = pfromData (phead # oldInputs)
                    registryAddress = pmatch oldInput $ \input ->
                      pmatch (ptxInInfo'resolved input) $ \out -> ptxOut'address out
                    leftOutputs = pfilter # (plam $ \outData ->
                      pmatch (pfromData outData) $ \out ->
                        (ptxOut'address out #== registryAddress) #&& (atNode oldTN (pfromData outData))) # outputs
                    rightOutputs = pfilter # (plam $ \outData ->
                      pmatch (pfromData outData) $ \out ->
                        (ptxOut'address out #== registryAddress) #&& (atNode rightTN (pfromData outData))) # outputs
                    oldNode = pmatch oldInput $ \input -> pNodeFromOutput # ptxInInfo'resolved input
                    leftNode = pNodeFromOutput # pfromData (phead # leftOutputs)
                    rightNode = pNodeFromOutput # pfromData (phead # rightOutputs)
                 in (pnot # (oldTN #== rightTN))
                      #&& (plength # oldInputs #== 1)
                      #&& (plength # leftOutputs #== 1)
                      #&& (plength # rightOutputs #== 1)
                      #&& (pOwnMintExactlyOne # ownCS # rightTN # info)
                      #&& (pgovernedAdaConservation # govCS # govTN # govAddress # registryAddress # ctx)
                      #&& (pvalidPackedSplit # oldNode # leftNode # rightNode
                        # pfromData entryData # pfromData indexData)
         in pif valid (pconstant ()) perror
      _ -> perror

pvalidateGovernanceMint ::
  Term s (PTxOutRef :--> PTokenName :--> PAddress :--> PScriptContext :--> PUnit)
pvalidateGovernanceMint = plam $ \seedRef govTN govAddress ctx ->
  pmatch ctx $ \scriptCtx ->
    pmatch (pscriptContext'scriptInfo scriptCtx) $ \case
      PMintingScript ownCS ->
        let info = pscriptContext'txInfo scriptCtx
            inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
            outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
            seeded = pany # (plam $ \inputData ->
              pmatch (pfromData inputData) $ \input -> ptxInInfo'outRef input #== seedRef) # inputs
            minted = pmatch info $ \i -> pfromData (ptxInfo'mint i)
            ownTokens = AssocMap.plookup # pfromData ownCS # pto (pto minted)
            exactMint = pmatch ownTokens $ \case
              PJust tokenMap -> tokenMap #== AssocMap.psingleton # govTN # (1 :: Term s PInteger)
              PNothing -> pconstant False
            successors = pfilter # (plam $ \outData ->
              pmatch (pfromData outData) $ \out ->
                (ptxOut'address out #== govAddress)
                  #&& (Value.pvalueOf # pfromData ownCS # govTN
                    # (punValueData # pforgetData (ptxOut'value out)) #== 1)
                  #&& (pmatch (ptxOut'datum out) $ \case
                    POutputDatum inlineDatum ->
                      pmatch (pfromData (punsafeCoerce @(PAsData PGovernanceDatum) (pto inlineDatum))) $ \d ->
                        (pgovCurrency d #== ownCS)
                          #&& (pgovToken d #== pdata govTN)
                          #&& (psafeRule # pfromData (pgovRule d))
                    _ -> pconstant False)) # outputs
            addressIsScript = pmatch govAddress $ \address ->
              pmatch (paddress'credential address) $ \case
                PScriptCredential _ -> pconstant True
                _ -> pconstant False
         in pif (seeded #&& exactMint #&& addressIsScript #&& (plength # successors #== 1))
              (pconstant ()) perror
      _ -> perror
