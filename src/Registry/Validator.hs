{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}

-- | One address for packed list nodes, independent preimages, and no-datum
-- ADA treasury outputs.
module Registry.Validator (PRegistryAction (..), pvalidateRegistrySpend) where

import GHC.Generics (Generic)
import Generics.SOP qualified as SOP
import Plutarch.Builtin.Crypto (pblake2b_256)
import Plutarch.Builtin.Value (punValueData)
import Plutarch.LedgerApi.V3
import Plutarch.LedgerApi.V3.Value qualified as Value
import Plutarch.Prelude
import Plutarch.Unsafe (punsafeCoerce)
import Registry.OnChain
import Registry.Treasury (pgovernedAdaConservation, pvalidateTreasurySpend)

data PRegistryAction (s :: S)
  = PInsertAction (Term s (PAsData PContentRef)) (Term s (PAsData PInteger))
  | PUpdateAction (Term s (PAsData PContentRef)) (Term s (PAsData PInteger))
  | PSplitAction (Term s (PAsData PContentRef)) (Term s (PAsData PInteger)) (Term s (PAsData PByteString))
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataStruct PRegistryAction

-- | The node NFT name is blake2b_256(lowerBound). The minting policy must
-- create exactly one root NFT and enforce unique names for new split nodes.
pvalidateRegistrySpend ::
  Term s
    ( PCurrencySymbol
        :--> PTokenName
        :--> PAddress
        :--> PCurrencySymbol
        :--> PScriptContext
        :--> PUnit
    )
pvalidateRegistrySpend = plam $ \govCS govTN govAddress nodeCS ctx ->
  pmatch ctx $ \scriptCtx ->
    pmatch (pscriptContext'scriptInfo scriptCtx) $ \case
      PSpendingScript ownRef datumMaybe -> pmatch datumMaybe $ \case
        PDNothing -> pvalidateTreasurySpend # govCS # govTN # govAddress # ctx
        PDJust datum ->
          let info0 = pscriptContext'txInfo scriptCtx
              allInputs = pmatch info0 $ \i -> pfromData (ptxInfo'inputs i)
              ownInput0 = phead # (pfilter # (plam $ \inputData ->
                pmatch (pfromData inputData) $ \input -> ptxInInfo'outRef input #== ownRef) # allInputs)
              registryAddress = pmatch (pfromData ownInput0) $ \input ->
                pmatch (ptxInInfo'resolved input) $ \out -> ptxOut'address out
              registryDatum = pfromData (punsafeCoerce @(PAsData PRegistryDatum) (pto datum))
              conserved = pgovernedAdaConservation # govCS # govTN # govAddress # registryAddress # ctx
           in pmatch registryDatum $ \case
                PPreimageItem preimageData ->
                  pif ((pvalidPreimage # pfromData preimageData) #&& conserved)
                    (pconstant ()) perror
                PManifestItem manifestData ->
                  pif ((pvalidManifest # pfromData manifestData) #&& conserved)
                    (pconstant ()) perror
                PListItem oldNodeData ->
                  let oldNode = pfromData oldNodeData
                      nodeTN = pmatch oldNode $ \node ->
                        pcon (PTokenName (pblake2b_256 # pfromData (plowerBound node)))
                      info = pscriptContext'txInfo scriptCtx
                      inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
                      outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
                      ownInputs = pfilter # (plam $ \inputData ->
                        pmatch (pfromData inputData) $ \input -> ptxInInfo'outRef input #== ownRef) # inputs
                      ownOutput = pmatch (pfromData (phead # ownInputs)) $ \input -> ptxInInfo'resolved input
                      successors = pfilter # (plam $ \outData ->
                        pmatch (pfromData outData) $ \out ->
                          (ptxOut'address out #== registryAddress)
                            #&& (Value.pvalueOf # nodeCS # nodeTN
                              # (punValueData # pforgetData (ptxOut'value out)) #== 1)) # outputs
                      successor = pfromData (phead # successors)
                      action = pfromData (punsafeCoerce @(PAsData PRegistryAction) (pto (pscriptContext'redeemer scriptCtx)))
                      leftDatum = pmatch successor $ \out ->
                        pmatch (ptxOut'datum out) $ \case
                          POutputDatum inlineDatum ->
                            pmatch (pfromData (punsafeCoerce @(PAsData PRegistryDatum) (pto inlineDatum))) $ \case
                              PListItem newNodeData -> pfromData newNodeData
                              _ -> perror
                          _ -> perror
                      transition = pmatch action $ \case
                        PInsertAction entryData indexData ->
                          (pmatch info $ \i -> Value.pvalueOf # nodeCS # nodeTN
                            # (punValueData # pforgetData (ptxInfo'mint i)) #== 0)
                            #&& (pvalidPackedInsert # oldNode # leftDatum # pfromData entryData # pfromData indexData)
                        PUpdateAction entryData indexData ->
                          (pmatch info $ \i -> Value.pvalueOf # nodeCS # nodeTN
                            # (punValueData # pforgetData (ptxInfo'mint i)) #== 0)
                            #&& (pvalidPackedUpdate # oldNode # leftDatum # pfromData entryData # pfromData indexData)
                        PSplitAction entryData indexData boundaryData ->
                          let rightTN = pcon (PTokenName (pblake2b_256 # pfromData boundaryData))
                              rightOutputs = pfilter # (plam $ \outData ->
                                pmatch (pfromData outData) $ \out ->
                                  (ptxOut'address out #== registryAddress)
                                    #&& (Value.pvalueOf # nodeCS # rightTN
                                      # (punValueData # pforgetData (ptxOut'value out)) #== 1)) # outputs
                              rightOutput = pfromData (phead # rightOutputs)
                              rightDatum = pmatch rightOutput $ \out ->
                                pmatch (ptxOut'datum out) $ \case
                                  POutputDatum inlineDatum ->
                                    pmatch (pfromData (punsafeCoerce @(PAsData PRegistryDatum) (pto inlineDatum))) $ \case
                                      PListItem newNodeData -> pfromData newNodeData
                                      _ -> perror
                                  _ -> perror
                           in (plength # rightOutputs #== 1)
                                #&& (pnot # (nodeTN #== rightTN))
                                #&& (pmatch info $ \i -> Value.pvalueOf # nodeCS # nodeTN
                                  # (punValueData # pforgetData (ptxInfo'mint i)) #== 0)
                                #&& (pmatch info $ \i -> Value.pvalueOf # nodeCS # rightTN
                                  # (punValueData # pforgetData (ptxInfo'mint i)) #== 1)
                                #&& (pvalidPackedSplit # oldNode # leftDatum # rightDatum
                                  # pfromData entryData # pfromData indexData)
                      valid =
                        (plength # ownInputs #== 1)
                          #&& (pmatch ownOutput $ \out ->
                            (ptxOut'address out #== registryAddress)
                              #&& (Value.pvalueOf # nodeCS # nodeTN
                                # (punValueData # pforgetData (ptxOut'value out)) #== 1))
                          #&& (plength # successors #== 1)
                          #&& conserved
                          #&& transition
                   in pif valid (pconstant ()) perror
      _ -> perror
