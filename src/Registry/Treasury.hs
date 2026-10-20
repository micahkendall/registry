{-# LANGUAGE LambdaCase #-}

-- | ADA conservation for no-datum treasury UTxOs at the registry address.
module Registry.Treasury (pgovernedAdaConservation, pvalidateTreasurySpend) where

import Plutarch.Builtin.Value (punValueData)
import Plutarch.LedgerApi.Value qualified as LedgerValue
import Plutarch.LedgerApi.V3
import Plutarch.LedgerApi.V3.Value qualified as Value
import Plutarch.Prelude

-- | Every spend at the registry address must pass this whole-transaction ADA
-- accounting rule. The governance NFT must be spent from its script address.
pgovernedAdaConservation ::
  Term s (PCurrencySymbol :--> PTokenName :--> PAddress :--> PAddress :--> PScriptContext :--> PBool)
pgovernedAdaConservation = phoistAcyclic $ plam $ \govCS govTN govAddress registryAddress ctx ->
  pmatch ctx $ \scriptCtx ->
    let info = pscriptContext'txInfo scriptCtx
        inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
        outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
        governingInputs = pfilter # (plam $ \inputData ->
          pmatch (pfromData inputData) $ \input ->
            pmatch (ptxInInfo'resolved input) $ \out ->
              (ptxOut'address out #== govAddress)
                #&& (Value.pvalueOf # govCS # govTN # (punValueData # pforgetData (ptxOut'value out)) #== 1)) # inputs
        inputAda = pfoldl # (plam $ \total inputData ->
          pmatch (pfromData inputData) $ \input ->
            pmatch (ptxInInfo'resolved input) $ \out ->
              pif (ptxOut'address out #== registryAddress)
                (total + Value.plovelaceValueOf # (punValueData # pforgetData (ptxOut'value out)))
                total) # 0 # inputs
        outputAda = pfoldl # (plam $ \total outData ->
          pmatch (pfromData outData) $ \out ->
            pif (ptxOut'address out #== registryAddress)
              (total + Value.plovelaceValueOf # (punValueData # pforgetData (ptxOut'value out)))
              total) # 0 # outputs
        fee = pmatch info $ \i -> pto (pfromData (ptxInfo'fee i))
        donation = pmatch info $ \i ->
          pmatch (ptxInfo'treasuryDonation i) $ \case
            PDJust amount -> pto (pfromData amount)
            PDNothing -> 0
     in (plength # governingInputs #== 1)
          #&& (inputAda #<= outputAda + fee + donation)

-- | A treasury UTxO contains ADA only and no datum. An authorized transaction
-- may move its ADA into registry/preimage outputs at the same script address,
-- or spend it as Cardano fees/treasury donation. Registry script ADA may not
-- fund external outputs: all controlled inputs must be covered by controlled
-- outputs plus the fee and treasury donation. External inputs may add funds.
pvalidateTreasurySpend ::
  Term s
    ( PCurrencySymbol
        :--> PTokenName
        :--> PAddress
        :--> PScriptContext
        :--> PUnit
    )
pvalidateTreasurySpend = plam $ \govCS govTN govAddress ctx ->
  pmatch ctx $ \scriptCtx ->
    pmatch (pscriptContext'scriptInfo scriptCtx) $ \case
      PSpendingScript ownRef datumMaybe -> pmatch datumMaybe $ \case
        PDNothing ->
          let info = pscriptContext'txInfo scriptCtx
              inputs = pmatch info $ \i -> pfromData (ptxInfo'inputs i)
              outputs = pmatch info $ \i -> pfromData (ptxInfo'outputs i)
              ownInputs = pfilter # (plam $ \inputData ->
                pmatch (pfromData inputData) $ \input -> ptxInInfo'outRef input #== ownRef) # inputs
              ownOutput = pmatch (pfromData (phead # ownInputs)) $ \input -> ptxInInfo'resolved input
              registryAddress = pmatch ownOutput $ \out -> ptxOut'address out
              onlyAda = pmatch ownOutput $ \out ->
                let v = punValueData # pforgetData (ptxOut'value out)
                    amount = Value.plovelaceValueOf # v
                 in (amount #> 0)
                      #&& (Value.ptoSortedValue v #== pdata (LedgerValue.psingletonSortedValue # LedgerValue.padaSymbol # LedgerValue.padaToken # amount))
              valid =
                (plength # ownInputs #== 1)
                  #&& (pmatch ownOutput $ \out -> ptxOut'address out #== registryAddress)
                  #&& (pmatch ownOutput $ \out -> pmatch (ptxOut'datum out) $ \case
                    PNoOutputDatum -> pconstant True
                    _ -> pconstant False)
                  #&& onlyAda
                  #&& (pgovernedAdaConservation # govCS # govTN # govAddress # registryAddress # ctx)
           in pif valid (pconstant ()) perror
        _ -> perror
      _ -> perror
