{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Short qualified as SBS
import Data.Char (isHexDigit)
import Numeric (readHex)
import Plutarch.Internal.Term (Config (NoTracing), compile)
import Plutarch.Prelude
import Plutarch.Script (serialiseScript)
import PlutusLedgerApi.V3 qualified as V3
import Registry.Governance (pvalidateGovernanceSpend)
import Registry.Policies (pvalidateGovernanceMint, pvalidateNodeMint)
import Registry.Validator (pvalidateRegistrySpend)
import System.Environment (getArgs)
import System.Exit (die)

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["governance", out] -> save out "Registry governance multisig" pvalidateGovernanceSpend
    ["governance-policy", seed, token, governanceHash, out] -> do
      ref <- parseRef seed
      tn <- tokenName token
      address <- scriptAddress governanceHash
      save out "One-shot governance NFT policy"
        (pvalidateGovernanceMint # pconstant ref # pconstant tn # pconstant address)
    ["node-policy", seed, governanceCS, token, governanceHash, out] -> do
      ref <- parseRef seed
      cs <- currencySymbol governanceCS
      tn <- tokenName token
      address <- scriptAddress governanceHash
      save out "Root and split node NFT policy"
        (pvalidateNodeMint # pconstant ref # pconstant cs # pconstant tn # pconstant address)
    ["registry", governanceCS, token, governanceHash, nodeCS, out] -> do
      cs <- currencySymbol governanceCS
      tn <- tokenName token
      address <- scriptAddress governanceHash
      nodeSymbol <- currencySymbol nodeCS
      save out "Packed native-token registry"
        (pvalidateRegistrySpend # pconstant cs # pconstant tn # pconstant address # pconstant nodeSymbol)
    _ -> die $ unlines
      [ "Usage:"
      , "  registry-export governance OUTPUT.plutus"
      , "  registry-export governance-policy SEED_TXID#INDEX TOKEN_HEX GOV_SCRIPT_HASH OUTPUT.plutus"
      , "  registry-export node-policy SEED_TXID#INDEX GOV_POLICY_ID TOKEN_HEX GOV_SCRIPT_HASH OUTPUT.plutus"
      , "  registry-export registry GOV_POLICY_ID TOKEN_HEX GOV_SCRIPT_HASH NODE_POLICY_ID OUTPUT.plutus"
      ]

save :: FilePath -> String -> (forall s. Term s a) -> IO ()
save out description term =
  case compile NoTracing term of
    Left err -> die (show err)
    Right script -> do
      let serialized = serialiseScript script
      case (V3.deserialiseScript (V3.MajorProtocolVersion 11) serialized
        :: Either V3.ScriptDecodeError V3.ScriptForEvaluation) of
        Left err -> die ("ledger rejected exported script: " <> show err)
        Right _ -> do
          let wrapped = SBS.fromShort serialized
              envelope = "{\"type\":\"PlutusScriptV3\",\"description\":\"" <> description
                <> "\",\"cborHex\":\"" <> encodeHex wrapped <> "\"}\n"
          writeFile out envelope
          putStrLn (description <> ": " <> show (BS.length wrapped) <> " serialized bytes -> " <> out)

parseRef :: String -> IO V3.TxOutRef
parseRef input = case break (== '#') input of
  (txid, '#' : indexText) -> do
    hash <- exactBytes 32 txid
    case reads indexText of
      [(index, "")] | index >= (0 :: Integer) ->
        pure (V3.TxOutRef (V3.TxId (V3.toBuiltin hash)) index)
      _ -> die "seed output index must be nonnegative"
  _ -> die "seed must be TXID#INDEX"

currencySymbol :: String -> IO V3.CurrencySymbol
currencySymbol encoded = V3.CurrencySymbol . V3.toBuiltin <$> exactBytes 28 encoded

tokenName :: String -> IO V3.TokenName
tokenName encoded = V3.TokenName . V3.toBuiltin <$> bytesUpTo 32 encoded

scriptAddress :: String -> IO V3.Address
scriptAddress encoded = do
  hash <- exactBytes 28 encoded
  pure (V3.Address (V3.ScriptCredential (V3.ScriptHash (V3.toBuiltin hash))) Nothing)

exactBytes :: Int -> String -> IO ByteString
exactBytes count encoded = do
  bytes <- parseHex encoded
  if BS.length bytes == count then pure bytes else die ("expected " <> show count <> " bytes of hex")

bytesUpTo :: Int -> String -> IO ByteString
bytesUpTo count encoded = do
  bytes <- parseHex encoded
  if BS.length bytes <= count then pure bytes else die ("expected at most " <> show count <> " bytes of hex")

parseHex :: String -> IO ByteString
parseHex input
  | odd (length input) || not (all isHexDigit input) = die "invalid hexadecimal value"
  | otherwise = pure $ BS.pack $ go input
  where
    go [] = []
    go (a : b : rest) = fromIntegral (fst (head (readHex [a, b]))) : go rest
    go _ = error "unreachable odd hex"

encodeHex :: ByteString -> String
encodeHex = concatMap encodeByte . BS.unpack
  where
    digits = "0123456789abcdef"
    encodeByte byte = [digits !! fromIntegral (byte `shiftR` 4), digits !! fromIntegral (byte .&. 15)]
