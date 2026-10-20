{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Three datum variants at the registry address: packed list nodes,
-- independently uploaded preimages, and segment manifests. No datum denotes
-- an ADA treasury UTxO.
module Registry.OnChain
  ( PContentRef (..)
  , PPackedNode (..)
  , PPreimage (..)
  , PRegistryDatum (..)
  , psegmentHash
  , pvalidPreimage
  , pvalidManifest
  , pvalidPackedInsert
  , pvalidPackedSplit
  , pvalidPackedUpdate
  ) where

import GHC.Generics (Generic)
import Generics.SOP qualified as SOP
import Plutarch.Builtin.Crypto (pblake2b_256)
import Plutarch.Builtin.Integer (pquotientInteger)
import Plutarch.Prelude

-- | A complete CIP-26 JSON document is committed by its full Blake2b-256
-- hash. A zero byte count and empty hash list mean the segment layout will
-- arrive in a separate permissionless manifest UTxO. Otherwise the node
-- commits its layout directly. Every segment preimage can be published
-- independently, including for a document up to 380,000 bytes.
data PContentRef (s :: S) = PContentRef
  { psubject :: Term s (PAsData PByteString)
  , pcontentHash :: Term s (PAsData PByteString)
  , pcontentBytes :: Term s (PAsData PInteger)
  , psegmentHashes :: Term s (PAsData (PBuiltinList (PAsData PByteString)))
  }
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData, PEq)
  deriving (PlutusType) via DeriveAsDataRec PContentRef

-- | One linked-list UTxO packs multiple sorted subjects in the half-open
-- interval [lowerBound,nextBound). The registry starts at the empty-byte
-- sentinel and ends at 61 bytes of 0xff (above every valid subject).
-- A transaction that fills a node must split it into two nodes while preserving
-- the sorted union of entries.
data PPackedNode (s :: S) = PPackedNode
  { plowerBound :: Term s (PAsData PByteString)
  , pnextBound :: Term s (PAsData PByteString)
  , pentries :: Term s (PAsData (PBuiltinList (PAsData PContentRef)))
  }
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData, PEq)
  deriving (PlutusType) via DeriveAsDataRec PPackedNode

data PPreimage (s :: S) = PPreimage
  { ppreimageSubject :: Term s (PAsData PByteString)
  , ppreimageIndex :: Term s (PAsData PInteger)
  , ppreimageHash :: Term s (PAsData PByteString)
  , ppreimageBytes :: Term s (PAsData PByteString)
  }
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData, PEq)
  deriving (PlutusType) via DeriveAsDataRec PPreimage

data PRegistryDatum (s :: S)
  = PListItem (Term s (PAsData PPackedNode))
  | PPreimageItem (Term s (PAsData PPreimage))
  | PManifestItem (Term s (PAsData PContentRef))
  deriving stock (Generic)
  deriving anyclass (SOP.Generic, PIsData)
  deriving (PlutusType) via DeriveAsDataStruct PRegistryDatum

psegmentHash :: Term s (PByteString :--> PByteString)
psegmentHash = phoistAcyclic $ plam $ \bytes ->
  pblake2b_256 # (pconstant "\x01" <> bytes)

pvalidPreimage :: Term s (PPreimage :--> PBool)
pvalidPreimage = phoistAcyclic $ plam $ \preimage ->
  pmatch preimage $ \item ->
    let payload = pfromData (ppreimageBytes item)
        subject = pfromData (ppreimageSubject item)
     in (plengthBS # subject #>= 28)
          #&& (plengthBS # subject #<= 60)
          #&& (pfromData (ppreimageIndex item) #>= 0)
          #&& (pfromData (ppreimageIndex item) #< 32)
          #&& (plengthBS # payload #> 0)
          #&& (plengthBS # payload #<= 12000)
          #&& (ppreimageHash item #== pdata (psegmentHash # payload))

pvalidContentRef :: Term s (PContentRef :--> PBool)
pvalidContentRef = phoistAcyclic $ plam $ \reference ->
  pmatch reference $ \ref ->
    let subject = pfromData (psubject ref)
        byteCount = pfromData (pcontentBytes ref)
        hashes = pfromData (psegmentHashes ref)
     in (plengthBS # subject #>= 28)
          #&& (plengthBS # subject #<= 60)
          #&& (plengthBS # pfromData (pcontentHash ref) #== 32)
          #&& (((byteCount #== 0) #&& (plength # hashes #== 0))
            #|| ((byteCount #> 0)
              #&& (byteCount #<= 380000)
              #&& (plength # hashes #== pquotientInteger # (byteCount + 11999) # 12000)
              #&& (plength # hashes #<= 32)
              #&& (pall # (plam $ \hashData -> plengthBS # pfromData hashData #== 32) # hashes)))

-- | A third party can publish the segment layout after a hash-only node is
-- inserted. The full content hash is verified by clients after reconstruction.
pvalidManifest :: Term s (PContentRef :--> PBool)
pvalidManifest = phoistAcyclic $ plam $ \reference ->
  pmatch reference $ \ref ->
    (pfromData (pcontentBytes ref) #> 0) #&& (pvalidContentRef # reference)

-- | Verify a local insert into a packed node. A separate transaction policy
-- must authenticate the list NFT, preserve the output address, and govern
-- replacement/split operations. The supplied insertion index is checked
-- against exact list reconstruction, so existing entries cannot be changed.
pvalidPackedInsert :: Term s (PPackedNode :--> PPackedNode :--> PContentRef :--> PInteger :--> PBool)
pvalidPackedInsert = phoistAcyclic $ plam $ \old new entry index ->
  pmatch old $ \oldNode ->
    pmatch new $ \newNode ->
      pmatch entry $ \newEntry ->
        let key = pfromData (psubject newEntry)
            oldEntries = pfromData (pentries oldNode)
            newEntries = pfromData (pentries newNode)
            ordered = (pfixHoisted #$ plam $ \self previous rest ->
              pelimList
                (\refData tailEntries ->
                  pmatch (pfromData refData) $ \ref ->
                    let subject = pfromData (psubject ref)
                     in (previous #< subject)
                          #&& (subject #< pfromData (pnextBound oldNode))
                          #&& (self # subject # tailEntries))
                (pconstant True)
                rest) # (pconstant "") # newEntries
            expected = (pfixHoisted #$ plam $ \self n rest ->
              pif (n #== 0)
                (pcons # pdata entry # rest)
                (pelimList
                  (\first tailEntries -> pcons # first # (self # (n - 1) # tailEntries))
                  perror
                  rest)) # index # oldEntries
         in (index #>= 0)
              #&& (index #<= plength # oldEntries)
              #&& (plength # newEntries #<= 8)
              #&& (plowerBound oldNode #== plowerBound newNode)
              #&& (pnextBound oldNode #== pnextBound newNode)
              #&& (pfromData (plowerBound oldNode) #<= key)
              #&& (key #< pfromData (pnextBound oldNode))
              #&& (pvalidContentRef # entry)
              #&& ordered
              #&& (pall # (plam $ \refData ->
                    pmatch (pfromData refData) $ \ref ->
                      pfromData (plowerBound oldNode) #<= pfromData (psubject ref)) # newEntries)
              #&& (newEntries #== expected)

-- | An exact split of a full node after inserting one content reference.
-- The right node begins at its first subject. Neither old entry may change;
-- both successor nodes must be nonempty and their ordered concatenation must
-- equal the old entries with exactly one insertion.
pvalidPackedSplit :: Term s (PPackedNode :--> PPackedNode :--> PPackedNode :--> PContentRef :--> PInteger :--> PBool)
pvalidPackedSplit = phoistAcyclic $ plam $ \old left right entry index ->
  pmatch old $ \oldNode ->
    pmatch left $ \leftNode ->
      pmatch right $ \rightNode ->
        let oldEntries = pfromData (pentries oldNode)
            leftEntries = pfromData (pentries leftNode)
            rightEntries = pfromData (pentries rightNode)
            combined = pfoldr # (plam $ \ref acc -> pcons # ref # acc) # rightEntries # leftEntries
            entryKey = pmatch entry $ \ref -> pfromData (psubject ref)
            expected = (pfixHoisted #$ plam $ \self n rest ->
              pif (n #== 0)
                (pcons # pdata entry # rest)
                (pelimList
                  (\first tailEntries -> pcons # first # (self # (n - 1) # tailEntries))
                  perror
                  rest)) # index # oldEntries
            ordered = (pfixHoisted #$ plam $ \self previous rest ->
              pelimList
                (\refData tailEntries ->
                  pmatch (pfromData refData) $ \ref ->
                    let subject = pfromData (psubject ref)
                     in (previous #< subject) #&& (self # subject # tailEntries))
                (pconstant True)
                rest) # (pconstant "") # combined
            boundary = pmatch (pfromData (phead # rightEntries)) $ \ref -> psubject ref
         in (index #>= 0)
              #&& (index #<= plength # oldEntries)
              #&& (plength # oldEntries #== 8)
              #&& (plength # leftEntries #> 0)
              #&& (plength # rightEntries #> 0)
              #&& (plength # leftEntries #<= 8)
              #&& (plength # rightEntries #<= 8)
              #&& (plowerBound leftNode #== plowerBound oldNode)
              #&& (pnextBound leftNode #== boundary)
              #&& (plowerBound rightNode #== boundary)
              #&& (pnextBound rightNode #== pnextBound oldNode)
              #&& (pfromData (plowerBound oldNode) #<= entryKey)
              #&& (pfromData (pnextBound oldNode) #> entryKey)
              #&& (pvalidContentRef # entry)
              #&& ordered
              #&& (combined #== expected)

-- | Replace exactly one subject's content commitment without changing its
-- sorted position or any other entry. Governance authorizes the replacement;
-- CIP-26 sequence and signature semantics remain in the committed JSON.
pvalidPackedUpdate :: Term s (PPackedNode :--> PPackedNode :--> PContentRef :--> PInteger :--> PBool)
pvalidPackedUpdate = phoistAcyclic $ plam $ \old new replacement index ->
  pmatch old $ \oldNode ->
    pmatch new $ \newNode ->
      let oldEntries = pfromData (pentries oldNode)
          newEntries = pfromData (pentries newNode)
          oldEntry = (pfixHoisted #$ plam $ \self n rest ->
            pif (n #== 0)
              (pfromData (phead # rest))
              (self # (n - 1) # (ptail # rest))) # index # oldEntries
          expected = (pfixHoisted #$ plam $ \self n rest ->
            pif (n #== 0)
              (pcons # pdata replacement # (ptail # rest))
              (pelimList
                (\first tailEntries -> pcons # first # (self # (n - 1) # tailEntries))
                perror
                rest)) # index # oldEntries
          sameSubject = pmatch oldEntry $ \refOld ->
            pmatch replacement $ \refNew -> psubject refOld #== psubject refNew
       in (index #>= 0)
            #&& (index #< plength # oldEntries)
            #&& (plowerBound oldNode #== plowerBound newNode)
            #&& (pnextBound oldNode #== pnextBound newNode)
            #&& (plength # oldEntries #== plength # newEntries)
            #&& sameSubject
            #&& (pvalidContentRef # replacement)
            #&& (newEntries #== expected)
