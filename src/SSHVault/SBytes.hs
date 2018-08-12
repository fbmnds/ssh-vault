
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}

module SSHVault.SBytes
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , HostName
    , HostData (..)
    , UserName
    , SSHKey (..)
    , MasterKey (..)
    , AESMasterKey (..)
    , KeyPhrase (..)
    , ToSBytes (..)
    )
where

import qualified Data.Text as T
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as CL
import qualified Data.ByteString.Lazy.UTF8 as CLU
import qualified Data.Aeson as JSON
import           GHC.Generics

newtype MasterKey    = MasterKey    { getMasterKey    :: BA.ScrubbedBytes } deriving (Show, Generic, Eq)
newtype AESMasterKey = AESMasterKey { getAESMasterKey :: BA.ScrubbedBytes } deriving (Show, Generic, Eq)
newtype KeyPhrase   = KeyPhrase   { getKeyPhrase   :: BA.ScrubbedBytes } deriving (Show, Generic, Eq)

--type KeyPhrase64 = String
newtype KeyPhrase64 =
  KeyPhrase64 { getKeyPhrase64 :: String
              } deriving (Show, Generic, Eq)
instance JSON.FromJSON KeyPhrase64
instance JSON.ToJSON   KeyPhrase64


type UTC = String
data SSHKey =
  SSHKey { phrase64    :: KeyPhrase64
         , key_file    :: String
         , key_priv    :: String
         , key_pub     :: String
         , created_at  :: UTC
         } deriving (Show, Generic, Eq)
instance JSON.FromJSON SSHKey
instance JSON.ToJSON   SSHKey
instance Ord           SSHKey where
  (SSHKey _ _ _ _ c1) `compare` (SSHKey _ _ _ _ c2) = c1 `compare` c2


type UserName = String
data User =
  User { user        :: UserName
       , sshkeys     :: [SSHKey]
       , created_at  :: UTC
       } deriving (Show, Generic, Eq)
instance JSON.FromJSON User
instance JSON.ToJSON   User


type HostName = String
data HostData =
  HostData { host_key   :: String
           , ip4        :: String
           , ip6        :: String
           , port       :: Int
           , created_at :: UTC
           } deriving (Show, Generic, Eq)
instance JSON.FromJSON HostData
instance JSON.ToJSON   HostData


data VaultEntry =
  VaultEntry { host       :: HostName
             , host_data  :: HostData
             , users      :: [User]
             , created_at :: UTC
             } deriving (Show, Generic, Eq)
instance JSON.FromJSON VaultEntry
instance JSON.ToJSON   VaultEntry


newtype Vault =
  Vault { vault :: [VaultEntry]
        } deriving (Show, Generic, Eq)
instance JSON.FromJSON Vault
instance JSON.ToJSON   Vault

class (Eq a) => ToSBytes a where
  toSBytes       :: a -> BA.ScrubbedBytes
  toString       :: a -> String
  toBytes        :: a -> B.ByteString
  toLUBytes      :: a -> CLU.ByteString
  toText         :: a -> T.Text
  toMasterKey    :: a -> MasterKey
  toAESMasterKey :: a -> AESMasterKey
  toKeyPhrase    :: a -> KeyPhrase
  toKeyPhrase64  :: a -> KeyPhrase64 -- type conversion without en-/decoding

instance ToSBytes B.ByteString where
  toSBytes       = BA.convert
  toString       = C.unpack
  toBytes        = id
  toLUBytes      = CLU.fromString . C.unpack -- unsafe for non-ASCCII ?
  toText         = T.pack . C.unpack
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes T.Text where
  toSBytes       = BA.convert . C.pack . T.unpack
  toString       = T.unpack
  toBytes        = BA.convert . toSBytes
  toLUBytes      = toLUBytes . toBytes
  toText         = id
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes String where
  toSBytes       = BA.convert . C.pack
  toString       = id
  toBytes        = C.pack
  toLUBytes      = CLU.fromString
  toText         = T.pack
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes BA.Bytes where
  toSBytes       = BA.convert
  toString       = C.unpack . BA.convert
  toBytes        = BA.convert
  toLUBytes      = toLUBytes . toBytes
  toText         = T.pack . C.unpack . toBytes
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes CLU.ByteString where
  toSBytes       = BA.convert . C.pack . map BI.w2c . CL.unpack
  toString       = map BI.w2c . CL.unpack
  toBytes        = BA.convert . C.pack . map BI.w2c . CL.unpack
  toLUBytes      = id
  toText         = T.pack . C.unpack . toBytes
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes BA.ScrubbedBytes where
  toSBytes       = BA.convert
  toString       = C.unpack . BA.convert
  toBytes        = BA.convert
  toLUBytes      = toLUBytes . toBytes
  toText         = T.pack . C.unpack . toBytes
  toMasterKey    = MasterKey . toSBytes
  toAESMasterKey = AESMasterKey . toSBytes
  toKeyPhrase    = KeyPhrase . toSBytes
  toKeyPhrase64  = KeyPhrase64 . toString

instance ToSBytes MasterKey where
  toSBytes       = getMasterKey
  toString       = C.unpack . BA.convert . getMasterKey
  toBytes        = BA.convert . getMasterKey
  toLUBytes      = toLUBytes . toBytes . getMasterKey
  toText         = T.pack . C.unpack . toBytes . getMasterKey
  toMasterKey    = id
  toAESMasterKey = AESMasterKey . toSBytes . getMasterKey
  toKeyPhrase    = KeyPhrase . toSBytes . getMasterKey
  toKeyPhrase64  = KeyPhrase64 . toString . getMasterKey

instance ToSBytes AESMasterKey where
  toSBytes       = getAESMasterKey
  toString       = C.unpack . BA.convert . getAESMasterKey
  toBytes        = BA.convert . getAESMasterKey
  toLUBytes      = toLUBytes . toBytes . getAESMasterKey
  toText         = T.pack . C.unpack . toBytes . getAESMasterKey
  toMasterKey    = MasterKey . toSBytes . getAESMasterKey
  toAESMasterKey = id
  toKeyPhrase    = KeyPhrase . toSBytes . getAESMasterKey
  toKeyPhrase64  = KeyPhrase64 . toString . getAESMasterKey

instance ToSBytes KeyPhrase where
  toSBytes       = getKeyPhrase
  toString       = C.unpack . BA.convert . getKeyPhrase
  toBytes        = BA.convert . getKeyPhrase
  toLUBytes      = toLUBytes . toBytes . getKeyPhrase
  toText         = T.pack . C.unpack . toBytes . getKeyPhrase
  toMasterKey    = MasterKey . toSBytes . getKeyPhrase
  toAESMasterKey = AESMasterKey . toSBytes . getKeyPhrase
  toKeyPhrase    = id
  toKeyPhrase64  = KeyPhrase64 . toString . getKeyPhrase

instance ToSBytes KeyPhrase64 where
  toSBytes       = BA.convert . C.pack . getKeyPhrase64
  toString       = getKeyPhrase64
  toBytes        = C.pack . getKeyPhrase64
  toLUBytes      = CLU.fromString . getKeyPhrase64
  toText         = T.pack . getKeyPhrase64
  toMasterKey    = MasterKey . toSBytes . getKeyPhrase64
  toAESMasterKey = AESMasterKey . toSBytes . getKeyPhrase64
  toKeyPhrase    = KeyPhrase . toSBytes . getKeyPhrase64
  toKeyPhrase64  = id
