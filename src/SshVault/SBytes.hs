{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}

module SshVault.SBytes where


import qualified Data.Text as T
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as CL
import qualified Data.ByteString.Lazy.UTF8 as CLU
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteArray as BA
--import Data.ByteArray (ByteArrayAccess)

class (Eq a) => ToSBytes a where
  toSBytes :: a -> BA.ScrubbedBytes
  toString :: a -> String
  toBytes  :: a -> B.ByteString
  toLUBytes :: a -> CLU.ByteString


instance ToSBytes B.ByteString where
  toSBytes = BA.convert
  toString = C.unpack
  toBytes  = id
  toLUBytes = CLU.fromString . C.unpack


instance ToSBytes T.Text where
  toSBytes = BA.convert . C.pack . T.unpack 
  toString = T.unpack
  toBytes  = BA.convert . toSBytes
  toLUBytes = undefined


instance ToSBytes String where
  toSBytes = BA.convert . C.pack 
  toString = id
  toBytes  = C.pack
  toLUBytes = undefined -- B.map BI.c2w


instance ToSBytes BA.Bytes where
  toSBytes = BA.convert
  toString = C.unpack . BA.convert
  toBytes  = BA.convert
  toLUBytes = undefined


instance ToSBytes BA.ScrubbedBytes where
  toSBytes = BA.convert
  toString = C.unpack . BA.convert
  toBytes  = BA.convert
  toLUBytes = toLUBytes . toBytes

