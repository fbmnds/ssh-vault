{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}

module SshVault.SBytes where


import qualified Data.Text as T
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as CL
import qualified Data.ByteString.Lazy.UTF8 as CLU
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteArray as BA
--import Data.ByteArray (ByteArrayAccess)

class (Eq a) => ToSBytes a where
  toSBytes  :: a -> BA.ScrubbedBytes
  toString  :: a -> String
  toBytes   :: a -> B.ByteString
  toLUBytes :: a -> CLU.ByteString
  toText    :: a -> T.Text

instance ToSBytes B.ByteString where
  toSBytes  = BA.convert
  toString  = C.unpack
  toBytes   = id
  toLUBytes = CLU.fromString . C.unpack -- unsafe for non-ASCCII ?
  toText    = T.pack . C.unpack

instance ToSBytes T.Text where
  toSBytes = BA.convert . C.pack . T.unpack 
  toString = T.unpack
  toBytes  = BA.convert . toSBytes
  toLUBytes = toLUBytes . toBytes 
  toText    = id


instance ToSBytes String where
  toSBytes = BA.convert . C.pack 
  toString = id
  toBytes  = C.pack
  toLUBytes = CLU.fromString
  toText    = T.pack


instance ToSBytes BA.Bytes where
  toSBytes = BA.convert
  toString = C.unpack . BA.convert
  toBytes  = BA.convert
  toLUBytes = toLUBytes . toBytes
  toText    = T.pack . C.unpack . toBytes


instance ToSBytes BA.ScrubbedBytes where
  toSBytes = BA.convert
  toString = C.unpack . BA.convert
  toBytes  = BA.convert
  toLUBytes = toLUBytes . toBytes
  toText    = T.pack . C.unpack . toBytes


instance ToSBytes CLU.ByteString where
  toSBytes = BA.convert . C.pack . map BI.w2c . CL.unpack
  toString = map BI.w2c . CL.unpack
  toBytes  = BA.convert . C.pack . map BI.w2c . CL.unpack
  toLUBytes = id
  toText    = T.pack . C.unpack . toBytes

