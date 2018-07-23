{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}

module SshVault.SBytes where


import qualified Data.Text as T
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString as B
import qualified Data.ByteArray as BA

class (Eq a) => ToSBytes a where
  toSBytes :: a -> BA.ScrubbedBytes
  toString :: a -> String


instance ToSBytes B.ByteString where
  toSBytes = BA.convert
  toString = C.unpack


instance ToSBytes T.Text where
  toSBytes = BA.convert . C.pack . T.unpack 
  toString = T.unpack


instance ToSBytes String where
  toSBytes = BA.convert . C.pack . T.unpack . T.pack 
  toString = id
