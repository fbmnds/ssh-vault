
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}

module SSHVault.Vault
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , Host
    , SSHKey (..)
--    , putVaultFile
    , encryptVault
    , decryptVault
    , updateUsers
    , updateVaultEntry
    , updateVault
    )
where

import           SSHVault.SBytes
import           SSHVault.Common

--import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
--import qualified Data.ByteString.Char8 as C
--import qualified Data.ByteString.UTF8 as CU
import qualified Data.ByteArray as BA
import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import           GHC.Generics

--import Turtle



data SSHKey =
  SSHKey { phrase64 :: String
         , key_file :: String
         } deriving (Show, Generic, Eq)
instance JSON.FromJSON SSHKey
instance JSON.ToJSON SSHKey


data User =
  User { user :: String
       , sshkey :: SSHKey
       } deriving (Show, Generic, Eq)
instance JSON.FromJSON User
instance JSON.ToJSON User


type Host = String
data VaultEntry =
  VaultEntry { host  :: Host
        , host_key :: String
        , ip4 :: String
        , ip6 :: String
        , port :: Int
        , users :: [User]
        } deriving (Show, Generic, Eq)
instance JSON.FromJSON VaultEntry
instance JSON.ToJSON VaultEntry


newtype Vault =
  Vault { vault :: [VaultEntry]
    } deriving (Show, Generic, Eq)
instance JSON.FromJSON Vault
instance JSON.ToJSON Vault



updateUsers :: User -> [User] -> [User]
updateUsers u' us = filter (\u'' -> user u'' == un) us ++ [u'] where un = user u'

updateVaultEntry :: [User] -> VaultEntry -> VaultEntry
updateVaultEntry us ve = ve { users = us }

updateVault :: VaultEntry -> Vault -> Vault
updateVault ve v = v { vault = filter (\ve' -> host ve' == hn) (vault v) ++ [ve] } where hn = host ve


decryptVault :: (ToSBytes a, JSON.FromJSON b) => a -> String -> IO b
decryptVault key fn = do
  v <- B.readFile fn
    >>= decryptAES (genAESKey $ SSHVault.SBytes.toText key)
  case B64.decode (toBytes v) of
    Left s' -> error s'
    Right s' -> return . fromMaybe (error "failed to JSON.decode in decryptVault") . JSON.decode $ toLUBytes s'

encryptVault :: BA.ScrubbedBytes -> String -> Vault -> IO ()
encryptVault k fn v =
  encryptAES (genAESKey $ SSHVault.SBytes.toText k) (B64.encode . toBytes $ JSON.encode v)
  >>= \ c' -> B.writeFile fn (toBytes c')
  >> chmodFile ("600" :: String) fn
