
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DeriveGeneric #-}
module SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , Secrets (..)
    , Queue
    , QueueEntry
    , putVaultFile
    , encryptVault
    , decryptVault
    , getHosts
    , getQueue
    )
where

import           SshVault.SBytes
import           SshVault.Common

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.UTF8 as CU
import qualified Data.ByteArray as BA
import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import           GHC.Generics

import           System.IO (writeFile)



data Secrets =
  Secrets { key_secret :: T.Text
          , key_file :: T.Text
          } deriving (Show, Generic, Eq)
instance JSON.FromJSON Secrets
instance JSON.ToJSON Secrets


data User =
  User { user :: T.Text
       , secrets :: Secrets
       } deriving (Show, Generic, Eq)


instance JSON.FromJSON User
instance JSON.ToJSON User

type Host = T.Text

data VaultEntry =
  VaultEntry { host  :: Host
        , host_key :: T.Text
        , ip4 :: T.Text
        , ip6 :: T.Text
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
 
type QueueEntry = (Host, User)
type Queue = [QueueEntry]

getHosts :: Vault -> [T.Text]
getHosts = fmap host . vault


getQueue :: [VaultEntry] -> Queue
getQueue ves = 
  let f ve = (host ve, users ve) in
  let s1 = fmap f ves in
  let s2 (h_us :: (Host, [User])) = fmap (fst h_us,) (snd h_us) in 
  concatMap s2 s1


putVaultFile :: BA.ScrubbedBytes -> String -> Vault -> IO ()
putVaultFile k fn v = encryptVault k v >>= \bs -> writeFile fn $ C.unpack bs


decryptVault :: BA.ScrubbedBytes -> String-> IO Vault
decryptVault key fn = do
  v <- B.readFile fn >>= \v' -> decryptAES (genAESKey $ toText key) v'
  return . fromMaybe (error "failed to decrypt vault") . JSON.decode $ toLUBytes v
 

encryptVault :: BA.ScrubbedBytes -> Vault -> IO B.ByteString
encryptVault k v = encryptAES (genAESKey $ toText k) (toBytes $ JSON.encode v)

