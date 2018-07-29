
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
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.UTF8 as CU
import qualified Data.ByteArray as BA
import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import           GHC.Generics

import Turtle

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
putVaultFile k fn v = encryptVault k v >>= B.writeFile fn


--decryptVault :: BA.ScrubbedBytes -> String-> IO Either _
decryptVault key fn = do
  v <- B.readFile fn >>= \v' -> decryptAES (genAESKey $ SshVault.SBytes.toText key) v'
  case B64.decode $ toBytes v of 
    Left s' -> error s'
    Right s' -> return . fromMaybe (error "failed to JSON.decode in decryptVault") . JSON.decode $ toLUBytes s'
 

encryptVault :: BA.ScrubbedBytes -> Vault -> IO B.ByteString
encryptVault k v = do
  printf w (JSON.encode v)
  encryptAES (genAESKey $ SshVault.SBytes.toText k) (B64.encode . toBytes $ JSON.encode v)

