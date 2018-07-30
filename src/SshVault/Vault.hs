
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
--    , putVaultFile
    , encryptVault
    , decryptVault
    , updateUsers
    , updateVaultEntry
    , updateVault
    , genQueue
    )
where

import           SshVault.SBytes
import           SshVault.Common

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
--import qualified Data.ByteString.Char8 as C
--import qualified Data.ByteString.UTF8 as CU
import qualified Data.ByteArray as BA
import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import           GHC.Generics

--import Turtle



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



genQueue :: [VaultEntry] -> Queue
genQueue ves =
  let f' ve = (host ve, users ve) in
  let s1 = fmap f' ves in
  let s2 (h_us :: (Host, [User])) = fmap (fst h_us,) (snd h_us) in
  concatMap s2 s1


updateUsers :: User -> [User] -> [User]
updateUsers u' us = filter (\u'' -> user u'' == un) us ++ [u'] where un = user u'

updateVaultEntry :: [User] -> VaultEntry -> VaultEntry
updateVaultEntry us ve = ve { users = us }

updateVault :: VaultEntry -> Vault -> Vault
updateVault ve v = v { vault = filter (\ve' -> host ve' == hn) (vault v) ++ [ve] } where hn = host ve


decryptVault :: (ToSBytes a, JSON.FromJSON b) => a -> Prelude.FilePath -> IO b
decryptVault key fn = do
  v <- B.readFile fn >>= \v' -> decryptAES (genAESKey $ SshVault.SBytes.toText key) v'
  case B64.decode v of
    Left s' -> error s'
    Right s' -> return . fromMaybe (error "failed to JSON.decode in decryptVault") . JSON.decode $ toLUBytes s'

encryptVault :: BA.ScrubbedBytes -> String -> Vault -> IO ()
encryptVault k fn v =
  encryptAES (genAESKey $ SshVault.SBytes.toText k) (B64.encode . toBytes $ JSON.encode v)
  >>= B.writeFile fn
  >> chmodFile ("600" :: String) fn
