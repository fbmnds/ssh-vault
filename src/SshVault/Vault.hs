
--{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}
module SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , Secrets (..)
    , getVaultFile
    , putVaultFile
    , encryptVault
    , decryptVault
    )
where

import SshVault.SBytes

import Crypto.Simple.CTR (encrypt, decrypt)

import Crypto.Hash (hash, SHA256 (..), Digest)
--import Crypto.Hash.Algorithms

import qualified Data.Text as T
import qualified Data.ByteString.Char8 as C
--import qualified Data.ByteString.Lazy as CL
--import qualified Data.ByteString.Lazy.UTF8 as CLU
import qualified Data.ByteString as B
--import qualified Data.ByteString.Internal as BI
import qualified Data.ByteArray as BA

import Data.ByteString.UTF8 as CU

import Data.Maybe (fromMaybe)
--import Data.ByteArray (convert)

import System.IO (readFile, writeFile)

import qualified Data.Aeson as JSON
import GHC.Generics

import Turtle 
    (
--      ExitCode, 
--      w
      s
    , printf
    )


data Secrets =
  Secrets { key_secret :: T.Text
          , key_file :: T.Text
          } deriving (Show, Generic)

instance JSON.FromJSON Secrets
instance JSON.ToJSON Secrets

data User =
  User { user :: T.Text
       , secrets :: Secrets
       } deriving (Show, Generic)

instance JSON.FromJSON User
instance JSON.ToJSON User

data VaultEntry =
  VaultEntry { host  :: T.Text
        , host_key :: T.Text
        , ip4 :: T.Text
        , ip6 :: T.Text
        , port :: Int
        , users :: [User]
        } deriving (Show, Generic)

instance JSON.FromJSON VaultEntry
instance JSON.ToJSON VaultEntry

newtype Vault =
  Vault { vault :: [VaultEntry] 
    } deriving (Show, Generic)

instance JSON.FromJSON Vault
instance JSON.ToJSON Vault
 


genSHA256 :: T.Text -> String
genSHA256 key = 
  let h :: Digest SHA256
      h = hash $ toBytes key in
  show h


genAESKey :: T.Text -> B.ByteString
genAESKey key = CU.take 32 . toBytes $ genSHA256 key


getVaultFile :: String -> IO T.Text
getVaultFile fn = do   
  contents <- System.IO.readFile fn      
  return $ T.pack contents


putVaultFile :: String -> BA.ScrubbedBytes -> Vault -> IO ()
putVaultFile fn k v = encryptVault k v >>= \bs -> writeFile fn $ C.unpack bs


decryptVault :: BA.ScrubbedBytes -> String-> IO Vault
decryptVault key fn = do
  v <- B.readFile fn >>= \v' -> Crypto.Simple.CTR.decrypt (genAESKey $ toText key) v'
  return . fromMaybe (error "failed to decrypt vault") . JSON.decode $ toLUBytes v
 

encryptVault :: BA.ScrubbedBytes -> Vault -> IO B.ByteString
encryptVault k v = Crypto.Simple.CTR.encrypt (genAESKey $ toText k) (toBytes $ JSON.encode v)

