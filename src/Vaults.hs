
--{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}
module Vaults 
  ( Vault
  , VaultEntry
  , Secrets
  , getVaultFile'
  , putVaultFile'
  , getVaultFile
  , putVaultFile       
  , encryptVault
  , decryptVault
  ) 
where

import Crypto.Simple.CBC (encrypt, decrypt)

import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 (pack, unpack)
import Data.Text (Text, pack, unpack)

import System.IO (readFile, writeFile)

import Data.Aeson
import GHC.Generics

import Turtle (ExitCode)


data Secrets =
  Secrets { key_secret :: Text
          , key_file :: Text
          } deriving (Show, Generic)

instance FromJSON Secrets
instance ToJSON Secrets

data VaultEntry =
  VaultEntry { users :: [Text]
        , host  :: Text
        , host_key :: Text
        , ip4 :: Text
        , ip6 :: Text
        , port :: Int
        , secrets :: [Secrets]
        } deriving (Show, Generic)

instance FromJSON VaultEntry
instance ToJSON VaultEntry

newtype Vault =
  Vault { vault :: [VaultEntry] 
    } deriving (Show, Generic)

instance FromJSON Vault
instance ToJSON Vault


getVaultFile :: String -> IO Text
getVaultFile fn = do   
  contents <- readFile fn      
  return $ Data.Text.pack contents


putVaultFile :: String -> Text -> IO ()
putVaultFile fn vaultbs = 
  writeFile fn (Data.Text.unpack vaultbs)


getVaultFile' :: String -> IO ByteString
getVaultFile' fn = do   
  contents <- readFile fn      
  return $ Data.ByteString.Lazy.Char8.pack contents


putVaultFile' :: String -> ByteString -> IO ()
putVaultFile' fn vaultbs = 
  writeFile fn (Data.ByteString.Lazy.Char8.unpack vaultbs)
  

decryptVault :: Text -> ByteString -> Vault
decryptVault key vaultbs = undefined

encryptVault :: Text -> Vault -> ByteString
encryptVault key vault = undefined


-- > import Crypto.Simple.CBC (encrypt, decrypt) 
-- > import Data.ByteString.Char8 (pack)
-- > let key = pack "my secret key"
-- > let msg = pack "this is a message"
-- > encrypt key msg >>= \secretMsg -> decrypt key secretMsg
-- "this is a message"