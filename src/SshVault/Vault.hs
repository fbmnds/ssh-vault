
--{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}
module SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , Secrets (..)
    , getVaultFile'
    , putVaultFile'
    , getVaultFile
    , putVaultFile
    , encryptVault
    , decryptVault
    )
where

import Crypto.Simple.CTR (encrypt, decrypt)

import Crypto.Hash (hash, SHA256 (..), Digest)
--import Crypto.Hash.Algorithms

import qualified Data.ByteString as BS  
--import Data.ByteString.Lazy (ByteString, readFile)
import Data.ByteString.Lazy.Char8 (pack, unpack)
import Data.ByteString.Char8 (pack, unpack)
import Data.ByteString.UTF8 (fromString)
import Data.Text (Text, pack, unpack)
import Data.Maybe (fromMaybe)
--import Data.ByteArray (convert)

import System.IO (readFile, writeFile)

import Data.Aeson
import GHC.Generics

import Turtle 
    (
--      ExitCode, 
      w
    , printf
    )


data Secrets =
  Secrets { key_secret :: Text
          , key_file :: Text
          } deriving (Show, Generic)

instance FromJSON Secrets
instance ToJSON Secrets

data User =
  User { user :: Text
       , secrets :: Secrets
       } deriving (Show, Generic)

instance FromJSON User
instance ToJSON User

data VaultEntry =
  VaultEntry { host  :: Text
        , host_key :: Text
        , ip4 :: Text
        , ip6 :: Text
        , port :: Int
        , users :: [User]
        } deriving (Show, Generic)

instance FromJSON VaultEntry
instance ToJSON VaultEntry

newtype Vault =
  Vault { vault :: [VaultEntry] 
    } deriving (Show, Generic)

instance FromJSON Vault
instance ToJSON Vault


-- genSHA256' :: Text -> Digest SHA256
-- genSHA256' key = 
--   hash . Prelude.head $ fmap Data.ByteString.UTF8.fromString [Data.Text.unpack key] 

genSHA256 :: Text -> String
genSHA256 key = 
  let h :: Digest SHA256
      h = hash . Prelude.head $ fmap Data.ByteString.UTF8.fromString [Data.Text.unpack key] in
  show h --genSHA256' key 
   

genAESKey :: Text -> BS.ByteString
genAESKey key = Data.ByteString.Char8.pack . take 32 $ genSHA256 key


getVaultFile :: String -> IO Text
getVaultFile fn = do   
  contents <- System.IO.readFile fn      
  return $ Data.Text.pack contents


putVaultFile' :: String -> Text -> IO ()
putVaultFile' fn vaultbs = 
  writeFile fn (Data.Text.unpack vaultbs)


getVaultFile' :: String -> IO BS.ByteString
getVaultFile' = BS.readFile


putVaultFile :: String -> Text -> Vault -> IO ()
putVaultFile fn k v =  do
  bs <- encryptVault k v
  writeFile fn $ Data.ByteString.Char8.unpack bs


decryptVault :: Text -> String-> IO Vault
decryptVault key fn = do
  let k' = genAESKey key
  v <- getVaultFile fn
  v' <- Crypto.Simple.CTR.decrypt k' . Data.ByteString.Char8.pack $ Data.Text.unpack v
  let v'' = Data.ByteString.Lazy.Char8.pack $ show v'
  printf w v''
  return . fromMaybe (error "failed to decrypt vault") $ decode v''
 

encryptVault :: Text -> Vault -> IO BS.ByteString
encryptVault k v = do 
  let k' = genAESKey k
      v' = Data.ByteString.Char8.pack . Data.ByteString.Lazy.Char8.unpack $ encode v
  Crypto.Simple.CTR.encrypt k' v'


-- > import Crypto.Simple.CBC (encrypt, decrypt) 
-- > import Data.ByteString.Char8 (pack)
-- > let key = pack "my secret key"
-- > let msg = pack "this is a message"
-- > encrypt key msg >>= \secretMsg -> decrypt key secretMsg
-- "this is a message"