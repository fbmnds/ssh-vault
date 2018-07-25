
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

import SshVault.SBytes

import Crypto.Simple.CTR (encrypt, decrypt)

import Crypto.Hash (hash, SHA256 (..), Digest)
--import Crypto.Hash.Algorithms

import qualified Data.Text as T
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as CL
import qualified Data.ByteString.Lazy.UTF8 as CLU
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteArray as BA

import Data.ByteString.UTF8 as CU

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
  Secrets { key_secret :: T.Text
          , key_file :: T.Text
          } deriving (Show, Generic)

instance FromJSON Secrets
instance ToJSON Secrets

data User =
  User { user :: T.Text
       , secrets :: Secrets
       } deriving (Show, Generic)

instance FromJSON User
instance ToJSON User

data VaultEntry =
  VaultEntry { host  :: T.Text
        , host_key :: T.Text
        , ip4 :: T.Text
        , ip6 :: T.Text
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
 
{-

-genSHA256 :: Text -> String
-genSHA256 key = 
-  let h :: Digest SHA256
-      h = hash . Prelude.head $ fmap Data.ByteString.UTF8.fromString [Data.Text.unpack key] in
-  show h --genSHA256' key 
-   
-
-genAESKey :: Text -> BS.ByteString
-genAESKey key = Data.ByteString.Char8.pack . take 32 $ genSHA256 key

-}

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


putVaultFile' :: String -> T.Text -> IO ()
putVaultFile' fn vaultbs = 
  writeFile fn (T.unpack vaultbs)


getVaultFile' :: String -> IO B.ByteString
getVaultFile' = B.readFile


putVaultFile :: String -> T.Text -> Vault -> IO ()
putVaultFile fn k v =  do
  bs <- encryptVault k v
  writeFile fn $ C.unpack bs


decryptVault :: T.Text -> String-> IO Vault
decryptVault key fn = do
  v <- getVaultFile fn
  v' <- Crypto.Simple.CTR.decrypt (genAESKey key) $ toBytes v
  let v'' = C.pack $ show v'
  printf w v''
  return . fromMaybe (error "failed to decrypt vault") . Data.Aeson.decode $ toLUBytes v''
 

encryptVault :: T.Text -> Vault -> IO B.ByteString
encryptVault k v = do 
  let k' = genAESKey k
      v' = toBytes . show $ Data.Aeson.encode v
  Crypto.Simple.CTR.encrypt k' v'


-- > import Crypto.Simple.CBC (encrypt, decrypt) 
-- > import Data.ByteString.Char8 (pack)
-- > let key = pack "my secret key"
-- > let msg = pack "this is a message"
-- > encrypt key msg >>= \secretMsg -> decrypt key secretMsg
-- "this is a message"