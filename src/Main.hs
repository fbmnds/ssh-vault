
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}
module Main where

import Workflows (ssh)
import Vaults (Vault, VaultEntry, Secrets, getVaultFile', putVaultFile', getVaultFile, putVaultFile, encryptVault, decryptVault)
import Turtle (ExitCode, printf, fromString, liftIO, readline, view)
import Turtle.Format
import Turtle.Prelude (stdout, input, shell)
import Turtle.Line (lineToText)


import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 (unpack)
import Data.Maybe (fromMaybe)
import Data.Aeson
import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty
import Data.Text(Text, pack)

import GHC.Generics

data Secrets =
  Secrets { user :: Text
          , key_secret :: Text
          , key_file :: Text
          } deriving (Show, Generic)

instance FromJSON Main.Secrets
instance ToJSON Main.Secrets

data VaultEntry =
  VaultEntry { users :: [Text]
        , host  :: Text
        , host_key :: Text
        , ip4 :: Text
        , ip6 :: Text
        , port :: Int
        , secrets :: [Main.Secrets]
        } deriving (Show, Generic)

instance FromJSON Main.VaultEntry
instance ToJSON Main.VaultEntry

newtype Vault =
  Vault { vault :: [Main.VaultEntry] 
    } deriving (Show, Generic)

instance FromJSON Main.Vault
instance ToJSON Main.Vault


nl :: IO ()
nl = printf s "\n"

done :: IO ExitCode
done = shell "" ""


main :: IO ExitCode
main = do
  sv <- getVaultFile' "/home/fb/.ssh/ssh-vault.json"
--  printf s . fromText $ Data.ByteText.Lazy.Char8.unpack sv
--  _ <- putVaultFile' "/home/fb/.ssh/ssh-vault-sv.json" sv
--  stdout . input $ fromText "/home/fb/.ssh/ssh-vault-sv.json"

  tv <- getVaultFile "/home/fb/.ssh/ssh-vault.json"
--  printf s tv
  _ <- putVaultFile' "/home/fb/.ssh/ssh-vault-tv.json" tv
--  stdout . input $ fromText "/home/fb/.ssh/ssh-vault-tv.json"


  let ss = Secrets (Data.Text.pack "p") (Data.Text.pack "q") (Data.Text.pack "r") 
  let vs = VaultEntry 
        [Data.Text.pack "p", Data.Text.pack "p"] 
        (Data.Text.pack "h") 
        (Data.Text.pack "h_k") 
        (Data.Text.pack "4") 
        (Data.Text.pack "6") 
        22 
        [ss, ss, ss]   
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vs
  nl
  let vvs = Vault [vs] 
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vvs
  nl


  let (v :: Vaults.Vault) = fromMaybe (error "failed to parse Vault decode $ encode") . decode $ encode vvs
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty v
  nl 


  let (vf :: Vaults.Vault) = fromMaybe (error "failed to parse Vault bytes from file") $ decode sv
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vf
  nl 


  view (return "[?] enter password > ")
  passw' <- readline
  let passwd = lineToText . fromMaybe (error "failed to parse password") $ passw'
  nl
    -- case passw' of
    --     Nothing -> "123456789"
    --     Just s' -> lineToText s'


  -- _ <- putVaultFile' "/home/fb/.ssh/ssh-vault-evf.json" (Data.Text.pack $ Data.ByteString.Lazy.Char8.unpack evf) 
  _ <- putVaultFile "/home/fb/.ssh/ssh-vault-enc.json" passwd vf


  vvf <- decryptVault passwd "/home/fb/.ssh/ssh-vault-enc.json"
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vvf
  nl 


  done




 

  --let detv = decryptVault passwd tv

 