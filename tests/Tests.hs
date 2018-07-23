
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

--import Control.Exception (SomeException, catch)

--import SshVault.Workflows (ssh)
import SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , Secrets (..)
    , getVaultFile'
--    , putVaultFile'
--    , getVaultFile
--    , putVaultFile
--    , encryptVault
--    , decryptVault
    )
import SshVault.SBytes
--import SshVault.Common (getKeyPhrase)

import Turtle 
    ( ExitCode
    , printf
    ,
--    , fromString
--    , liftIO
--    , readline
--    , view
    )
import Turtle.Format
import Turtle.Prelude 
    ( 
--      stdout
--    , input
      shell
    )
--import Turtle.Line (lineToText)

import Data.ByteArray (eq, length)
import qualified Data.Text as T

import Data.Maybe (fromMaybe)
import Data.Aeson
--import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty

--import GHC.Generics


done :: IO ExitCode
done = shell "" ""


s0 :: [Secrets]
s0 = 
  [
      Secrets
      "root"
      "root*box1***"
      "/root/.ssh/id_box1"
    , Secrets
      "a"
      "a*box1******"
      "/home/a/.ssh/id_box1"
  ]    

ve0 :: VaultEntry
ve0 = VaultEntry 
        ["root","a"] 
        "box1"
        ""
        ""
        ""
        22
        s0


textSBytes :: () -> IO ()
textSBytes _ = do
  let (t :: T.Text) = "äöüß!\"§$%&/"
      t' = toSBytes t
      t'' = toBytes t'

  printf (s % "\n") t
  printf (w % "\n") $ t'' `eq` t'


readUnencryptedVaultFromJSON :: () -> IO Vault
readUnencryptedVaultFromJSON _ = do
  -- read file to scrubbed bytes
  vsc' <- getVaultFile' "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  printf (w % "\n") $ Data.ByteArray.length vsc
  printf s "decode JSON\n"
  let (v :: Vault) = 
        fromMaybe
          (error "readUnencryptedVaultFromJSON: failed to parse Vault decode $ encode")
          . decode $ toLUBytes vsc
  
  printf (s % "\n") . toText $ encodePretty v
  printf s "---\n"
  return v


test :: IO ExitCode
test = do
  textSBytes () 

  _ <- readUnencryptedVaultFromJSON ()

  -- vvf <- catch 
  --     (decryptVault passwd "/home/fb/.ssh/ssh-vault-enc.json") 
  --     (\(e' :: SomeException) -> do
  --       printf w $ "failed JSON decoding throws " ++ show e'
  --       return vvs)
  -- printf s . toText $ encodePretty vvf

  done


main = test
