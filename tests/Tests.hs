
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

import Data.Maybe (fromMaybe)
import Data.Aeson
--import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty

import Test.QuickCheck


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


prop_scrubbedbytes :: String -> Property
prop_scrubbedbytes t =
  True
    ==>  toSBytes t
    `eq` toBytes (toSBytes t)
    ==   toBytes t
    `eq` toBytes (toSBytes t)
    &&   toSBytes t'
    `eq` toBytes (toSBytes t')
    ==   toBytes t'
    `eq` toBytes (toSBytes t')
    &&   toSBytes t''
    `eq` toSBytes (toLUBytes t'')
    ==   toBytes t''
    `eq` toBytes (toLUBytes t'')    
  where t'  = toText t
        t'' = toBytes t


readUnencryptedVaultFromJSON :: () -> IO Vault
readUnencryptedVaultFromJSON _ = do
  vsc' <- getVaultFile' "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  printf (w % "\n") $ Data.ByteArray.length vsc
  printf s "decode JSON\n"
  let (v :: Vault) = 
        fromMaybe
          (error "readUnencryptedVaultFromJSON: failed to parse Vault decode $ encode")
          . decode $ toLUBytes vsc
  
  printf (s % "\n") . toText $ encodePretty v
  printf s "+++\n"
  return v


test :: IO ()
test = do
  -- | Convert to ScrubbedBytes
  -- textSBytes () 
  -- | Read and decode plaintext JSON from file
  _ <- readUnencryptedVaultFromJSON ()
  -- | Verify vault consistency from JSON decoding 
  -- vvf <- catch 
  --     (decryptVault passwd "/home/fb/.ssh/ssh-vault-enc.json") 
  --     (\(e' :: SomeException) -> do
  --       printf w $ "failed JSON decoding throws " ++ show e'
  --       return vvs)
  -- printf s . toText $ encodePretty vvf
  return ()


main :: IO ()
main = do
  test
  quickCheck prop_scrubbedbytes

  
