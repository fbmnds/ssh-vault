
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

import qualified System.IO as IO
import Control.Exception (SomeException, catch)

--import SshVault.Workflows (ssh)
import SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , Secrets (..)
    , getVaultFile'
    , putVaultFile'
    , getVaultFile
    , putVaultFile
--    , encryptVault
    , decryptVault
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

import Data.ByteArray (eq, convert, length)
import Data.ByteString
import Data.ByteString.Internal (c2w)
import Data.ByteString.Lazy (ByteString, pack)
import Data.ByteString.Lazy.Char8 (pack, unpack, toStrict, map)
import Data.Maybe (fromMaybe)
import Data.Aeson
--import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty
import Data.Text
    (
      Text
    , pack
    )

--import GHC.Generics


nl :: IO ()
nl = printf s "\n"

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
  let (t :: Data.Text.Text) = "äöüß!\"§$%&/"
      t' = toSBytes t
      (t'' :: Data.ByteString.ByteString) = convert t'
  nl
  printf s t
  nl
  printf w $ t'' `eq` t'
  nl

readUnencryptedVaultFromJSON :: () -> IO ()
readUnencryptedVaultFromJSON _ = do
  -- read file to scrubbed bytes
  vsc' <- getVaultFile' "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  printf w $ Data.ByteArray.length vsc
  nl
  IO.putStrLn "decode JSON"
  let (v :: Vault) = 
        fromMaybe
          (error "readUnencryptedVaultFromJSON: failed to parse Vault decode $ encode")
          . decode $ toLUBytes vsc
  -- verify first element
  printf w v
  nl
  IO.putStrLn "---"



test :: IO ExitCode
test = do
  textSBytes () 

  readUnencryptedVaultFromJSON ()

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


  let (v :: Vault) = fromMaybe (error "failed to parse Vault decode $ encode") . decode $ encode vvs
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty v
  nl 


  --let (vf :: Vault) = fromMaybe (error "failed to parse Vault bytes from file") . decode $ Data.ByteString.Lazy.Char8.unpack sv
  --printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vf
  --nl 


--  passwd' <- getKeyPhrase
--  let passwd = Data.Text.pack $ show passwd'
  let passwd = "123456789"

  -- _ <- putVaultFile' "/home/fb/.ssh/ssh-vault-evf.json" (Data.Text.pack $ Data.ByteString.Lazy.Char8.unpack evf) 
  --_ <- putVaultFile "/home/fb/.ssh/ssh-vault-enc.json" passwd vf

  vvf <- catch 
      (decryptVault passwd "/home/fb/.ssh/ssh-vault-enc.json") 
      (\(e' :: SomeException) -> do
        printf w $ "failed JSON decoding throws " ++ show e'
        return vvs)
  printf s . Data.Text.pack . Data.ByteString.Lazy.Char8.unpack $ encodePretty vvf
  nl 


  done


main = test

 

  --let detv = decryptVault passwd tv

 