
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

--import Control.Exception (SomeException, catch)

--import SshVault.Workflows (ssh)
import SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
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
import qualified Data.ByteString as BS
--import Data.ByteString (pack, unpack)
import Data.ByteArray (eq, length)

import Data.Maybe (fromMaybe)
import Data.Aeson
--import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty

import Test.QuickCheck


--import GHC.Generics

instance Arbitrary BS.ByteString where arbitrary = BS.pack <$> arbitrary
instance CoArbitrary BS.ByteString where coarbitrary = coarbitrary . BS.unpack


done :: IO ExitCode
done = shell "" ""

s01 :: Secrets
s01 = Secrets
        "root*box1***"
        "/root/.ssh/id_box1"

s02 :: Secrets
s02 = Secrets
        "a*box1******"    
        "/home/a/.ssh/id_box1"


u01 :: User
u01 = User
        "root"
        s01


u02 :: User
u02 = User
        "a"
        s02
  
ve0 :: VaultEntry
ve0 = VaultEntry 
        "box1"
        ""
        ""
        ""
        22
        [u01,u02]

v0 :: Vault
v0 = Vault [ve0]

prop_scrubbedbytes :: BS.ByteString -> Property
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
  _ <- readUnencryptedVaultFromJSON ()
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

  
