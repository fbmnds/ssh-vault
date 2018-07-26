
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

--import Control.Exception (SomeException, catch)


import SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , Secrets (..)
    , getHosts
--    , putVaultFile'
--    , getVaultFile
--    , putVaultFile
--    , encryptVault
--    , decryptVault
    )
import SshVault.Workflows
import SshVault.SBytes


import Turtle 
--import Turtle.Format
--import Turtle.Prelude 
import qualified Data.ByteString as B
import Data.ByteArray (eq, length)

import Data.Maybe (fromMaybe)
import Data.Aeson

import Test.QuickCheck

import System.Environment


instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack


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

prop_scrubbedbytes :: B.ByteString -> Property
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
  where t'  = SshVault.SBytes.toText t
        t'' = toBytes t


decodeVaultFromJSON :: () -> IO Vault
decodeVaultFromJSON _ = do
  vsc' <- B.readFile "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  printf (w % "\n") $ Data.ByteArray.length vsc
  printf s "decode JSON\n"
  let (v :: Vault) = 
        fromMaybe
          (error "decodeVaultFromJSON: failed to parse Vault decode $ encode")
          . decode $ toLUBytes vsc
  printf s "+++ OK, passed JSON decode test.\n"
  return v


testGetHost :: Vault -> IO ()
testGetHost v = case getHosts v of
  ["box1","box2","box3"] -> printf s "+++ OK, passed getHost test.\n"
  _                      -> error "--- ERR, failed getHost test.\n" 

test :: IO ()
test = do
  v <- decodeVaultFromJSON ()
  testGetHost v
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
  h <- lookupEnv "HOME"
  s' <- genSSHSecrets ("", fromString . fromMaybe "failed path $HOME" $ h) ("root",u01)
  printf w s'
  printf s "+++ OK, passed genSSHSecrets test.\n"
  quickCheck prop_scrubbedbytes