
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

--import Control.Exception (SomeException, catch)

import qualified SSHVault.Vault.Config as Cfg
import SSHVault.Vault
    ( Vault (..)
    , VaultEntry (..)
    , User (..)
    , SSHKey (..)
    , encryptVault
    , decryptVault
    )
import SSHVault.Workflows
import SSHVault.SBytes
import SSHVault.Common

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import Data.ByteArray (eq)

import Data.Maybe (fromMaybe)
import Data.Aeson

import Test.QuickCheck

import qualified Turtle as Tu
import Turtle.Format

instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack



done :: IO Tu.ExitCode
done = Tu.shell "" ""


updateVault01 :: SSHKey -> Vault
updateVault01 s01' =
  let
    s01 = s01'
    s02 = SSHKey "a*box1******" "/home/a/.ssh/id_box1"
    u01 = User "root" s01
    u02 = User "a" s02
    ve0 = VaultEntry  "box1" "" "" "" 22 [u01,u02] in
  Vault [ve0]

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
  where t'  = SSHVault.SBytes.toText t
        t'' = toBytes t


decodeVaultFromJSON :: () -> IO Vault
decodeVaultFromJSON _ = do
  vsc' <- B.readFile "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  let v =
        fromMaybe
          (error "decodeVaultFromJSON: failed to parse Vault decode $ encode\n")
          . decode $ toLUBytes vsc
  printf s "+++ OK, passed JSON decode test.\n"
  return v


getHosts :: Vault -> [T.Text]
getHosts = fmap host . vault

testGetHost :: Vault -> IO ()
testGetHost v = case getHosts v of
  ["box1","box2","box3"] -> printf s "+++ OK, passed getHost test.\n"
  _                      -> error "--- ERR, failed getHost test.\n"

genTestConfig :: IO Cfg.Config
genTestConfig = do
  vdir <- Tu.pwd
  return Cfg.Config {
        Cfg.dir = toString (format fp vdir) ++ "/tests/data"
      , Cfg.file = toString (format fp vdir) ++ "/tests/data/.vault"
      , Cfg.keystore = toString (format fp vdir) ++ "/tests/data/.vault/STORE"
      }


test0 :: IO ()
test0 = do
  v <- decodeVaultFromJSON ()
  testGetHost v
  -- vvf <- catch
  --     (decryptVault passwd "/home/fb/.ssh/ssh-vault-enc.json")
  --     (\(e' :: SomeException) -> do
  --       printf w $ "failed JSON decoding throws " ++ show e'
  --       return vvs)
  -- printf s . toText $ encodePretty vvf
  return ()


test1 :: IO ()
test1 = do
  h <- Tu.home
  let fn = toString (format fp h) ++ "/.ssh/vault" ++ ".NEW"
      vk = "0123456789" :: T.Text
      u' = User "root" $ SSHKey "root*box1***" "/root/.ssh/id_box1"

  dcfg <- genTestConfig
  s' <- genSSHKey dcfg ("root", u')
  let v1 = updateVault01 (SSHKey (toText . B64.encode . toBytes $ passphrase s') (key_file s'))
  printf s "+++ OK, passed genSSHKey test.\n"

  encryptVault (toSBytes $ genAESKey vk) fn v1
  printf s "[*] encryptVault\n"
  v2 <- decryptVault (toSBytes $ genAESKey vk) fn
  if v1 == v2 then printf s "+++ OK, passed decryptVault test.\n" else
    printf s "-- ERR, failed decryptVault test.\n"




main :: IO ()
main = do
  test0
  test1
  quickCheck prop_scrubbedbytes