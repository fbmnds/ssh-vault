
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
--    , putVaultFile'
--    , getVaultFile
--    , putVaultFile
--    , encryptVault
    , decryptVault
    )
import SshVault.Workflows
import SshVault.SBytes
import SshVault.Common


import Turtle
--import Turtle.Format
--import Turtle.Prelude
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import Data.ByteArray (eq)

import Data.Maybe (fromMaybe)
import Data.Aeson

import Test.QuickCheck



instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack



done :: IO ExitCode
done = shell "" ""


updateVault01 :: Secrets -> Vault
updateVault01 s01' =
  let
    s01 = s01'
    s02 = Secrets "a*box1******" "/home/a/.ssh/id_box1"
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
  where t'  = SshVault.SBytes.toText t
        t'' = toBytes t


decodeVaultFromJSON :: () -> IO Vault
decodeVaultFromJSON _ = do
  vsc' <- B.readFile "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  let (v :: Vault) =
        fromMaybe
          (error "decodeVaultFromJSON: failed to parse Vault decode $ encode")
          . decode $ toLUBytes vsc
  printf s "+++ OK, passed JSON decode test.\n"
  return v


getHosts :: Vault -> [Text]
getHosts = fmap host . vault

testGetHost :: Vault -> IO ()
testGetHost v = case getHosts v of
  ["box1","box2","box3"] -> printf s "+++ OK, passed getHost test.\n"
  _                      -> error "--- ERR, failed getHost test.\n"

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
  let vk = "0123456789" :: Text
  h <- home
  let cfg = (toSBytes vk, h, "/.ssh/vault") :: Config
  let vkey = toSBytes $ getCfgVaultKey cfg
  let fn = getCfgVaultFile cfg
  let u' = User "root" $ Secrets "root*box1***" "/root/.ssh/id_box1"
  s' <- genSSHSecrets cfg ("root", u')
  printf s "+++ OK, passed genSSHSecrets test.\n"
  let v1 = updateVault01 (Secrets (SshVault.SBytes.toText . B64.encode . SshVault.SBytes.toBytes $ key_secret s') (key_file s'))
  printf s "+++ OK, passed putVaultFile test.\n"
  v2 <- decryptVault vkey fn
  if v1 == v2 then printf s "+++ OK, passed decryptVault test.\n" else
    printf s "-- ERR, TODO VERIFY SECRET CHANGE IS OK failed decryptVault test.\n"

{-
safeVault :: Config -> Vault -> IO ()
safeVault cfg v = do
    let fn = toString $ format (fp % w) (getCfgHome cfg) (getCfgVault cfg)
    putVaultFile fn (getCfgVKey cfg) v

readVault :: Config -> IO Vault
readVault cfg = do
    let fn = toString $ format (fp % w) (getCfgHome cfg) (getCfgVault cfg)
    decryptVault (getCfgVKey cfg) fn
-}

main :: IO ()
main = do
  test0
  test1
  quickCheck prop_scrubbedbytes