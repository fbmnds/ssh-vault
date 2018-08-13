
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where


import qualified SSHVault.SBytes as Ty
import qualified SSHVault.Vault as V
import qualified SSHVault.Vault.Config as Cfg
import SSHVault.Workflows
import SSHVault.Common

import qualified Data.ByteString as B
-- import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteArray as BA

import Data.Text (splitOn)
import Data.Maybe (fromMaybe)
import Data.Aeson as JSON
import Data.Aeson.Encode.Pretty (encodePretty)
import GHC.Generics

import Test.QuickCheck

import Control.Exception (SomeException, catch)
import Control.Monad
-- import System.Exit (ExitCode(..))
import qualified Turtle as Tu
import Turtle.Format

instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack



data TestConfig =
  Config { host :: String
         , user :: String
         , mpw  :: String
    } deriving (Show, Generic, Eq)
instance FromJSON TestConfig
instance ToJSON TestConfig

-- | test0: check vault deserialization (unencrypted)

test0 :: IO ()
test0 = catch (do
  v <- checkVaultJSON
  testGetHost v
  putStrLn "\n+++ OK, passed test0: check vault deserialization (unencrypted)."
  )(\ (e' :: SomeException) -> error $ "\n--- ERR, failed test0: check vault deserialization (unencrypted).\n" ++ show e')
  where
    checkVaultJSON :: IO Ty.Vault
    checkVaultJSON = do
      vsc' <- B.readFile "./tests/data/vault0.json"
      let vsc = Ty.toLUBytes vsc'
      return . fromMaybe (error "checkVaultJSON: failed to parse Vault decode $ encode\n") $ JSON.decode vsc
    testGetHost :: Ty.Vault -> IO ()
    testGetHost v = case V.getHosts v of
      ["box1","box2","box3"] -> putStrLn "+++ OK, passed getHost test."
      _                      -> error "--- ERR, failed getHost test.\n"




-- | test1 : roundtrip to/from disk for vault user update with new SSH key/passphrase

test1 :: Cfg.Config -> IO ()
test1 dcfg = do
  let debug = False
  h <- Tu.home
  let fn = Ty.toString (format fp h) ++ "/.ssh/vault" ++ ".NEW"
      m = genAESKey $ Ty.toMasterKey "0123456789"
      sk = [Ty.SSHKey
              (Ty.toKeyPhrase64 "root*box1***")
              "/root/.ssh/id_box1"
              "##################"
              "##################"
              "2018-08-05 17:58:39.67413695 UTC"]
      u' = Ty.User "root" sk ["pub1","pub2"] "2018-08-05 17:58:39.67413695 UTC"

  s' <- genSSHKeyU dcfg m "root" u'

  let v1 = updateVault01 $
        Ty.SSHKey
          (Ty.phrase64 s')
          (Ty.key_file s')
          "##################"
          "##################"
          "2018-08-05 17:58:39.67413695 UTC"

  putStrLn "[+] passed genSSHKeyU and vault update."

  V.encryptVault m fn v1
  putStrLn "[*] encryptVault"
  (v2 :: Ty.Vault) <- V.decryptVault m fn
  putStrLn "[*] decryptVault"
  when debug . putStrLn . Ty.toString  $ encodePretty v1
  when debug . putStrLn . Ty.toString  $ encodePretty v2
  if v1 == v2 then putStrLn "+++ OK, passed test1 : roundtrip to/from disk for vault user update."
  else             putStrLn "--- ERR, failed test1 : roundtrip to/from disk for vault user update."
  where
    updateVault01 :: Ty.SSHKey -> Ty.Vault
    updateVault01 s01' =
      let
        s01 = s01'
        s02 = Ty.SSHKey
                (Ty.toKeyPhrase64 "YSpib3gxKioqKioq")
                "/home/a/.ssh/id_box1"
                "##################"
                "##################"
                "2018-08-05 17:58:39.67413695 UTC"
        u01 = Ty.User "root" [s01] [] "2018-08-05 17:58:39.67413695 UTC"
        u02 = Ty.User "a" [s02] ["pub1","pub2"] "2018-08-05 17:58:39.67413695 UTC"
        h0  = Ty.HostData "" "" "" 22 "2018-08-05 17:58:39.67413695 UTC"
        ve0 = Ty.VaultEntry  "box1" h0 [u01,u02] "2018-08-05 17:58:39.67413695 UTC" in
      Ty.Vault [ve0]



-- develop key synchronization



-- test2 : test key synchronization WIP

test2 :: IO ()
test2 = do
  cfg <- Cfg.genDefaultConfig
  tcfg' <- B.readFile $ Cfg.dir cfg ++ "/test.json"
  (tcfg :: TestConfig) <- return
    . fromMaybe (error "failed to JSON.decode in test2")
    . decode $ Ty.toLUBytes tcfg'
  let un   = user tcfg
      h    = host tcfg
      m    = genAESKey . Ty.toMasterKey $ mpw  tcfg
  (v :: Ty.Vault) <- V.decryptVault m (Cfg.file cfg)
  _ <- case V.getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"
  r <- confirmSSHAccess cfg m h un
  case r of
    "Access confirmed" -> do putStrLn "+++ OK, access confirmed"; return ()
    _                  -> error "--- ERR, access failed"


-- | property check on string conversions (depricated)

prop_scrubbedbytes :: B.ByteString -> Property
prop_scrubbedbytes t =
  True
    ==>  Ty.toSBytes t
    `BA.eq` Ty.toBytes (Ty.toSBytes t)
    ==   Ty.toBytes t
    `BA.eq` Ty.toBytes (Ty.toSBytes t)
    &&   Ty.toSBytes t'
    `BA.eq` Ty.toBytes (Ty.toSBytes t')
    ==   Ty.toBytes t'
    `BA.eq` Ty.toBytes (Ty.toSBytes t')
    &&   Ty.toSBytes t''
    `BA.eq` Ty.toSBytes (Ty.toLUBytes t'')
    ==   Ty.toBytes t''
    `BA.eq` Ty.toBytes (Ty.toLUBytes t'')
  where t'  = Ty.toText t
        t'' = Ty.toBytes t


-- | test setup

genTestConfig :: IO Cfg.Config
genTestConfig = do
  vdir' <- Tu.pwd
  let vdir = Ty.toString $ format fp vdir'
  return Cfg.Config {
        Cfg.dir      = vdir ++ "/tests/data"
      , Cfg.file     = vdir ++ "/tests/data/.vault"
      , Cfg.keystore = vdir ++ "/tests/data/.vault/STORE"
      , Cfg.ttl      = 1
      }


main :: IO ()
main = do
  test0
  dcfg <- genTestConfig
  test1 dcfg
  shellD $ "rm " ++ Cfg.keystore dcfg ++ "/*"
  test2
  quickCheck prop_scrubbedbytes
